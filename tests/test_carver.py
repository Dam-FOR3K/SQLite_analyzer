"""Tests for forensic carving, schema-guided matching, and deleted record recovery."""

import sqlite3
import tempfile
from pathlib import Path
import pytest

from sqlite_carver.core.carver import SQLiteCarver, TableSchema


def test_table_schema_from_sql():
    sql = """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(255) NOT NULL,
        email TEXT,
        score REAL,
        avatar BLOB
    );
    """
    schema = TableSchema.from_sql("users", 2, sql)
    assert schema.name == "users"
    assert len(schema.columns) == 5
    assert schema.columns[0].name == "id" and schema.columns[0].affinity == "INTEGER"
    assert schema.columns[1].name == "username" and schema.columns[1].affinity == "TEXT"
    assert schema.columns[2].name == "email" and schema.columns[2].affinity == "TEXT"
    assert schema.columns[3].name == "score" and schema.columns[3].affinity == "REAL"
    assert schema.columns[4].name == "avatar" and schema.columns[4].affinity == "BLOB"


def test_schema_matching():
    schema = TableSchema.from_sql(
        "messages",
        2,
        "CREATE TABLE messages (id INTEGER, sender TEXT, body TEXT, timestamp INTEGER)",
    )
    carver = SQLiteCarver(b"", user_schemas=[schema])

    # Serial types for: (10, "alice", "hello world", 1600000000)
    # INT8 (1), TEXT (odd >= 13), TEXT (odd >= 13), INT32 (4)
    serial_types = [1, 23, 35, 4]
    values = [10, "alice", "hello world", 1600000000]

    matched_tbl, conf, cols = carver.match_schema(serial_types, values)
    assert matched_tbl == "messages"
    assert conf >= 0.85
    assert cols == ["id", "sender", "body", "timestamp"]


def test_carve_real_sqlite_deleted_records():
    # Create an actual SQLite database file using standard sqlite3
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Use a small page size to test boundaries
        cursor.execute("PRAGMA page_size = 4096;")
        cursor.execute("PRAGMA secure_delete = OFF;")  # Ensure deleted cells are not zeroed
        cursor.execute("CREATE TABLE forensics_evidence (id INTEGER PRIMARY KEY, case_id TEXT, suspect TEXT, notes TEXT);")
        
        cursor.execute("INSERT INTO forensics_evidence VALUES (1, 'CASE-101', 'John Doe', 'Initial suspect note');")
        cursor.execute("INSERT INTO forensics_evidence VALUES (2, 'CASE-102', 'Jane Smith', 'Recovered deleted artefact');")
        cursor.execute("INSERT INTO forensics_evidence VALUES (3, 'CASE-103', 'Dr. Moriarty', 'Critical classified evidence');")
        conn.commit()

        # Delete record 2 ("Jane Smith") without VACUUM
        cursor.execute("DELETE FROM forensics_evidence WHERE id = 2;")
        conn.commit()
        conn.close()

        # Read raw DB bytes
        raw_db = db_path.read_bytes()
        carver = SQLiteCarver(raw_db)

        # Assert schema was loaded
        assert "forensics_evidence" in carver.schemas

        # Carve all records (active + deleted)
        records = carver.carve_all(include_active=True)
        assert len(records) >= 3

        # Verify active records exist
        active_suspects = [r.values[2] for r in records if r.source == "active" and len(r.values) >= 3]
        assert "John Doe" in active_suspects
        assert "Dr. Moriarty" in active_suspects

        # Verify deleted record "Jane Smith" was recovered from freeblock/slack/unallocated
        all_values = [str(r.values) for r in records]
        found_deleted = any("Jane Smith" in v for v in all_values)
        assert found_deleted, f"Deleted record 'Jane Smith' was not carved! Records found: {all_values}"

    finally:
        if db_path.exists():
            db_path.unlink()


def test_sqlite_sequence_not_matched_by_unrelated_record():
    schema = TableSchema.from_sql("sqlite_sequence", 0, "CREATE TABLE sqlite_sequence(name,seq)")
    carver = SQLiteCarver(b"", user_schemas=[schema])

    # 4 columns: BLOB(0), BLOB(4), TEXT(0), BLOB(7357)
    fake_st = [12, 20, 13, 14726]
    fake_vals = [b"", b"\x8b\x04\xaa\x02", "", b"noise" * 10]

    matched_tbl, conf, cols = carver.match_schema(fake_st, fake_vals)
    # Must NOT match sqlite_sequence
    assert matched_tbl is None


def test_noise_does_not_skip_subsequent_cells():
    # Build a simulated 4096-byte page with noise at offset 12 and a valid record at offset 200
    msg_schema = TableSchema.from_sql(
        "message", 2, "CREATE TABLE message (id INTEGER PRIMARY KEY, text TEXT, guid TEXT)"
    )
    seq_schema = TableSchema.from_sql("sqlite_sequence", 0, "CREATE TABLE sqlite_sequence(name,seq)")
    carver = SQLiteCarver(b"", user_schemas=[msg_schema, seq_schema])

    buf = bytearray(4096)
    # Put misleading serial types at offset 12: [12, 20, 13, 14726]
    buf[12:16] = bytes([12, 20, 13, 0x80 | 0x73]) # varint ending with noise
    buf[16] = 0x06

    # At offset 200, put a genuine SQLite record cell
    # Cell format: payload_size (varint), rowid (varint), header_size (varint), serial_types...
    # Values: text="Hello World", guid="9D4C4257-E10C-45F6-85B3-8EC457F84C01"
    # serial types: 0 (NULL/rowid), 35 (TEXT 11 bytes: "Hello World"), 85 (TEXT 36 bytes: GUID)
    # header_size = 4 (varint 4, 0, 35, 85)
    text_bytes = b"Hello World"
    guid_bytes = b"9D4C4257-E10C-45F6-85B3-8EC457F84C01"
    payload = bytes([4, 0, 35, 85]) + text_bytes + guid_bytes
    payload_len = len(payload)
    rowid = 42

    cell = bytes([payload_len, rowid]) + payload
    buf[200 : 200 + len(cell)] = cell

    records = carver.scan_bytes_for_records(
        bytes(buf), page_id=673, base_offset=0, source="freelist", known_offsets=set()
    )

    # Genuine record at offset 200 MUST be carved!
    found_guid = any("9D4C4257-E10C-45F6-85B3-8EC457F84C01" in str(r.values) for r in records)
    assert found_guid, f"Carver skipped legitimate cell! Records found: {[r.values for r in records]}"


def test_index_carved_record_rowid_extraction():
    from sqlite_carver.core.carver import IndexSchema
    # An index on chat(guid) stores (guid, rowid)
    idx_schema = IndexSchema(
        name="idx_chat_guid",
        table_name="chat",
        root_page=47,
        sql="CREATE INDEX idx_chat_guid ON chat(guid)",
        indexed_columns=["guid"],
    )
    carver = SQLiteCarver(b"")
    carver.index_root_map[47] = idx_schema

    # Simulate an index leaf page (page 47) with a freeblock containing (guid, rowid=7695969)
    buf = bytearray(4096)
    # Page header for index leaf (0x0A) at offset 0
    buf[0] = 0x0A
    # First freeblock offset at offset 1: 0x0100 (256)
    buf[1:3] = (256).to_bytes(2, "big")
    # Cell content start: 4096
    buf[5:7] = (4096).to_bytes(2, "big")

    # Freeblock at 256: 4 bytes header (next_offset=0, size=60)
    fb_offset = 256
    buf[fb_offset:fb_offset+2] = (0).to_bytes(2, "big") # next freeblock = 0
    buf[fb_offset+2:fb_offset+4] = (60).to_bytes(2, "big") # size = 60

    # Inside freeblock (offset 260): record with [header_size=3, guid (TEXT 36), rowid (INT32 = 7695969)]
    guid_val = "chat1234-guid"
    guid_st = 13 + (len(guid_val) * 2) # TEXT serial type
    rowid_val = 7695969
    # rowid_val fits in 32-bit signed int (serial type 4)
    # Payload: header_size=3, serial_types=[guid_st, 4], values=[guid_val, rowid_val]
    rec_payload = bytes([3, guid_st, 4]) + guid_val.encode("utf-8") + rowid_val.to_bytes(4, "big")

    # In SQLite index leaf, cell format is: payload_size (varint), payload
    cell_data = bytes([len(rec_payload)]) + rec_payload
    buf[fb_offset + 4 : fb_offset + 4 + len(cell_data)] = cell_data

    records = carver.carve_page_data(bytes(buf), page_id=47, is_page_1=False, include_active=False)

    # Must have carved record from index_freeblock
    fb_recs = [r for r in records if r.source == "index_freeblock"]
    assert len(fb_recs) >= 1
    assert fb_recs[0].matched_table == "chat"
    assert fb_recs[0].rowid == 7695969
    assert "rowid" in fb_recs[0].column_names


def test_carve_page_reserved_space():
    import struct
    from sqlite_carver.core.parser import PageType
    page_size = 512
    reserved_sz = 16
    magic = b"SQLite format 3\x00"
    hdr = bytearray(100)
    hdr[:16] = magic
    struct.pack_into(">H", hdr, 16, page_size)
    struct.pack_into(">B", hdr, 18, 1)
    struct.pack_into(">B", hdr, 19, 1)
    struct.pack_into(">B", hdr, 20, reserved_sz)

    page1 = bytearray(hdr)
    usable_sz = page_size - reserved_sz
    page_hdr = struct.pack(">BHHHB", PageType.TABLE_LEAF.value, 0, 0, usable_sz, 0)
    page1.extend(page_hdr)
    page1 = page1.ljust(page_size, b"\x00")
    page1[usable_sz:] = b"StegoPayload123!"

    carver = SQLiteCarver(bytes(page1))
    records = carver.carve_all()
    res_recs = [r for r in records if r.source == "page_reserved_space"]
    assert len(res_recs) == 1
    assert "StegoPayload123!" in res_recs[0].values[0]
    assert res_recs[0].page_id == 1
    assert res_recs[0].offset_in_page == usable_sz


def test_table_schema_sql_tokenizer():
    """Verify tokenizer handles quotes, brackets, and complex column constraints."""
    sql = 'CREATE TABLE "users" (["id" NOT NULL,] INT, \'name\' TEXT, [zip code] INT)'
    schema = TableSchema.from_sql("users", 2, sql)
    assert len(schema.columns) == 3
    assert schema.columns[0].name == '"id" NOT NULL,'
    assert schema.columns[0].affinity == "INTEGER"
    assert schema.columns[1].name == "name"
    assert schema.columns[1].affinity == "TEXT"
    assert schema.columns[2].name == "zip code"


def test_empty_and_parenthesis_table_names():
    """Verify table name edge cases: empty string '' and parenthesis '('."""
    sql1 = "CREATE TABLE '' ('id' INT, 'name' TEXT)"
    schema1 = TableSchema.from_sql("", 2, sql1)
    assert schema1.name == ""
    assert len(schema1.columns) == 2

    sql2 = 'CREATE TABLE "(" (\'id\' INT, \'name\' TEXT)'
    schema2 = TableSchema.from_sql("(", 2, sql2)
    assert schema2.name == "("
    assert len(schema2.columns) == 2




