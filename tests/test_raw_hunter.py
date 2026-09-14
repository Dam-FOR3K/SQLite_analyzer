import sqlite3
import pytest
from sqlite_carver.core.carver import SQLiteCarver, TableSchema


def test_raw_page_hunter_carves_orphan_page():
    # Create SQLite database with 1 table and multiple records
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("PRAGMA page_size = 4096;")
    cur.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, content TEXT);")
    for i in range(1, 15):
        cur.execute("INSERT INTO notes VALUES (?, ?);", (i, f"Confidential forensic memo #{i}"))
    conn.commit()

    raw_db = conn.serialize()
    conn.close()

    # Extract page 2 (leaf table page) without database header (offset 4096:8192)
    assert len(raw_db) >= 8192
    orphan_page = raw_db[4096:8192]

    # Prepend dummy unallocated binary garbage (e.g. simulating disk/RAM dump slice)
    dummy_prefix = b"\x55" * 4096  # unaligned garbage
    simulated_dump = dummy_prefix + orphan_page + (b"\xAA" * 4096)

    # Supply schema to match
    schema = TableSchema.from_sql("notes", 0, "CREATE TABLE notes (id INTEGER PRIMARY KEY, content TEXT)")

    # Run Raw Page Hunter on the stream
    carved = SQLiteCarver.carve_raw_pages(
        simulated_dump,
        page_size=4096,
        user_schemas=[schema],
        include_active=True,
    )

    assert len(carved) >= 1
    # Check that records match 'notes' table
    memo_recs = [r for r in carved if r.matched_table == "notes"]
    assert len(memo_recs) >= 1
    assert any("Confidential forensic memo" in str(r.values) for r in memo_recs)
    assert memo_recs[0].evidence_hash != ""
