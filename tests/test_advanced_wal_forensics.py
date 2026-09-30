import struct
import pytest
from sqlite_carver.core.parser import DatabaseHeader, DatabaseParser, PageType
from sqlite_carver.core.integrity import check_anti_forensics_anomalies
from sqlite_carver.core.wal_diff import WalDiffEngine, WalHeader, WalFrame


def test_auto_vacuum_and_pointermap_detection():
    # DatabaseHeader with auto-vacuum FULL
    # offset 52: largest_root_btree_page = 5, offset 64: incremental_vacuum_flag = 0
    hdr_full = bytearray(100)
    hdr_full[:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", hdr_full, 16, 4096)
    hdr_full[18] = 1
    hdr_full[19] = 1
    struct.pack_into(">I", hdr_full, 52, 5)  # largest_root_btree_page
    struct.pack_into(">I", hdr_full, 64, 0)  # incremental_vacuum_flag
    
    parsed_full = DatabaseHeader.from_bytes(hdr_full)
    assert parsed_full.has_pointermap is True
    assert parsed_full.vacuum_mode == "FULL"

    # DatabaseHeader with auto-vacuum INCREMENTAL
    # offset 52: largest_root_btree_page = 5, offset 64: incremental_vacuum_flag = 1
    hdr_incr = bytearray(hdr_full)
    struct.pack_into(">I", hdr_incr, 64, 1)
    parsed_incr = DatabaseHeader.from_bytes(hdr_incr)
    assert parsed_incr.has_pointermap is True
    assert parsed_incr.vacuum_mode == "INCREMENTAL"

    # DatabaseHeader with auto-vacuum NONE
    hdr_none = bytearray(hdr_full)
    struct.pack_into(">I", hdr_none, 52, 0)
    struct.pack_into(">I", hdr_none, 64, 0)
    parsed_none = DatabaseHeader.from_bytes(hdr_none)
    assert parsed_none.has_pointermap is False
    assert parsed_none.vacuum_mode == "NONE"


def test_auto_vacuum_anomaly_reporting():
    hdr_bytes = bytearray(100)
    hdr_bytes[:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", hdr_bytes, 16, 512)
    hdr_bytes[18] = 1
    hdr_bytes[19] = 1
    struct.pack_into(">I", hdr_bytes, 52, 10)  # Full auto-vacuum
    struct.pack_into(">I", hdr_bytes, 64, 0)

    db_bytes = bytes(hdr_bytes).ljust(1024, b"\x00")
    parser = DatabaseParser(db_bytes)
    anomalies = check_anti_forensics_anomalies(parser, file_size=len(db_bytes))
    codes = [a["code"] for a in anomalies]
    assert "AUTO_VACUUM_FULL_ACTIVE" in codes


def test_pragma_secure_delete_detection():
    page_size = 512
    # Create page 1 with a freeblock whose payload is 100% zeros
    p1 = bytearray(page_size)
    p1[:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", p1, 16, page_size)
    p1[18] = 1
    p1[19] = 1
    # Page 1 b-tree header starts at offset 100:
    # 100: type=0x0D (leaf), 101-102: first_freeblock=120, 103-104: cell_count=0
    p1[100] = 0x0D
    struct.pack_into(">H", p1, 101, 120)  # first_freeblock at 120
    struct.pack_into(">H", p1, 103, 0)
    struct.pack_into(">H", p1, 105, 512)  # cell_content_offset

    # Freeblock at offset 120: next=0 (end), size=40 bytes, all payload (36 bytes) is zeros
    struct.pack_into(">H", p1, 120, 0)
    struct.pack_into(">H", p1, 122, 40)
    p1[124:160] = b"\x00" * 36

    parser = DatabaseParser(bytes(p1))
    anomalies = check_anti_forensics_anomalies(parser, file_size=len(p1))
    codes = [a["code"] for a in anomalies]
    assert "PRAGMA_SECURE_DELETE_DETECTED" in codes
    sec_del = [a for a in anomalies if a["code"] == "PRAGMA_SECURE_DELETE_DETECTED"][0]
    assert sec_del["zero_ratio"] == 1.0


def test_wal_slack_and_multi_version_pages():
    page_size = 512
    # Base DB (2 pages)
    db_bytes = bytearray(page_size * 2)
    db_bytes[:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", db_bytes, 16, page_size)
    db_bytes[18] = 2  # WAL write version
    db_bytes[19] = 2  # WAL read version

    # Construct synthetic WAL:
    # 32-byte WAL Header: magic (4B), version (4B), page_size (4B), seq (4B), salt1 (4B), salt2 (4B), c1, c2
    wal_hdr = struct.pack(">8I", 0x377f0682, 3007000, page_size, 10, 0x11111111, 0x22222222, 0, 0)

    # Frame 1: active salt (0x11111111), page_id = 2, commit=1
    f1_hdr = struct.pack(">6I", 2, 2, 0x11111111, 0x22222222, 0, 0)
    f1_page = b"\x0d\x00\x00\x01\x01\xf0\x00\x00" + (b"\x11" * (page_size - 8))
    frame1 = f1_hdr + f1_page

    # Frame 2: active salt (0x11111111), page_id = 2, commit=1 (Second version of page 2 in current transaction!)
    f2_hdr = struct.pack(">6I", 2, 2, 0x11111111, 0x22222222, 0, 0)
    f2_page = b"\x0d\x00\x00\x01\x01\xe0\x00\x00" + (b"\x22" * (page_size - 8))
    frame2 = f2_hdr + f2_page

    # Frame 3: STALE salt from prior checkpoint (0x99999999) = WAL SLACK!
    # page_id = 2 (Third historical version in WAL slack!)
    f3_hdr = struct.pack(">6I", 2, 0, 0x99999999, 0x88888888, 0, 0)
    f3_page = b"\x0d\x00\x00\x01\x01\xd0\x00\x00" + (b"\x33" * (page_size - 8))
    frame3 = f3_hdr + f3_page

    wal_bytes = wal_hdr + frame1 + frame2 + frame3

    engine = WalDiffEngine(bytes(db_bytes), wal_bytes)
    
    # Active frames should only include frame 1 and 2
    assert len(engine.frames) == 2
    # Slack frames should contain frame 3
    assert len(engine.slack_frames) == 1
    assert engine.slack_frames[0].is_wal_slack is True

    # Multi-version pages: Page 2 should have 3 versions recorded!
    multi = engine.get_multi_version_pages()
    assert 2 in multi
    assert len(multi[2]) == 3
    assert multi[2][0]["frame_index"] == 1
    assert multi[2][1]["frame_index"] == 2
    assert multi[2][2]["frame_index"] == 3
    assert multi[2][2]["is_wal_slack"] is True

    # Carve WAL slack records
    slack_records = engine.carve_wal_slack_records()
    assert isinstance(slack_records, list)
    for r in slack_records:
        assert r.source == "wal_slack"


def test_encrypted_wal_frame_decryption():
    """Verifies that WalDiffEngine decrypts encrypted WAL frame payloads on-the-fly."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import OFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import OFB

    page_size = 4096
    key = b"A" * 32

    test_marker = b"HELLO_SQLCIPHER_WAL"
    raw_leaf = bytearray(page_size)
    raw_leaf[0] = 0x0D  # Leaf table B-Tree
    raw_leaf[1:3] = b"\x00\x00"
    raw_leaf[3:5] = struct.pack(">H", 1)  # 1 cell
    raw_leaf[5:7] = struct.pack(">H", 100)
    raw_leaf[100 : 100 + len(test_marker)] = test_marker

    # Encrypt with SQLCipher AES-256-CBC (reserve=48, IV at page_size - 48)
    iv = b"I" * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(bytes(raw_leaf[: page_size - 48])) + enc.finalize()
    enc_page = bytearray(ct + iv + (b"\x00" * 32))

    # WAL Header + Frame
    wal_hdr = struct.pack(">8I", 0x377f0682, 3007000, page_size, 1, 0x11111111, 0x22222222, 0, 0)
    frame_hdr = struct.pack(">6I", 2, 1, 0x11111111, 0x22222222, 0, 0)
    wal_data = wal_hdr + frame_hdr + bytes(enc_page)

    dummy_db = b"SQLite format 3\x00" + (b"\x00" * (page_size - 16))

    # Without encryption_meta: page_data remains encrypted ciphertext
    engine_plain = WalDiffEngine(dummy_db, wal_data)
    assert engine_plain.frames[0].page_data[0] != 0x0D

    # With encryption_meta: page_data is decrypted on-the-fly!
    meta = {"raw_key": key, "scheme": "SQLCipher v4", "reserve_bytes": 48}
    engine_dec = WalDiffEngine(dummy_db, wal_data, encryption_meta=meta)
    assert engine_dec.frames[0].page_data[0] == 0x0D
    assert b"HELLO_SQLCIPHER_WAL" in engine_dec.frames[0].page_data

    # 2. Test SEE WAL Frame (AES-OFB)
    see_iv = struct.pack(">I", 2).ljust(16, b"\x00")
    see_cipher = Cipher(algorithms.AES(key), OFB(see_iv))
    see_enc = see_cipher.encryptor()
    see_ct = see_enc.update(bytes(raw_leaf))

    wal_data_see = wal_hdr + frame_hdr + see_ct
    see_meta = {"raw_key": key, "scheme": "SEE-AES-OFB", "reserve_bytes": 0}
    engine_see = WalDiffEngine(dummy_db, wal_data_see, encryption_meta=see_meta)
    assert engine_see.frames[0].page_data[0] == 0x0D
    assert b"HELLO_SQLCIPHER_WAL" in engine_see.frames[0].page_data

