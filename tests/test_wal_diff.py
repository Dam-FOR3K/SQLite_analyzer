"""Tests for WAL parsing, frame decoding, and transaction diff engine."""

import sqlite3
import tempfile
from pathlib import Path
import pytest

from sqlite_carver.core.wal_diff import MutationType, WalDiffEngine, WalHeader


def test_wal_header_parsing():
    raw_wal = bytearray(32)
    # Magic 0x377f0682, version 3007000, page_size 4096, checkpoint_seq 1, salts, checksums
    import struct
    struct.pack_into(">8I", raw_wal, 0, 0x377F0682, 3007000, 4096, 1, 100, 200, 300, 400)

    header = WalHeader.from_bytes(raw_wal)
    assert header is not None
    assert header.format_version == 3007000
    assert header.page_size == 4096
    assert header.checkpoint_seq == 1
    assert header.salt1 == 100
    assert header.salt2 == 200


def test_wal_diff_end_to_end():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)
    wal_path = db_path.with_name(db_path.name + "-wal")

    try:
        # Step 1: Initialize DB in WAL mode
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode = WAL;")
        cursor.execute("PRAGMA synchronous = NORMAL;")
        cursor.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT, user TEXT, ip TEXT);")
        conn.commit()

        # Step 2: Insert initial rows
        cursor.execute("INSERT INTO audit_log VALUES (1, 'LOGIN', 'alice', '192.168.1.10');")
        conn.commit()

        # Step 3: Mutate - update alice action
        cursor.execute("UPDATE audit_log SET action = 'PRIV_ESC' WHERE id = 1;")
        conn.commit()

        # Step 4: Insert bob
        cursor.execute("INSERT INTO audit_log VALUES (2, 'DATA_EXFIL', 'bob', '10.0.0.5');")
        conn.commit()

        # Step 5: Delete alice
        cursor.execute("DELETE FROM audit_log WHERE id = 1;")
        conn.commit()

        # Do NOT close connection with default checkpointing so WAL has rich history
        db_data = db_path.read_bytes()
        wal_data = wal_path.read_bytes() if wal_path.exists() else b""
        conn.close()

        if len(wal_data) > 32:
            engine = WalDiffEngine(db_data, wal_data)
            assert len(engine.frames) > 0

            mutations = engine.compute_timeline_diff()
            assert len(mutations) > 0

            mut_types = [m.mutation_type for m in mutations]
            assert MutationType.INSERT in mut_types
        else:
            assert False, "WAL file was not generated or too small during test setup."

    finally:
        if db_path.exists():
            db_path.unlink()
        if wal_path.exists():
            wal_path.unlink()
        shm_path = db_path.with_name(db_path.name + "-shm")
        if shm_path.exists():
            shm_path.unlink()


def test_wal_empty_and_zeroed():
    db_data = b"SQLite format 3\x00" + b"\x00" * 4080
    # Empty WAL
    engine_empty = WalDiffEngine(db_data, b"")
    assert engine_empty.wal_header is None
    assert len(engine_empty.frames) == 0
    assert engine_empty.compute_timeline_diff() == []

    # Zeroed WAL (checkpointed/reset state)
    zeroed_wal = b"\x00" * 4096
    engine_zeroed = WalDiffEngine(db_data, zeroed_wal)
    assert engine_zeroed.wal_header is None
    assert len(engine_zeroed.frames) == 0
    assert engine_zeroed.compute_timeline_diff() == []


def test_wal_high_page_id_no_memory_error():
    import struct
    db_data = b"SQLite format 3\x00" + b"\x00" * 4080
    raw_wal = bytearray(32 + 24 + 4096)
    # Header
    struct.pack_into(">8I", raw_wal, 0, 0x377F0682, 3007000, 4096, 1, 999, 888, 1, 2)
    # Frame with huge page_id (e.g. 500,000) that previously caused MemoryError
    struct.pack_into(">6I", raw_wal, 32, 500000, 1, 999, 888, 1, 2)
    # Page data with dummy leaf page header (0x0D, cell_count=0)
    struct.pack_into(">BHHHB", raw_wal, 32 + 24, 0x0D, 0, 0, 4096, 0)

    engine = WalDiffEngine(db_data, bytes(raw_wal))
    assert len(engine.frames) == 1
    # Must compute without MemoryError
    mutations = engine.compute_timeline_diff()
    assert isinstance(mutations, list)


def test_wal_mismatched_salt_and_checkpoint_fallback():
    """Verify that when WAL header salt does not match frame salt (post-checkpoint/reset), frames are not lost."""
    import struct
    db_data = b"SQLite format 3\x00" + b"\x00" * 4080
    raw_wal = bytearray(32 + 24 + 4096)
    # Header has salt1 = 0xAAAA (e.g. incremented by checkpoint)
    struct.pack_into(">8I", raw_wal, 0, 0x377F0682, 3007000, 4096, 2, 0xAAAA, 0x1111, 0, 0)
    # Frame has older salt1 = 0xBBBB from prior transaction
    struct.pack_into(">6I", raw_wal, 32, 2, 1, 0xBBBB, 0x2222, 0, 0)
    # Leaf table page
    struct.pack_into(">BHHHB", raw_wal, 32 + 24, 0x0D, 0, 0, 4096, 0)

    engine = WalDiffEngine(db_data, bytes(raw_wal))
    # Should fallback to parsing frames
    assert len(engine.frames) == 1
    assert len(engine.all_frames) == 1
    mutations = engine.compute_timeline_diff()
    assert isinstance(mutations, list)


def test_wal_zeroed_header_with_valid_frames():
    """Verify that when SQLite zeroes out the WAL header on checkpoint/close, valid trailing frames are still parsed."""
    import struct
    db_data = b"SQLite format 3\x00" + b"\x00" * 4080
    raw_wal = bytearray(32 + 24 + 4096)
    # Header is 100% zeroed out (magic=0)
    # Frame at offset 32 has valid page_id=2
    struct.pack_into(">6I", raw_wal, 32, 2, 1, 0x5555, 0x6666, 0, 0)
    struct.pack_into(">BHHHB", raw_wal, 32 + 24, 0x0D, 0, 0, 4096, 0)

    engine = WalDiffEngine(db_data, bytes(raw_wal))
    assert engine.wal_header is None
    # Valid frame should still be recovered from offset 32
    assert len(engine.frames) == 1
    assert len(engine.all_frames) == 1

