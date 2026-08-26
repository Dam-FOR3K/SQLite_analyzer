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

    finally:
        if db_path.exists():
            db_path.unlink()
        if wal_path.exists():
            wal_path.unlink()
        shm_path = db_path.with_name(db_path.name + "-shm")
        if shm_path.exists():
            shm_path.unlink()
