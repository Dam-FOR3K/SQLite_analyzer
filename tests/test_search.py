"""Tests for global forensic deep search engine."""

import plistlib
import sqlite3
import tempfile
from pathlib import Path
import pytest

from sqlite_carver.core.search import ForensicSearchEngine, recursive_search_in_data


def test_recursive_search_in_data_primitives():
    # String match
    found, fmt, snip = recursive_search_in_data("Secret Password 123", "password")
    assert found is True
    assert "Secret Password 123" in snip

    # Case insensitivity
    found, _, _ = recursive_search_in_data("Administrator Account", "ADMIN")
    assert found is True

    # Numeric match
    found, _, _ = recursive_search_in_data(987654, "9876")
    assert found is True

    # Dict & List recursion
    nested = {"user": "alice", "roles": ["admin", "auditor"], "tokens": [101, 202]}
    found, _, snip = recursive_search_in_data(nested, "auditor")
    assert found is True
    assert "roles[1]" in snip


def test_recursive_search_in_bplist_and_hex():
    # Apple binary plist in bytes
    plist_bytes = plistlib.dumps({"target_uuid": "F47AC10B-58CC-4372-A567-0E02B2C3D479"}, fmt=plistlib.FMT_BINARY)
    found, fmt, snip = recursive_search_in_data(plist_bytes, "F47AC10B")
    assert found is True
    assert "bplist" in fmt

    # Hex search
    raw_binary = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
    found, fmt, snip = recursive_search_in_data(raw_binary, "deadbeef", is_hex=True)
    assert found is True
    assert fmt == "raw_hex"


def test_forensic_search_engine_active_and_deleted():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA page_size = 4096;")
        cur.execute("PRAGMA secure_delete = OFF;")
        cur.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, suspect TEXT, notes TEXT, payload BLOB);")

        plist_blob = plistlib.dumps({"session": "secret_jwt_token_999"}, fmt=plistlib.FMT_BINARY)
        cur.execute("INSERT INTO evidence VALUES (1, 'Alice', 'Active note', ?);", (plist_blob,))
        cur.execute("INSERT INTO evidence VALUES (2, 'Bob The Infiltrator', 'Deleted suspect note with malware_payload', X'CAFEBABE');")
        conn.commit()

        # Delete row 2 (Bob)
        cur.execute("DELETE FROM evidence WHERE id = 2;")
        conn.commit()
        conn.close()

        engine = ForensicSearchEngine(db_path.read_bytes())

        # 1. Search for bplist token in active row 1
        matches_active = engine.search("secret_jwt_token_999")
        assert len(matches_active) >= 1
        assert matches_active[0].record_source == "active"
        assert "bplist" in matches_active[0].container_format

        # 2. Search for keyword in deleted row 2 (Bob)
        matches_deleted = engine.search("malware_payload", deleted_only=True)
        assert len(matches_deleted) >= 1
        assert matches_deleted[0].record_source in ("freeblock", "slack", "unallocated")

        # 3. Search for hex signature in deleted record
        matches_hex = engine.search("cafebabe", is_hex=True)
        assert len(matches_hex) >= 1

    finally:
        if db_path.exists():
            db_path.unlink()
