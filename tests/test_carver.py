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
