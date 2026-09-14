import sqlite3
import pytest
from sqlite_carver.core.carver import IndexSchema, SQLiteCarver


def test_index_schema_parsing():
    sql = "CREATE INDEX idx_user_email ON users (email, status)"
    idx = IndexSchema.from_sql("idx_user_email", "users", 4, sql)
    assert idx.name == "idx_user_email"
    assert idx.table_name == "users"
    assert idx.root_page == 4
    assert idx.indexed_columns == ["email", "status"]


def test_carve_real_index_records():
    # Create SQLite database in memory with a table and index, then carve
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("PRAGMA page_size = 4096;")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, role TEXT);")
    cur.execute("CREATE INDEX idx_users_email ON users (email);")
    for i in range(1, 20):
        cur.execute("INSERT INTO users VALUES (?, ?, ?);", (i, f"user{i}@example.com", "admin"))
    conn.commit()

    # Get database bytes
    raw_db = conn.serialize()
    conn.close()

    carver = SQLiteCarver(raw_db)
    assert len(carver.index_schemas) >= 1
    assert "idx_users_email" in carver.index_schemas

    records = carver.carve_all(include_active=True)
    index_recs = [r for r in records if "index" in r.source]
    assert len(index_recs) >= 1

    sample = index_recs[0]
    assert sample.matched_table == "users"
    assert "idx_users_email" in sample.details
    assert sample.evidence_hash != ""
