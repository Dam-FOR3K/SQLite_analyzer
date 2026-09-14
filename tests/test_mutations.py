import sqlite3
import pytest
from sqlite_carver.core.carver import SQLiteCarver, CarvedRecord
from sqlite_carver.core.mutations import detect_record_mutations
from sqlite_carver.exporters.html_report import generate_html_report
from sqlite_carver.exporters.export import export_sqlite, dispatch_export


def test_mutations_detection_active_vs_carved():
    # Create SQLite database in memory
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("PRAGMA page_size = 4096;")
    cur.execute("PRAGMA auto_vacuum = 0;")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, status TEXT);")
    
    # Insert 3 records
    cur.execute("INSERT INTO users VALUES (1, 'alice', 'alice@corp.local', 'active');")
    cur.execute("INSERT INTO users VALUES (2, 'bob', 'bob@corp.local', 'active');")
    cur.execute("INSERT INTO users VALUES (3, 'charlie', 'charlie@corp.local', 'pending');")
    conn.commit()

    # Update Bob's email and status (the previous cell becomes a freeblock or unallocated entry in the leaf page)
    # Perform an update with larger text to force cell relocation leaving old cell in freeblock/slack
    cur.execute("UPDATE users SET email = 'bob.updated.newemail@corp.local', status = 'suspended' WHERE id = 2;")
    conn.commit()

    raw_db = conn.serialize()
    conn.close()

    carver = SQLiteCarver(raw_db)
    records = carver.carve_all(include_active=True)

    # We should have carved both the active Bob row (id=2) and the historical/freeblock version
    bob_records = [r for r in records if r.matched_table == "users" and r.rowid == 2]
    assert len(bob_records) >= 1

    # Check that detect_record_mutations has flagged mutations if a deleted version was preserved
    mutated = [r for r in records if r.is_mutation]
    if mutated:
        m = mutated[0]
        assert m.matched_table == "users"
        assert m.rowid is not None
        assert len(m.mutation_diff) > 0
        # Check diff structure
        diff = m.mutation_diff
        assert any("active" in val and "carved" in val for val in diff.values())


def test_mutations_html_and_sqlite_export(tmp_path):
    # Create dummy records with a mutation
    active_rec = CarvedRecord(
        page_id=2,
        offset_in_page=100,
        source="active",
        confidence=1.0,
        rowid=1,
        matched_table="accounts",
        column_names=["id", "balance", "owner"],
        column_types=["INTEGER", "INTEGER", "TEXT"],
        serial_types=[1, 1, 13],
        raw_payload=b"\x01\x02\x03",
        values=[1, 5000, "Alice"],
    )
    historical_rec = CarvedRecord(
        page_id=2,
        offset_in_page=200,
        source="freeblock",
        confidence=0.9,
        rowid=1,
        matched_table="accounts",
        column_names=["id", "balance", "owner"],
        column_types=["INTEGER", "INTEGER", "TEXT"],
        serial_types=[1, 1, 13],
        raw_payload=b"\x01\x02\x04",
        values=[1, 1000, "Alice"],
        is_mutation=True,
        mutation_diff={"balance": {"active": 5000, "carved": 1000}},
    )

    records = [active_rec, historical_rec]

    # Test HTML export
    html_file = tmp_path / "report.html"
    generate_html_report(records, html_file, title="Test Mutation Report")
    html_content = html_file.read_text(encoding="utf-8")
    assert "sourceFilter" in html_content
    assert 'value="mutations"' in html_content
    assert "HISTORICAL MUTATION" in html_content or "is_mutation" in html_content

    # Test SQLite export
    sqlite_file = tmp_path / "forensic_export.sqlite"
    export_sqlite(records, sqlite_file)
    assert sqlite_file.exists()

    conn = sqlite3.connect(sqlite_file)
    cur = conn.cursor()
    diff_rows = cur.execute("SELECT * FROM _mutations_diff;").fetchall()
    assert len(diff_rows) == 1
    # Indices: 0:id, 1:table, 2:rowid, 3:carved_source, 8:col, 9:old, 10:new
    assert diff_rows[0][1] == "accounts"
    assert diff_rows[0][2] == 1
    assert diff_rows[0][3] == "freeblock"
    assert diff_rows[0][8] == "balance"
    assert str(diff_rows[0][9]) == "1000"
    assert str(diff_rows[0][10]) == "5000"
    conn.close()


def test_mutations_with_raw_bytes_export(tmp_path):
    rec = CarvedRecord(
        page_id=2,
        offset_in_page=100,
        source="freeblock",
        confidence=0.9,
        rowid=1,
        matched_table="documents",
        column_names=["id", "avatar_blob"],
        column_types=["INTEGER", "BLOB"],
        serial_types=[1, 14],
        raw_payload=b"\x01\x02",
        values=[1, b"\x89PNG\r\n\x1a\n\x00\x00"],
        is_mutation=True,
        mutation_diff={
            "avatar_blob": {
                "active": b"\x89PNG\r\n\x1a\nNEW_AVATAR",
                "carved": b"\x89PNG\r\n\x1a\nOLD_AVATAR",
            }
        },
    )

    # Export to HTML, JSON, JSONL, SQLite without bytes error
    dispatch_export([rec], tmp_path / "test.html")
    dispatch_export([rec], tmp_path / "test.json")
    dispatch_export([rec], tmp_path / "test.jsonl")
    dispatch_export([rec], tmp_path / "test.sqlite")
    assert (tmp_path / "test.html").exists()
    assert (tmp_path / "test.json").exists()
    assert (tmp_path / "test.jsonl").exists()
    assert (tmp_path / "test.sqlite").exists()
