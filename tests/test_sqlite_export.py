import sqlite3
import tempfile
from pathlib import Path

import pytest
from sqlite_carver.core.carver import CarvedRecord, SQLiteCarver, TableSchema, ColumnDef
from sqlite_carver.core.wal_diff import ColumnDiff, MutationType, RowMutation
from sqlite_carver.exporters.export import dispatch_export, export_sqlite


def test_sqlite_export_reconstructs_tables():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "evidence.sqlite"

        # Define schema for "messages" table
        schema_messages = TableSchema(
            name="messages",
            root_page=2,
            sql="CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, body TEXT, timestamp INTEGER);",
            columns=[
                ColumnDef("id", "INTEGER"),
                ColumnDef("sender", "TEXT"),
                ColumnDef("body", "TEXT"),
                ColumnDef("timestamp", "INTEGER"),
            ],
        )

        records = [
            # Active record
            CarvedRecord(
                page_id=2,
                offset_in_page=100,
                source="active",
                confidence=1.0,
                matched_table="messages",
                rowid=1,
                values=[1, "+123456789", "Hello Alice!", 1700000000],
                column_names=["id", "sender", "body", "timestamp"],
                column_types=["INTEGER", "TEXT", "TEXT", "INTEGER"],
                serial_types=[1, 23, 25, 4],
                raw_payload=b"sample_payload_1",
                evidence_hash="sha_active_1",
            ),
            # Deleted record recovered from freeblock with same rowid or different rowid
            CarvedRecord(
                page_id=2,
                offset_in_page=450,
                source="freeblock",
                confidence=0.92,
                matched_table="messages",
                rowid=1,  # Same rowid to test constraint-free forensic preservation
                values=[1, "+123456789", "Deleted message draft", 1699999000],
                column_names=["id", "sender", "body", "timestamp"],
                column_types=["INTEGER", "TEXT", "TEXT", "INTEGER"],
                serial_types=[1, 23, 45, 4],
                raw_payload=b"sample_payload_deleted",
                evidence_hash="sha_deleted_1",
            ),
            # Deleted record from freelist
            CarvedRecord(
                page_id=15,
                offset_in_page=200,
                source="freelist",
                confidence=0.88,
                matched_table="messages",
                rowid=42,
                values=[42, "+987654321", "Secret rendezvous at 8pm", 1699990000],
                column_names=["id", "sender", "body", "timestamp"],
                column_types=["INTEGER", "TEXT", "TEXT", "INTEGER"],
                serial_types=[1, 23, 51, 4],
                raw_payload=b"sample_payload_freelist",
                evidence_hash="sha_freelist_42",
            ),
            # Unmatched evidence
            CarvedRecord(
                page_id=8,
                offset_in_page=312,
                source="slack",
                confidence=0.65,
                matched_table=None,
                rowid=None,
                values=["orphan string", 12345],
                column_names=["col_0", "col_1"],
                column_types=["TEXT", "INTEGER"],
                serial_types=[27, 2],
                raw_payload=b"orphan_payload",
                evidence_hash="sha_orphan_8",
            ),
            # WAL mutation
            RowMutation(
                mutation_type=MutationType.UPDATE,
                frame_index=3,
                page_id=2,
                journal_source="wal",
                table_name="messages",
                rowid=1,
                column_diffs=[ColumnDiff("body", "Draft", "Hello Alice!")],
                new_values=[1, "+123456789", "Hello Alice!", 1700000000],
            ),
        ]

        storage_breakdown = {
            "total_pages": 50,
            "total_bytes": 204800,
            "active_bytes": 100000,
            "freeblock_bytes": 45000,
            "freelist_pages_count": 1,
            "freelist_bytes": 4096,
            "total_slack_bytes": 60000,
        }
        integrity_info = {"sample.db": {"sha256": "abc123sha", "md5": "def456md5"}}

        res = dispatch_export(
            records,
            out_path,
            title="Investigation Test Case",
            schemas={"messages": schema_messages},
            storage_breakdown=storage_breakdown,
            integrity_info=integrity_info,
        )

        assert res["status"] == "ok"
        assert res["format"] == "SQLite"
        assert out_path.exists()

        # Connect to the reconstructed database and verify contents
        conn = sqlite3.connect(str(out_path))
        cur = conn.cursor()

        # Verify messages table exists
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        assert "messages" in tables
        assert "_unmatched_evidence" in tables
        assert "_wal_journal_timeline" in tables
        assert "_forensic_metadata" in tables

        # Verify columns of messages table
        cur.execute("PRAGMA table_info(messages);")
        col_names = [col[1] for col in cur.fetchall()]
        assert "id" in col_names
        assert "sender" in col_names
        assert "body" in col_names
        assert "timestamp" in col_names
        assert "_forensic_source" in col_names
        assert "_forensic_confidence" in col_names
        assert "_forensic_page" in col_names
        assert "_forensic_hash" in col_names

        # Verify messages table contains both active and deleted rows
        all_rows = cur.execute("SELECT id, sender, body, _forensic_source FROM messages ORDER BY id, _forensic_source;").fetchall()
        assert len(all_rows) == 3

        # Query deleted messages specifically
        deleted_rows = cur.execute("SELECT body, _forensic_source, _forensic_page FROM messages WHERE _forensic_source != 'active' ORDER BY _forensic_page;").fetchall()
        assert len(deleted_rows) == 2
        assert deleted_rows[0][0] == "Deleted message draft"
        assert deleted_rows[0][1] == "freeblock"
        assert deleted_rows[0][2] == 2
        assert deleted_rows[1][0] == "Secret rendezvous at 8pm"
        assert deleted_rows[1][1] == "freelist"
        assert deleted_rows[1][2] == 15

        # Verify _unmatched_evidence table
        unmatched = cur.execute("SELECT source, values_json, evidence_hash FROM _unmatched_evidence;").fetchall()
        assert len(unmatched) == 1
        assert unmatched[0][0] == "slack"
        assert "orphan string" in unmatched[0][1]

        # Verify _wal_journal_timeline table
        wal_timeline = cur.execute("SELECT mutation_type, table_name, rowid, timestamp_utc FROM _wal_journal_timeline;").fetchall()
        assert len(wal_timeline) == 1
        assert wal_timeline[0][0] == "UPDATE"
        assert wal_timeline[0][1] == "messages"

        # Verify _forensic_metadata table
        meta = dict(cur.execute("SELECT property, value FROM _forensic_metadata;").fetchall())
        assert meta["report_title"] == "Investigation Test Case"
        assert "SQLite-Carver-Pro" in meta["generator"]
        assert meta["total_evidence_records"] == "5"
        assert "abc123sha" in meta["integrity_hashes_json"]
        assert "freeblock_bytes" in meta["storage_breakdown_json"]

        conn.close()


def test_sqlite_export_with_db_extension():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "output.db"
        rec = CarvedRecord(
            page_id=3,
            offset_in_page=120,
            source="freeblock",
            confidence=0.9,
            matched_table="contacts",
            rowid=1,
            values=["Bob", "bob@example.com"],
            column_names=["name", "email"],
            column_types=["TEXT", "TEXT"],
            serial_types=[15, 33],
            raw_payload=b"bob_payload",
            evidence_hash="sha_bob",
        )
        res = dispatch_export([rec], out_path)
        assert res["status"] == "ok"
        assert res["format"] == "SQLite"
        assert out_path.exists()

        conn = sqlite3.connect(str(out_path))
        cur = conn.cursor()
        contacts = cur.execute("SELECT name, email, _forensic_source FROM contacts;").fetchall()
        assert len(contacts) == 1
        assert contacts[0] == ("Bob", "bob@example.com", "freeblock")
        conn.close()


def test_sqlite_export_with_truncated_column_types():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "truncated_test.sqlite"
        rec = CarvedRecord(
            page_id=5,
            offset_in_page=300,
            source="freeblock",
            confidence=0.85,
            matched_table="notes",
            rowid=10,
            values=["My note content...", b"\x01\x02\x03"],
            column_names=["content", "attachment"],
            # Column types with 'truncated' annotations that previously caused syntax errors
            column_types=["TEXT (truncated)", "BLOB (truncated)"],
            serial_types=[25, 12],
            raw_payload=b"truncated_payload",
            evidence_hash="sha_trunc_5",
        )
        res = dispatch_export([rec], out_path)
        assert res["status"] == "ok"
        assert res["format"] == "SQLite"
        assert out_path.exists()

        conn = sqlite3.connect(str(out_path))
        cur = conn.cursor()
        notes = cur.execute("SELECT content, attachment, _forensic_source FROM notes;").fetchall()
        assert len(notes) == 1
        assert notes[0][0] == "My note content..."
        assert notes[0][1] == b"\x01\x02\x03"
        assert notes[0][2] == "freeblock"
        conn.close()

