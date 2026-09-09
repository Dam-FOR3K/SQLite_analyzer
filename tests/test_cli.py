"""Tests for CLI subcommands and exporters."""

import sqlite3
import tempfile
from pathlib import Path
import pytest
from rich.console import Console

from sqlite_carver.core.carver import SQLiteCarver
from sqlite_carver.exporters.export import export_csv, export_jsonl, export_parquet


def test_exporters():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test (id INTEGER, name TEXT, data BLOB);")
        cursor.execute("INSERT INTO test VALUES (1, 'Alpha', X'414243');")
        cursor.execute("INSERT INTO test VALUES (2, 'Beta', X'444546');")
        conn.commit()
        conn.close()

        carver = SQLiteCarver(db_path.read_bytes())
        records = carver.carve_all()

        # 1. JSON Lines
        jsonl_path = db_path.with_suffix(".jsonl")
        export_jsonl(records, jsonl_path)
        assert jsonl_path.exists()
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == len(records)
        jsonl_path.unlink()

        # 2. CSV
        csv_path = db_path.with_suffix(".csv")
        export_csv(records, csv_path)
        assert csv_path.exists()
        csv_lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(csv_lines) >= 2  # header + rows
        csv_path.unlink()

        # 3. Parquet
        parquet_path = db_path.with_suffix(".parquet")
        export_parquet(records, parquet_path)
        assert parquet_path.exists()
        assert parquet_path.stat().st_size > 0
        parquet_path.unlink()

        # 4. dispatch_export router
        from sqlite_carver.exporters.export import dispatch_export
        res_html = dispatch_export(records, db_path.with_suffix(".html"))
        assert res_html["status"] == "ok"
        assert res_html["written"] == len(records)
        db_path.with_suffix(".html").unlink()

        res_json = dispatch_export(records, db_path.with_suffix(".json"))
        assert res_json["status"] == "ok"
        assert res_json["written"] == len(records)
        db_path.with_suffix(".json").unlink()

    finally:
        if db_path.exists():
            db_path.unlink()
