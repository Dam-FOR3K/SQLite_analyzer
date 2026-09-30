"""
Tests for v1.5.0 Advanced Forensic Enhancements:
1. Zero-Copy ForensicBuffer (mmap)
2. Chained Overflow Page Payload Reconstruction
3. EOF Slack Detection and Recovery
4. Anti-Forensics Anomaly Detection Engine
5. Interactive Smartphone Chat & Messages HTML Dashboard
"""

import os
import sqlite3
import tempfile
from pathlib import Path
import pytest

from sqlite_carver.core.carver import SQLiteCarver, TableSchema
from sqlite_carver.core.integrity import check_anti_forensics_anomalies
from sqlite_carver.core.parser import DatabaseParser, ForensicBuffer, open_forensic_buffer
from sqlite_carver.exporters.html_report import generate_html_report


def test_forensic_buffer_mmap():
    """Verify ForensicBuffer maps files without loading full file into memory."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        p = Path(tmp.name)
        data = b"SQLite format 3\x00" + b"\x00" * 4080
        p.write_bytes(data)

    try:
        with open_forensic_buffer(p) as buf:
            assert len(buf) == 4096
            assert bytes(buf[:16]) == b"SQLite format 3\x00"
            with DatabaseParser(buf) as parser:
                assert parser.page_size == 4096
                assert parser.total_pages == 1
    finally:
        if p.exists():
            p.unlink()


def test_overflow_page_reconstruction_carving():
    """
    Verify that records larger than leaf page capacity spanning overflow pages
    are fully reconstructed during carving.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA page_size = 1024;")
        cursor.execute("PRAGMA secure_delete = OFF;")
        cursor.execute("CREATE TABLE long_messages (id INTEGER PRIMARY KEY, recipient TEXT, long_text TEXT);")
        
        large_text = "CONFIDENTIAL_PAYLOAD_CHUNK_" * 200
        cursor.execute("INSERT INTO long_messages VALUES (1, 'agent_47', ?);", (large_text,))
        cursor.execute("INSERT INTO long_messages VALUES (2, 'agent_99', 'short message');")
        conn.commit()
        conn.close()

        with open_forensic_buffer(db_path) as raw_data:
            with SQLiteCarver(raw_data) as carver:
                records = carver.carve_all(include_active=True)

        found_large = False
        for r in records:
            for v in r.values:
                if isinstance(v, str) and "CONFIDENTIAL_PAYLOAD_CHUNK_" in v and len(v) >= 1000:
                    found_large = True
                    break
            if found_large:
                break
        assert found_large, "Record spanning overflow pages was not carved!"
    finally:
        if db_path.exists():
            db_path.unlink()


def test_eof_slack_detection_and_carving():
    """Verify that trailing EOF slack past logical DB size is detected and carved."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA page_size = 4096;")
        cursor.execute("CREATE TABLE secrets (id INT, secret_code TEXT);")
        cursor.execute("INSERT INTO secrets VALUES (1, 'ALPHA_CODE_99');")
        conn.commit()
        conn.close()

        slack_payload = b"\x00" * 64 + b"TAIL_SLACK_FORENSIC_EVIDENCE" + b"\x00" * 128
        with open(db_path, "ab") as f:
            f.write(slack_payload)

        actual_size = db_path.stat().st_size
        with open_forensic_buffer(db_path) as raw_data:
            with DatabaseParser(raw_data) as parser:
                assert parser.eof_slack_size >= len(slack_payload)
                raw_slack = parser.get_eof_slack_bytes()
                assert raw_slack is not None
                assert b"TAIL_SLACK_FORENSIC_EVIDENCE" in bytes(raw_slack)

                breakdown = parser.compute_storage_breakdown()
                assert breakdown.eof_slack_bytes >= len(slack_payload)

                anomalies = check_anti_forensics_anomalies(parser, actual_file_size=actual_size)
                assert any(a["code"] == "EOF_SLACK_DETECTED" for a in anomalies)
                del raw_slack
    finally:
        if db_path.exists():
            db_path.unlink()


def test_anti_forensics_anomaly_change_counter_mismatch():
    """Verify change counter mismatch detection when database header is tampered."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE t (x INT);")
        conn.execute("INSERT INTO t VALUES (1);")
        conn.commit()
        conn.close()

        db_bytes = bytearray(db_path.read_bytes())
        db_bytes[24:28] = (99999).to_bytes(4, "big")
        db_bytes[92:96] = (1).to_bytes(4, "big")
        db_path.write_bytes(db_bytes)

        with open_forensic_buffer(db_path) as raw_data:
            with DatabaseParser(raw_data) as parser:
                anomalies = check_anti_forensics_anomalies(parser, actual_file_size=len(raw_data))
                assert any(a["code"] == "CHANGE_COUNTER_MISMATCH" for a in anomalies)
    finally:
        if db_path.exists():
            db_path.unlink()


def test_html_report_anti_forensics_banner_generation():
    """Verify that HTML export contains the anti-forensics banner and clean forensic layout."""
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
        html_path = Path(tmp.name)

    try:
        from sqlite_carver.core.carver import CarvedRecord

        records = [
            CarvedRecord(
                page_id=2,
                offset_in_page=100,
                source="active",
                confidence=1.0,
                matched_table="message",
                rowid=1,
                values=[1, "agent_alice", "Meet me at safehouse B.", 1600000000, 0],
                column_names=["id", "sender", "text", "date", "is_from_me"],
                column_types=["INTEGER", "TEXT", "TEXT", "INTEGER", "INTEGER"],
                serial_types=[1, 25, 47, 4, 1],
                raw_payload=b"\x01test",
            ),
            CarvedRecord(
                page_id=3,
                offset_in_page=250,
                source="unallocated",
                confidence=0.9,
                matched_table="message",
                rowid=2,
                values=[2, "agent_bob", "Understood. Bring the encrypted drive.", 1600000060, 1],
                column_names=["id", "sender", "text", "date", "is_from_me"],
                column_types=["INTEGER", "TEXT", "TEXT", "INTEGER", "INTEGER"],
                serial_types=[1, 21, 75, 4, 1],
                raw_payload=b"\x02test",
                details="Carved from unallocated space",
            ),
        ]

        generate_html_report(
            records=records,
            output_path=html_path,
            title="Forensics Test Report",
            integrity_info={
                "anomalies": [
                    {
                        "code": "EOF_SLACK_DETECTED",
                        "severity": "HIGH",
                        "title": "EOF Slack Space Detected",
                        "details": "Trailing data discovered.",
                    }
                ]
            },
        )

        content = html_path.read_text(encoding="utf-8")
        assert "btn-tab-evidence" in content
        assert "btn-tab-wal" in content
        assert "btn-tab-chat" not in content
        assert "antiForensicsBanner" in content
        assert "EOF_SLACK_DETECTED" in content
        assert "Dam-FOR3K" in content
    finally:
        if html_path.exists():
            html_path.unlink()

