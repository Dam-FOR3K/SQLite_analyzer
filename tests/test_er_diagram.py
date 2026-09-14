import sqlite3
import pytest
from sqlite_carver.core.carver import SQLiteCarver
from sqlite_carver.exporters.html_report import generate_html_report


def test_html_report_schema_er_diagram_generation(tmp_path):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")
    cur.execute("""
        CREATE TABLE departments (
            dept_id INTEGER PRIMARY KEY,
            dept_name TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE employees (
            emp_id INTEGER PRIMARY KEY,
            dept_id INTEGER,
            full_name TEXT,
            FOREIGN KEY (dept_id) REFERENCES departments(dept_id)
        );
    """)
    cur.execute("INSERT INTO departments VALUES (1, 'Engineering');")
    cur.execute("INSERT INTO employees VALUES (10, 1, 'John Doe');")
    conn.commit()

    raw_db = conn.serialize()
    conn.close()

    carver = SQLiteCarver(raw_db)
    schemas = carver.schemas
    records = carver.carve_all(include_active=True)

    out_file = tmp_path / "topology.html"
    generate_html_report(
        records=records,
        output_path=out_file,
        title="Topology Forensic Report",
        schemas=schemas,
        lang="en",
    )
    html_content = out_file.read_text(encoding="utf-8")

    assert 'id="btn-tab-schema"' in html_content
    assert 'id="pane-schema"' in html_content
    assert "Database Schema & ER Diagram" in html_content

    assert "erDiagram" in html_content
    assert "departments" in html_content
    assert "employees" in html_content
    assert "copyMermaidCode()" in html_content

    assert "dept_name" in html_content
    assert "full_name" in html_content
