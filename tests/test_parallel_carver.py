import sqlite3
import pytest
from sqlite_carver.core.carver import SQLiteCarver, TableSchema


def test_parallel_carve_raw_pages():
    # Create database with multiple pages of records
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("PRAGMA page_size = 4096;")
    cur.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT);")
    for i in range(1, 100):
        cur.execute("INSERT INTO logs VALUES (?, ?);", (i, f"Audit event #{i} logged at checkpoint"))
    conn.commit()

    raw_db = conn.serialize()
    conn.close()

    # Concatenate 4 copies of raw_db separated by unaligned padding to simulate 100KB+ memory dump
    simulated_dump = (raw_db + (b"\xcc" * 2048)) * 4
    schema = TableSchema.from_sql("logs", 0, "CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT)")

    # Test single-threaded
    recs_single = SQLiteCarver.carve_raw_pages(
        simulated_dump,
        page_size=4096,
        user_schemas=[schema],
        include_active=True,
        workers=1,
    )

    # Test multi-threaded (workers=2)
    recs_multi = SQLiteCarver.carve_raw_pages(
        simulated_dump,
        page_size=4096,
        user_schemas=[schema],
        include_active=True,
        workers=2,
    )

    # Verify both carved the records and found identical count
    assert len(recs_single) > 0
    assert len(recs_single) == len(recs_multi)
    assert {r.evidence_hash for r in recs_single} == {r.evidence_hash for r in recs_multi}
