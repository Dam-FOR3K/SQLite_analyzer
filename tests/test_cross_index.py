import sqlite3
import pytest
from sqlite_carver.core.carver import SQLiteCarver


def test_cross_index_resurrection_multi_column():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("PRAGMA page_size = 4096;")
    cur.execute("PRAGMA auto_vacuum = 0;")
    cur.execute("""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY,
            email TEXT,
            phone TEXT,
            balance REAL
        );
    """)
    cur.execute("CREATE INDEX idx_accounts_email ON accounts (email);")
    cur.execute("CREATE INDEX idx_accounts_phone ON accounts (phone);")

    for i in range(1, 15):
        cur.execute(
            "INSERT INTO accounts VALUES (?, ?, ?, ?);",
            (i, f"user_{i}@cyber.fr", f"+336000000{i:02d}", 100.0 * i),
        )
    conn.commit()

    cur.execute("DELETE FROM accounts WHERE id = 7;")
    conn.commit()

    raw_db = conn.serialize()
    conn.close()

    carver = SQLiteCarver(raw_db)
    records = carver.carve_all(include_active=False)

    resurrected = [r for r in records if r.rowid == 7 or (r.values and any("user_7@cyber.fr" in str(v) for v in r.values if v is not None))]
    assert len(resurrected) >= 1

    from_index = [r for r in resurrected if r.source == "resurrected_from_index"]
    assert len(from_index) >= 1
    idx_rec = from_index[0]
    assert idx_rec.confidence >= 0.90
    assert idx_rec.matched_table == "accounts"
    assert idx_rec.rowid == 7
    val_strs = [str(v) for v in idx_rec.values if v is not None]
    assert any("user_7@cyber.fr" in s for s in val_strs)
