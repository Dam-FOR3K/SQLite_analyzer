import hashlib
import tempfile
from pathlib import Path
import pytest
from sqlite_carver.core.integrity import compute_record_evidence_hash, hash_bytes, hash_file


def test_hash_bytes():
    payload = b"forensic verification data 123"
    digests = hash_bytes(payload)
    assert digests["sha256"] == hashlib.sha256(payload).hexdigest()
    assert digests["md5"] == hashlib.md5(payload).hexdigest()


def test_hash_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"file integrity evidence test")
        temp_path = Path(f.name)

    try:
        res = hash_file(temp_path)
        assert res["filename"] == temp_path.name
        assert res["size_bytes"] == len(b"file integrity evidence test")
        assert res["sha256"] == hashlib.sha256(b"file integrity evidence test").hexdigest()
        assert res["md5"] == hashlib.md5(b"file integrity evidence test").hexdigest()
    finally:
        temp_path.unlink(missing_ok=True)


def test_compute_record_evidence_hash_deterministic():
    h1 = compute_record_evidence_hash(
        page_id=5,
        offset_in_page=128,
        source="freeblock",
        matched_table="messages",
        rowid=42,
        values=["alice", "hello", 12345],
    )
    h2 = compute_record_evidence_hash(
        page_id=5,
        offset_in_page=128,
        source="freeblock",
        matched_table="messages",
        rowid=42,
        values=["alice", "hello", 12345],
    )
    assert len(h1) == 64
    assert h1 == h2

    # Different rowid should produce different hash
    h3 = compute_record_evidence_hash(
        page_id=5,
        offset_in_page=128,
        source="freeblock",
        matched_table="messages",
        rowid=43,
        values=["alice", "hello", 12345],
    )
    assert h1 != h3


def test_anti_forensics_reserved_space_detection():
    import struct
    from sqlite_carver.core.integrity import check_anti_forensics_anomalies
    from sqlite_carver.core.parser import DatabaseParser
    hdr = bytearray(100)
    hdr[:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", hdr, 16, 512)
    hdr[18] = 1
    hdr[19] = 1
    hdr[20] = 16  # reserved bytes per page
    db_bytes = bytes(hdr).ljust(1024, b"\x00")
    parser = DatabaseParser(db_bytes)
    anomalies = check_anti_forensics_anomalies(parser, file_size=len(db_bytes))
    codes = [a["code"] for a in anomalies]
    assert "PAGE_RESERVED_SPACE_DETECTED" in codes
    res_a = [a for a in anomalies if a["code"] == "PAGE_RESERVED_SPACE_DETECTED"][0]
    assert res_a["reserved_space_per_page"] == 16
    assert res_a["total_reserved_bytes"] == 32


