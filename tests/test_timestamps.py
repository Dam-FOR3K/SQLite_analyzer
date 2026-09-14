import pytest
from sqlite_carver.decoders.timestamps import decode_timestamp, get_all_possible_timestamps, DecodedTimestamp

def test_webkit_chrome_timestamp():
    # 2023-11-28 21:01:41.234568 UTC
    val = 13345678901234567
    ts = decode_timestamp(val)
    assert ts is not None
    assert ts.format_name == "webkit"
    assert "2023-11-28" in ts.iso_utc
    assert "WebKit" in ts.description

def test_windows_filetime_timestamp():
    # 2023-11-28 21:01:41.234567 UTC
    val = 133456789012345678
    ts = decode_timestamp(val)
    assert ts is not None
    assert ts.format_name == "filetime"
    assert "2023-11-28" in ts.iso_utc
    assert "FILETIME" in ts.description

def test_unix_ms_timestamp():
    # 2024-08-24 11:46:40 UTC
    val = 1724500000000
    ts = decode_timestamp(val)
    assert ts is not None
    assert ts.format_name == "unix_ms"
    assert "2024-08-24" in ts.iso_utc

def test_unix_sec_timestamp():
    # 2024-08-24 11:46:40 UTC
    val = 1724500000
    ts = decode_timestamp(val, column_hint="created_at")
    assert ts is not None
    assert ts.format_name == "unix_sec"
    assert "2024-08-24" in ts.iso_utc

def test_cocoa_mac_timestamp():
    # Seconds since 2001-01-01
    val = 724500000
    ts = decode_timestamp(val, column_hint="ZDATE")
    assert ts is not None
    assert ts.format_name == "cocoa_sec"
    assert "2023-12-17" in ts.iso_utc

def test_invalid_negative_or_zero():
    assert decode_timestamp(0) is None
    assert decode_timestamp(-100) is None
    assert decode_timestamp("not_a_number") is None

def test_get_all_possible_timestamps():
    val = 1724500000
    results = get_all_possible_timestamps(val)
    assert len(results) >= 1
    assert any(r.format_name == "unix_sec" for r in results)
