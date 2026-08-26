"""Tests for varint and serial type codec."""

import struct
import pytest
from sqlite_carver.core.varint import (
    VarintError,
    decode_serial_value,
    encode_varint,
    read_varint,
    safe_read_varint,
    serial_type_length,
    serial_type_name,
)


def test_single_byte_varint():
    assert read_varint(b"\x00") == (0, 1)
    assert read_varint(b"\x7F") == (127, 1)
    assert read_varint(b"\x2A") == (42, 1)


def test_multi_byte_varint():
    # 128 = 0x81 0x00
    assert read_varint(b"\x81\x00") == (128, 2)
    # 300 = 0x82 0x2C
    val, consumed = read_varint(b"\x82\x2c")
    assert val == 300
    assert consumed == 2

    # Roundtrip encode-decode test
    for v in [0, 1, 127, 128, 255, 300, 16384, 65535, 1000000, 0xFFFFFFFF]:
        enc = encode_varint(v)
        dec_v, dec_len = read_varint(enc)
        assert dec_v == v
        assert dec_len == len(enc)


def test_nine_byte_varint():
    # 9-byte varint test with high bit set on 9th byte
    raw = bytes([0x81] * 8 + [0xFF])
    val, consumed = read_varint(raw)
    assert consumed == 9
    assert val > 0


def test_truncated_varint():
    # Buffer ended while continuation bit was set
    with pytest.raises(VarintError):
        read_varint(b"\x81")
    assert safe_read_varint(b"\x81") is None
    assert safe_read_varint(b"") is None


def test_serial_type_lengths():
    assert serial_type_length(0) == 0   # NULL
    assert serial_type_length(1) == 1   # INT8
    assert serial_type_length(2) == 2   # INT16
    assert serial_type_length(3) == 3   # INT24
    assert serial_type_length(4) == 4   # INT32
    assert serial_type_length(5) == 6   # INT48
    assert serial_type_length(6) == 8   # INT64
    assert serial_type_length(7) == 8   # FLOAT
    assert serial_type_length(8) == 0   # Constant 0
    assert serial_type_length(9) == 0   # Constant 1
    assert serial_type_length(12) == 0  # 0-byte BLOB
    assert serial_type_length(14) == 1  # 1-byte BLOB
    assert serial_type_length(13) == 0  # 0-byte TEXT
    assert serial_type_length(23) == 5  # 5-byte TEXT: (23-13)/2 = 5


def test_decode_serial_values():
    # NULL
    assert decode_serial_value(0, b"") == (None, "NULL", 0)
    # INT 0 and 1
    assert decode_serial_value(8, b"") == (0, "INTEGER", 0)
    assert decode_serial_value(9, b"") == (1, "INTEGER", 0)

    # 8-bit signed int
    assert decode_serial_value(1, b"\xFE") == (-2, "INTEGER", 1)
    assert decode_serial_value(1, b"\x2A") == (42, "INTEGER", 1)

    # 16-bit signed int
    assert decode_serial_value(2, struct.pack(">h", -1234)) == (-1234, "INTEGER", 2)

    # 24-bit signed int
    b24 = int(-50000).to_bytes(3, byteorder="big", signed=True)
    assert decode_serial_value(3, b24) == (-50000, "INTEGER", 3)

    # 32-bit signed int
    assert decode_serial_value(4, struct.pack(">i", 100000)) == (100000, "INTEGER", 4)

    # 48-bit signed int
    b48 = int(123456789012).to_bytes(6, byteorder="big", signed=True)
    assert decode_serial_value(5, b48) == (123456789012, "INTEGER", 6)

    # 64-bit signed int
    assert decode_serial_value(6, struct.pack(">q", -9999999999)) == (-9999999999, "INTEGER", 8)

    # 64-bit Float
    val, tname, consumed = decode_serial_value(7, struct.pack(">d", 3.14159))
    assert pytest.approx(val) == 3.14159
    assert tname == "REAL"
    assert consumed == 8

    # TEXT
    text_data = "Forensics".encode("utf-8")
    st_text = 13 + len(text_data) * 2
    assert decode_serial_value(st_text, text_data) == ("Forensics", "TEXT", 9)

    # BLOB
    blob_data = b"\xDE\xAD\xBE\xEF"
    st_blob = 12 + len(blob_data) * 2
    assert decode_serial_value(st_blob, blob_data) == (b"\xDE\xAD\xBE\xEF", "BLOB", 4)


def test_truncated_serial_value():
    # Attempting to read 4 bytes when only 2 are available
    val, tname, consumed = decode_serial_value(4, b"\x12\x34")
    assert tname.startswith("TRUNCATED_")
    assert consumed == 2
    assert val == b"\x12\x34"
