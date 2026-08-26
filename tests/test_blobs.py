"""Tests for embedded binary payload extractors (bplist, protobuf, zlib)."""

import plistlib
import struct
import zlib
import pytest

from sqlite_carver.decoders.blobs import (
    decode_bplist,
    decode_protobuf_wire,
    decode_zlib,
    inspect_blob,
)


def test_apple_binary_plist():
    sample_dict = {"User": "Administrator", "UID": 501, "Roles": ["admin", "forensics"]}
    bplist_bytes = plistlib.dumps(sample_dict, fmt=plistlib.FMT_BINARY)

    res = decode_bplist(bplist_bytes)
    assert res is not None
    assert res.detected_format == "bplist"
    assert res.data["User"] == "Administrator"
    assert res.data["UID"] == 501
    assert res.data["Roles"] == ["admin", "forensics"]


def test_protobuf_dynamic_wire_parser():
    # Construct a raw protobuf message manually:
    # Field 1 (Varint): 150 -> Tag: (1 << 3) | 0 = 0x08, Value: 0x96 0x01
    # Field 2 (String): "ForensicPayload" -> Tag: (2 << 3) | 2 = 0x12, Len: 15, String bytes
    # Field 3 (Float 32): 42.5 -> Tag: (3 << 3) | 5 = 0x1D, Float bytes
    str_val = b"ForensicPayload"
    raw_proto = bytearray()
    # Field 1
    raw_proto.extend([0x08, 0x96, 0x01])
    # Field 2
    raw_proto.extend([0x12, len(str_val)])
    raw_proto.extend(str_val)
    # Field 3
    raw_proto.append(0x1D)
    raw_proto.extend(struct.pack("<f", 42.5))

    parsed = decode_protobuf_wire(bytes(raw_proto))
    assert parsed is not None
    assert parsed["field_1"] == 150
    assert parsed["field_2"] == "ForensicPayload"
    assert pytest.approx(parsed["field_3"]["float"]) == 42.5


def test_zlib_compressed_stream():
    original_text = "Highly confidential forensic artifact payload compressed with deflate."
    compressed = zlib.compress(original_text.encode("utf-8"))

    res = decode_zlib(compressed)
    assert res is not None
    assert res.detected_format == "zlib+text"
    assert res.data == original_text


def test_inspect_blob_router():
    # Test router automatically identifying formats
    # 1. Plist
    bplist_bytes = plistlib.dumps({"device": "iPhone14,2"}, fmt=plistlib.FMT_BINARY)
    assert inspect_blob(bplist_bytes).detected_format == "bplist"

    # 2. Zlib Text
    zlib_bytes = zlib.compress(b"Secret Document Contents")
    assert inspect_blob(zlib_bytes).detected_format == "zlib+text"

    # 3. Zlib Binary (unprintable binary)
    zlib_bin = zlib.compress(bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x88, 0x99]))
    res_bin = inspect_blob(zlib_bin)
    assert res_bin.detected_format == "zlib+binary"
    assert res_bin.metadata["uncompressed_size"] == 8

    # 4. Plain text
    assert inspect_blob(b"Hello Forensics").detected_format == "text"


def test_protobuf_false_positive_rejection():
    # Test that random/invalid byte sequences with invalid tags/wire types are properly rejected
    invalid_wire = bytes([0xFF, 0xFF, 0xFF, 0x7F, 0x07, 0x12])  # wire_type 7 is invalid
    assert decode_protobuf_wire(invalid_wire) is None

    # Single zero byte or too short
    assert decode_protobuf_wire(b"\x00") is None

    # Tag with reserved field number
    reserved_tag = (19001 << 3) | 0
    raw_res = bytearray()
    raw_res.extend([0xC8, 0xD0, 0x09, 0x01])  # field 19001
    assert decode_protobuf_wire(bytes(raw_res)) is None
