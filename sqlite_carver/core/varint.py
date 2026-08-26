"""
SQLite Variable-Length Integer (Varint) and Serial Type Codec.

Handles strict parsing and recovery of SQLite varints (1-9 bytes) and
all SQLite record serial types (0-9, strings, blobs, floats, signed integers).
Designed with zero-crash semantics for forensic and corrupt payload carving.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Tuple


class VarintError(Exception):
    """Raised when varint decoding encounters malformed or truncated data."""
    pass


def read_varint(data: bytes | memoryview, offset: int = 0) -> tuple[int, int]:
    """
    Reads a variable-length integer from data starting at offset.

    Returns:
        tuple[int, int]: (decoded_integer_value, bytes_consumed)

    Raises:
        VarintError: If the buffer is truncated before completing a valid varint.
    """
    data_len = len(data)
    if offset >= data_len:
        raise VarintError(f"Offset {offset} is beyond buffer length {data_len}")

    v = 0
    for i in range(8):
        idx = offset + i
        if idx >= data_len:
            raise VarintError(f"Truncated varint at index {idx}, buffer length {data_len}")
        b = data[idx]
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            return v, i + 1

    # 9th byte uses all 8 bits
    idx = offset + 8
    if idx >= data_len:
        raise VarintError(f"Truncated 9-byte varint at index {idx}")
    b = data[idx]
    v = (v << 8) | b
    return v, 9


def safe_read_varint(data: bytes | memoryview, offset: int = 0) -> tuple[int, int] | None:
    """
    Non-throwing safe variant of read_varint. Returns None if decoding fails.
    """
    try:
        return read_varint(data, offset)
    except VarintError:
        return None


def encode_varint(val: int) -> bytes:
    """
    Encodes an integer into SQLite variable-length format (up to 9 bytes).
    """
    if val < 0:
        val = val & 0xFFFFFFFFFFFFFFFF

    if val <= 0x7F:
        return bytes([val])

    buf = bytearray()
    if val > 0x00FFFFFFFFFFFFFF:
        buf.append(val & 0xFF)
        val >>= 8
        while val > 0:
            buf.append((val & 0x7F) | 0x80)
            val >>= 7
        buf.reverse()
        return bytes(buf)

    while val > 0:
        buf.append(val & 0x7F)
        val >>= 7

    out = bytearray()
    for i in range(len(buf) - 1, 0, -1):
        out.append(buf[i] | 0x80)
    out.append(buf[0])
    return bytes(out)


def serial_type_length(serial_type: int) -> int:
    """
    Computes the byte length of data associated with a given serial type.
    """
    if serial_type == 0:
        return 0  # NULL
    elif serial_type == 1:
        return 1  # 8-bit signed int
    elif serial_type == 2:
        return 2  # 16-bit signed int
    elif serial_type == 3:
        return 3  # 24-bit signed int
    elif serial_type == 4:
        return 4  # 32-bit signed int
    elif serial_type == 5:
        return 6  # 48-bit signed int
    elif serial_type == 6:
        return 8  # 64-bit signed int
    elif serial_type == 7:
        return 8  # 64-bit IEEE float
    elif serial_type in (8, 9, 10, 11):
        return 0  # Constant 0, Constant 1, Reserved
    elif serial_type >= 12 and (serial_type % 2 == 0):
        return (serial_type - 12) // 2  # BLOB
    elif serial_type >= 13 and (serial_type % 2 != 0):
        return (serial_type - 13) // 2  # TEXT
    return 0


def serial_type_name(serial_type: int) -> str:
    """Returns human-readable name of the SQLite serial type."""
    if serial_type == 0:
        return "NULL"
    elif 1 <= serial_type <= 6:
        return f"INT{serial_type_length(serial_type) * 8}"
    elif serial_type == 7:
        return "FLOAT"
    elif serial_type == 8:
        return "INT_0"
    elif serial_type == 9:
        return "INT_1"
    elif serial_type in (10, 11):
        return "RESERVED"
    elif serial_type >= 12 and (serial_type % 2 == 0):
        return f"BLOB[{serial_type_length(serial_type)}]"
    elif serial_type >= 13 and (serial_type % 2 != 0):
        return f"TEXT[{serial_type_length(serial_type)}]"
    return "UNKNOWN"


def decode_serial_value(
    serial_type: int,
    data: bytes | memoryview,
    offset: int = 0,
    encoding: str = "utf-8",
) -> tuple[Any, str, int]:
    """
    Decodes a single column value from data at offset given its serial type.

    Returns:
        tuple[Any, str, int]: (decoded_value, type_name, bytes_consumed)
    """
    length = serial_type_length(serial_type)
    data_len = len(data)

    if offset + length > data_len:
        # Partial / truncated column payload in corrupted/carved records
        available = max(0, data_len - offset)
        raw_slice = bytes(data[offset:offset + available])
        return raw_slice, f"TRUNCATED_{serial_type_name(serial_type)}", available

    raw = data[offset:offset + length]

    if serial_type == 0:
        return None, "NULL", 0

    elif serial_type == 1:
        val = struct.unpack(">b", raw)[0]
        return val, "INTEGER", 1

    elif serial_type == 2:
        val = struct.unpack(">h", raw)[0]
        return val, "INTEGER", 2

    elif serial_type == 3:
        # 24-bit big-endian signed int
        b = bytes(raw)
        val = int.from_bytes(b, byteorder="big", signed=True)
        return val, "INTEGER", 3

    elif serial_type == 4:
        val = struct.unpack(">i", raw)[0]
        return val, "INTEGER", 4

    elif serial_type == 5:
        # 48-bit big-endian signed int
        b = bytes(raw)
        val = int.from_bytes(b, byteorder="big", signed=True)
        return val, "INTEGER", 6

    elif serial_type == 6:
        val = struct.unpack(">q", raw)[0]
        return val, "INTEGER", 8

    elif serial_type == 7:
        val = struct.unpack(">d", raw)[0]
        return val, "REAL", 8

    elif serial_type == 8:
        return 0, "INTEGER", 0

    elif serial_type == 9:
        return 1, "INTEGER", 0

    elif serial_type in (10, 11):
        return None, "RESERVED", 0

    elif serial_type >= 12 and (serial_type % 2 == 0):
        # BLOB
        return bytes(raw), "BLOB", length

    elif serial_type >= 13 and (serial_type % 2 != 0):
        # TEXT
        b = bytes(raw)
        try:
            val = b.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            # Fallback with replacement for forensic resilience
            val = b.decode(encoding, errors="replace")
        return val, "TEXT", length

    return bytes(raw), "UNKNOWN", length
