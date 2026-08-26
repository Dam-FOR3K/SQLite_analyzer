"""Tests for binary SQLite parser, headers, pages, cells, and overflow handling."""

import struct
import pytest
from sqlite_carver.core.parser import (
    DatabaseHeader,
    DatabaseParser,
    PageHeader,
    PageType,
    calculate_local_payload_size,
    decode_record_payload,
)
from sqlite_carver.core.varint import encode_varint


def test_database_header_parsing():
    # Build a standard 100-byte SQLite header
    header_bytes = bytearray(100)
    header_bytes[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", header_bytes, 16, 4096)  # Page size 4096
    header_bytes[18] = 2  # WAL write version
    header_bytes[19] = 2  # WAL read version
    header_bytes[20] = 0  # Reserved space
    struct.pack_into(">II", header_bytes, 24, 42, 10)  # change counter 42, size 10 pages
    struct.pack_into(">II", header_bytes, 32, 5, 2)    # freelist trunk 5, total free 2
    struct.pack_into(">II", header_bytes, 56, 1, 0)    # encoding UTF-8 (1)

    hdr = DatabaseHeader.from_bytes(header_bytes)
    assert hdr.page_size == 4096
    assert hdr.usable_page_size == 4096
    assert hdr.write_version == 2
    assert hdr.encoding == "utf-8"
    assert hdr.file_change_counter == 42
    assert hdr.first_freelist_trunk_page == 5
    assert hdr.total_freelist_pages == 2


def test_page_header_parsing():
    # Table leaf page (0x0D), first_freeblock=0, 3 cells, cell_content=3800, 0 frag bytes
    page_data = bytearray(4096)
    page_data[0] = 0x0D
    struct.pack_into(">HHHB", page_data, 1, 0, 3, 3800, 0)

    hdr = PageHeader.from_bytes(page_data, is_page_1=False)
    assert hdr.page_type == PageType.TABLE_LEAF
    assert hdr.cell_count == 3
    assert hdr.cell_content_start == 3800
    assert hdr.header_size == 8

    # Table interior page (0x05) with rightmost child pointer
    page_data[0] = 0x05
    struct.pack_into(">HHHBI", page_data, 1, 0, 2, 3900, 0, 7)
    hdr_interior = PageHeader.from_bytes(page_data, is_page_1=False)
    assert hdr_interior.page_type == PageType.TABLE_INTERIOR
    assert hdr_interior.header_size == 12
    assert hdr_interior.rightmost_pointer == 7


def test_decode_record_payload():
    # Construct a SQLite record: (id: 1, name: "Antigravity", score: 99.5)
    # Header: [header_size, st_id, st_name, st_score]
    name_bytes = "Antigravity".encode("utf-8")
    st_id = 9       # constant 1 (length 0)
    st_name = 13 + len(name_bytes) * 2  # 13 + 22 = 35
    st_score = 7    # float 64 (length 8)

    # Header size varint: 4 bytes total header
    hdr = bytes([4, st_id, st_name, st_score])
    body = name_bytes + struct.pack(">d", 99.5)
    payload = hdr + body

    rec = decode_record_payload(payload)
    assert rec is not None
    assert rec.values == [1, "Antigravity", 99.5]
    assert rec.column_types == ["INTEGER", "TEXT", "REAL"]
    assert rec.is_partial is False


def test_overflow_reassembly():
    # Simulate a database with an overflow page chain: Page 1 -> Page 2 -> Page 3
    page_size = 512
    db_bytes = bytearray(page_size * 3)

    # Page 1: DB Header + Leaf table with large record pointing to overflow page 2
    db_bytes[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", db_bytes, 16, page_size)
    struct.pack_into(">II", db_bytes, 56, 1, 0)  # UTF-8

    parser = DatabaseParser(db_bytes)
    assert parser.page_size == 512

    # Overflow Page 2: points to Page 3, contains 508 bytes
    chunk_1 = b"A" * 508
    struct.pack_into(">I", db_bytes, page_size * 1, 3)  # Next overflow page = 3
    db_bytes[page_size * 1 + 4 : page_size * 2] = chunk_1

    # Overflow Page 3: final page (points to 0), contains 200 bytes
    chunk_2 = b"B" * 200
    struct.pack_into(">I", db_bytes, page_size * 2, 0)  # Next overflow page = 0
    db_bytes[page_size * 2 + 4 : page_size * 2 + 4 + len(chunk_2)] = chunk_2

    reassembled = parser.reassemble_overflow_chain(first_overflow_page=2, needed_bytes=708)
    assert len(reassembled) == 708
    assert reassembled == chunk_1 + chunk_2


def test_freelist_traversal():
    page_size = 512
    db_bytes = bytearray(page_size * 4)
    db_bytes[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", db_bytes, 16, page_size)
    struct.pack_into(">II", db_bytes, 32, 2, 2)  # First trunk page = 2, total free = 2

    # Page 2: Trunk page. Points to next trunk 0, 2 leaf pages: [3, 4]
    struct.pack_into(">II", db_bytes, page_size * 1, 0, 2)
    struct.pack_into(">II", db_bytes, page_size * 1 + 8, 3, 4)

    parser = DatabaseParser(db_bytes)
    freelist = parser.parse_freelist_pages()
    assert freelist == [2, 3, 4]
