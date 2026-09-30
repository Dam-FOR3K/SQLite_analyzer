import struct
import pytest
from sqlite_carver.core.parser import DatabaseParser, StorageBreakdown, PageType


def test_storage_breakdown_metrics():
    page_size = 512
    # Create valid SQLite database header (100 bytes)
    # 0..16: magic
    # 16..18: page size (512)
    # 32..36: first freelist trunk (0)
    # 36..40: total freelist pages (0)
    magic = b"SQLite format 3\x00"
    hdr = bytearray(100)
    hdr[:16] = magic
    struct.pack_into(">H", hdr, 16, page_size)
    struct.pack_into(">B", hdr, 18, 1)  # write version
    struct.pack_into(">B", hdr, 19, 1)  # read version
    struct.pack_into(">B", hdr, 20, 0)  # reserved space

    # Page 1: 100 bytes DB header + PageHeader
    # Leaf table header at offset 100: type 0x0D, first_fb 0, cell_count 0, cell_content 512, frag 7
    page1 = bytearray(hdr)
    page_hdr = struct.pack(">BHHHB", PageType.TABLE_LEAF.value, 0, 0, 512, 7)
    page1.extend(page_hdr)
    page1 = page1.ljust(page_size, b"\x00")

    parser = DatabaseParser(bytes(page1))
    breakdown = parser.compute_storage_breakdown()

    assert breakdown.total_pages == 1
    assert breakdown.page_size == 512
    assert breakdown.fragmented_free_bytes == 7
    assert breakdown.freelist_pages_count == 0
    assert breakdown.total_bytes == 512

    d = breakdown.to_dict()
    assert d["fragmented_free_bytes"] == 7
    assert d["total_pages"] == 1


def test_storage_breakdown_with_reserved_space():
    page_size = 512
    reserved_sz = 16
    magic = b"SQLite format 3\x00"
    hdr = bytearray(100)
    hdr[:16] = magic
    struct.pack_into(">H", hdr, 16, page_size)
    struct.pack_into(">B", hdr, 18, 1)
    struct.pack_into(">B", hdr, 19, 1)
    struct.pack_into(">B", hdr, 20, reserved_sz)  # reserved space

    # Page 1: 100 bytes DB header + PageHeader
    page1 = bytearray(hdr)
    usable_sz = page_size - reserved_sz
    page_hdr = struct.pack(">BHHHB", PageType.TABLE_LEAF.value, 0, 0, usable_sz, 0)
    page1.extend(page_hdr)
    page1 = page1.ljust(page_size, b"\x00")
    # Put hidden text in reserved area
    page1[usable_sz:] = b"HiddenPayload123"

    parser = DatabaseParser(bytes(page1))
    breakdown = parser.compute_storage_breakdown()

    assert breakdown.reserved_space_per_page == 16
    assert breakdown.reserved_space_bytes == 16
    assert breakdown.to_dict()["reserved_space_bytes"] == 16
    assert breakdown.to_dict()["total_slack_bytes"] >= 16

