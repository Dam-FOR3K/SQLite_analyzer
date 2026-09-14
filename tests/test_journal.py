import struct
import pytest
from sqlite_carver.core.carver import TableSchema
from sqlite_carver.core.wal_diff import JournalDiffEngine, JournalHeader, RowMutation, MutationType


def test_journal_header_parse():
    # SQLite 3 rollback journal header format:
    # 0..8: Magic (0xd9d505f920a163d7)
    # 8..12: Page count in journal
    # 12..16: Random nonce
    # 16..20: Initial database size in pages
    # 20..24: Sector size (usually 512 or 4096)
    # 24..28: Page size
    magic = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"
    hdr_data = magic + struct.pack(">IIIII", 1, 0x12345678, 10, 512, 4096)
    header = JournalHeader.from_bytes(hdr_data)
    assert header is not None
    assert header.page_count == 1
    assert header.nonce == 0x12345678
    assert header.initial_db_size == 10
    assert header.sector_size == 512
    assert header.page_size == 4096


def test_journal_engine_diff():
    # Construct base db with page size 512 and page 2 containing old cell
    # Base db page 1 (header + dummy), page 2
    page_size = 512
    magic = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"
    # Sector size 512, page size 512
    j_hdr = magic + struct.pack(">IIIII", 1, 0, 2, 512, page_size)
    # Pad sector to 512 bytes
    j_hdr = j_hdr.ljust(512, b"\x00")

    # In journal frame: [4-byte page_id] [page_data] [4-byte checksum]
    page_id = 2
    # Leaf table page header: 0x0D, cell_count=0, cell_content_offset=512
    leaf_hdr = struct.pack(">BHHHB", 0x0D, 0, 0, 512, 0)
    old_page_data = leaf_hdr.ljust(page_size, b"\x00")
    frame = struct.pack(">I", page_id) + old_page_data + struct.pack(">I", 0)

    journal_bytes = j_hdr + frame

    # Base db data: page 1 (100-byte db header + leaf hdr), page 2 (leaf with 1 cell)
    db_hdr = b"SQLite format 3\x00" + struct.pack(">H", page_size) + b"\x00" * 82
    base_page1 = db_hdr.ljust(page_size, b"\x00")
    base_page2 = old_page_data  # identical for now

    engine = JournalDiffEngine(base_page1 + base_page2, journal_bytes)
    assert engine.journal_header is not None
    assert engine.journal_header.page_count == 1
    mutations = engine.compute_timeline_diff()
    # Since pages are identical, 0 mutations
    assert len(mutations) == 0
