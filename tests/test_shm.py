import struct
import pytest
from sqlite_carver.core.shm import ShmAnalyzer, ShmHeader


def test_shm_header_parse():
    # SQLite .db-shm header layout (48 bytes):
    # ver (3007000), unused (0), change_counter (123)
    # is_init (1), big_cksum (0), page_size (4096)
    # mx_frame (500), n_page (250), a_frame0 (10), a_frame1 (5)
    # a_trunc0 (0), a_trunc1 (0), cksum1 (0), cksum2 (0)
    data = bytearray(128)
    struct.pack_into("<III", data, 0, 3007000, 0, 123)
    data[12] = 1  # is_init
    data[13] = 0  # little-endian cksum
    struct.pack_into("<H", data, 14, 4096)
    struct.pack_into("<II", data, 16, 500, 250)
    struct.pack_into("<II", data, 24, 10, 5)
    struct.pack_into("<II", data, 32, 0, 0)
    struct.pack_into("<II", data, 40, 0, 0)

    # Set reader lock slot 0 to frame 450
    struct.pack_into("<I", data, 96, 450)
    # Slot 1 unlocked (0xFFFFFFFF)
    struct.pack_into("<I", data, 100, 0xFFFFFFFF)

    analyzer = ShmAnalyzer(bytes(data))
    assert analyzer.header is not None
    assert analyzer.header.is_valid is True
    assert analyzer.header.version == 3007000
    assert analyzer.header.change_counter == 123
    assert analyzer.header.page_size == 4096
    assert analyzer.header.mx_frame == 500
    assert analyzer.header.n_page == 250
    assert analyzer.header.checkpoint_seq == 10
    assert analyzer.header.checkpoint_backfill == 5

    # Reader locks
    assert len(analyzer.reader_locks) >= 2
    assert analyzer.reader_locks[0].is_locked is True
    assert analyzer.reader_locks[0].read_mark == 450
    assert analyzer.reader_locks[1].is_locked is False

    d = analyzer.to_dict()
    assert d["has_shm"] is True
    assert d["active_readers_count"] >= 1
    assert d["max_wal_frame"] == 500
