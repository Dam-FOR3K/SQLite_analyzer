"""
sqlite_carver.core.shm
~~~~~~~~~~~~~~~~~~~~~~

Parser and forensic analyzer for SQLite WAL Shared Memory (.db-shm) index files.
Extracts transaction checkpoint sequence, reader locks, and page bounds.
"""

from dataclasses import dataclass, field
import struct
from typing import Any, Dict, List, Optional


@dataclass
class ShmHeader:
    version: int
    change_counter: int
    is_init: bool
    is_big_endian_checksum: bool
    page_size: int
    mx_frame: int
    n_page: int
    checkpoint_seq: int
    checkpoint_backfill: int
    checksum1: int
    checksum2: int
    is_valid: bool = True

    @classmethod
    def from_bytes(cls, data: bytes | memoryview) -> Optional["ShmHeader"]:
        if len(data) < 48:
            return None

        # Try big-endian first, then little-endian
        try:
            v_be = struct.unpack(">I", data[:4])[0]
            if v_be == 3007000:
                endian = ">"
            else:
                v_le = struct.unpack("<I", data[:4])[0]
                if v_le == 3007000:
                    endian = "<"
                else:
                    endian = "<"  # Default SQLite format
            
            ver, _, chg = struct.unpack(f"{endian}III", data[:12])
            is_init = bool(data[12])
            big_cksum = bool(data[13])
            psize = struct.unpack(f"{endian}H", data[14:16])[0]
            mx_frame, n_page = struct.unpack(f"{endian}II", data[16:24])
            a_frame0, a_frame1 = struct.unpack(f"{endian}II", data[24:32])
            a_trunc0, a_trunc1 = struct.unpack(f"{endian}II", data[32:40])
            c1, c2 = struct.unpack(f"{endian}II", data[40:48])

            if psize == 1:
                psize = 65536
            elif psize < 512 or (psize & (psize - 1)) != 0:
                psize = 4096

            return cls(
                version=ver,
                change_counter=chg,
                is_init=is_init,
                is_big_endian_checksum=big_cksum,
                page_size=psize,
                mx_frame=mx_frame,
                n_page=n_page,
                checkpoint_seq=a_frame0,
                checkpoint_backfill=a_frame1,
                checksum1=c1,
                checksum2=c2,
                is_valid=(ver == 3007000),
            )
        except Exception:
            return None


@dataclass
class ReaderLock:
    slot: int
    is_locked: bool
    read_mark: int


class ShmAnalyzer:
    """
    Forensic analyzer for SQLite .db-shm files.
    """

    def __init__(self, shm_bytes: bytes | memoryview):
        self.raw_data = memoryview(shm_bytes)
        self.size = len(shm_bytes)
        self.header: Optional[ShmHeader] = None
        self.reader_locks: List[ReaderLock] = []
        self._parse()

    def _parse(self) -> None:
        if self.size < 48:
            return

        self.header = ShmHeader.from_bytes(self.raw_data[:48])
        if not self.header or not self.header.is_valid:
            # Try second copy at offset 48
            if self.size >= 96:
                alt = ShmHeader.from_bytes(self.raw_data[48:96])
                if alt and alt.is_valid:
                    self.header = alt

        # Parse read marks at offset 96..128
        if self.size >= 128:
            # 8 read-marks (each 4 bytes integer)
            endian = "<" if self.header and not self.header.is_big_endian_checksum else ">"
            for slot in range(8):
                offset = 96 + slot * 4
                if offset + 4 <= self.size:
                    try:
                        mark = struct.unpack(f"{endian}I", self.raw_data[offset : offset + 4])[0]
                        is_locked = (mark != 0xFFFFFFFF and mark > 0)
                        self.reader_locks.append(
                            ReaderLock(slot=slot, is_locked=is_locked, read_mark=mark if mark != 0xFFFFFFFF else 0)
                        )
                    except Exception:
                        pass

    def to_dict(self) -> Dict[str, Any]:
        if not self.header:
            return {"has_shm": False, "size_bytes": self.size}

        active_readers = [l for l in self.reader_locks if l.is_locked]
        return {
            "has_shm": True,
            "size_bytes": self.size,
            "version": self.header.version,
            "change_counter": self.header.change_counter,
            "page_size": self.header.page_size,
            "max_wal_frame": self.header.mx_frame,
            "database_pages": self.header.n_page,
            "checkpoint_sequence": self.header.checkpoint_seq,
            "checkpoint_backfill": self.header.checkpoint_backfill,
            "active_readers_count": len(active_readers),
            "reader_locks": [
                {"slot": l.slot, "locked": l.is_locked, "read_mark": l.read_mark}
                for l in self.reader_locks
            ],
        }
