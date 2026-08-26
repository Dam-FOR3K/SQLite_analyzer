"""
SQLite WAL (Write-Ahead Log) and Rollback Journal Forensic Diff Engine.

Parses WAL headers, frame headers (salt, checksums, commit markers),
reconstructs transactional timelines, and computes granular row-level
mutations (Insert, Update with column diffs, Delete) across transactions.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlite_carver.core.carver import CarvedRecord, SQLiteCarver, TableSchema
from sqlite_carver.core.parser import DatabaseParser, PageHeader, PageType


class MutationType(enum.Enum):
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


@dataclass
class ColumnDiff:
    column_name: str
    old_value: Any
    new_value: Any


@dataclass
class RowMutation:
    mutation_type: MutationType
    frame_index: int
    page_id: int
    table_name: Optional[str]
    rowid: Optional[int]
    old_values: Optional[List[Any]] = None
    new_values: Optional[List[Any]] = None
    column_diffs: List[ColumnDiff] = field(default_factory=list)
    is_commit: bool = False
    details: str = ""


@dataclass
class WalHeader:
    magic: int
    format_version: int
    page_size: int
    checkpoint_seq: int
    salt1: int
    salt2: int
    checksum1: int
    checksum2: int
    is_valid: bool = True

    @classmethod
    def from_bytes(cls, data: bytes | memoryview) -> Optional["WalHeader"]:
        if len(data) < 32:
            return None
        magic, ver, psize, seq, s1, s2, c1, c2 = struct.unpack(">8I", data[:32])
        if magic not in (0x377F0682, 0x377F0683):
            return None
        return cls(
            magic=magic,
            format_version=ver,
            page_size=psize,
            checkpoint_seq=seq,
            salt1=s1,
            salt2=s2,
            checksum1=c1,
            checksum2=c2,
            is_valid=True,
        )


@dataclass
class WalFrame:
    frame_index: int
    page_id: int
    db_size_after_commit: int
    salt1: int
    salt2: int
    checksum1: int
    checksum2: int
    page_data: bytes
    is_commit: bool = False

    @classmethod
    def from_bytes(
        cls,
        frame_index: int,
        data: bytes | memoryview,
        page_size: int,
    ) -> Optional["WalFrame"]:
        if len(data) < 24 + page_size:
            return None
        page_id, commit_size, s1, s2, c1, c2 = struct.unpack(">6I", data[:24])
        page_data = bytes(data[24 : 24 + page_size])
        return cls(
            frame_index=frame_index,
            page_id=page_id,
            db_size_after_commit=commit_size,
            salt1=s1,
            salt2=s2,
            checksum1=c1,
            checksum2=c2,
            page_data=page_data,
            is_commit=(commit_size > 0),
        )


@dataclass
class JournalHeader:
    magic: bytes
    page_count: int
    nonce: int
    initial_db_size: int
    sector_size: int
    page_size: int

    @classmethod
    def from_bytes(cls, data: bytes | memoryview) -> Optional["JournalHeader"]:
        if len(data) < 28:
            return None
        magic = bytes(data[:8])
        if magic != b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
            return None
        pg_cnt, nonce, init_db, sector, psize = struct.unpack(">5I", data[8:28])
        return cls(
            magic=magic,
            page_count=pg_cnt,
            nonce=nonce,
            initial_db_size=init_db,
            sector_size=sector,
            page_size=psize if psize >= 512 else 4096,
        )


class WalDiffEngine:
    """
    Parses WAL frames and reconstructs row-level transaction timelines.
    """

    def __init__(
        self,
        base_db_data: bytes | memoryview,
        wal_data: bytes | memoryview,
        user_schemas: Optional[List[TableSchema]] = None,
    ):
        self.base_carver = SQLiteCarver(base_db_data, user_schemas=user_schemas)
        self.wal_data = memoryview(wal_data)
        self.wal_header = WalHeader.from_bytes(self.wal_data)
        self.page_size = (
            self.wal_header.page_size
            if self.wal_header
            else self.base_carver.parser.page_size
        )
        self.frames: List[WalFrame] = []
        self._parse_frames()

    def _parse_frames(self) -> None:
        """Iterates over all 24-byte headers + page payloads in WAL file."""
        if len(self.wal_data) < 32:
            return

        offset = 32  # Skip 32-byte WAL header
        frame_size = 24 + self.page_size
        frame_idx = 1

        while offset + frame_size <= len(self.wal_data):
            chunk = self.wal_data[offset : offset + frame_size]
            frame = WalFrame.from_bytes(frame_idx, chunk, self.page_size)
            if frame:
                self.frames.append(frame)
            offset += frame_size
            frame_idx += 1

    def compute_timeline_diff(self) -> List[RowMutation]:
        """
        Computes row mutations across WAL frames compared to base DB.
        """
        mutations: List[RowMutation] = []
        
        # Track active row states: (table_name, rowid) -> CarvedRecord
        # Base state:
        base_records = self.base_carver.carve_all(include_active=True)
        row_state: Dict[Tuple[Optional[str], Optional[int]], CarvedRecord] = {}
        for rec in base_records:
            if rec.source == "active" and rec.rowid is not None:
                key = (rec.matched_table, rec.rowid)
                row_state[key] = rec

        # Iterate through WAL frames sequentially
        for frame in self.frames:
            # Build a temporary parser for this single frame page
            # To parse page properly, if page_id == 1, frame page has 100-byte db header.
            frame_carver = SQLiteCarver(
                frame.page_data if frame.page_id == 1 else (b"\x00" * ((frame.page_id - 1) * self.page_size) + frame.page_data),
                user_schemas=list(self.base_carver.schemas.values()),
            )
            
            frame_records = frame_carver.carve_page(frame.page_id, include_active=True)
            active_frame_records = [r for r in frame_records if r.source == "active"]
            deleted_frame_records = [r for r in frame_records if r.source in ("freeblock", "slack", "unallocated")]

            current_frame_keys = set()

            for rec in active_frame_records:
                if rec.rowid is None:
                    continue
                key = (rec.matched_table, rec.rowid)
                current_frame_keys.add(key)

                if key not in row_state:
                    # New record inserted
                    mutations.append(
                        RowMutation(
                            mutation_type=MutationType.INSERT,
                            frame_index=frame.frame_index,
                            page_id=frame.page_id,
                            table_name=rec.matched_table,
                            rowid=rec.rowid,
                            new_values=rec.values,
                            is_commit=frame.is_commit,
                            details=f"Inserted into {rec.matched_table or 'Unknown Table'}",
                        )
                    )
                    row_state[key] = rec
                else:
                    # Check if updated
                    prev_rec = row_state[key]
                    if prev_rec.values != rec.values:
                        diffs = []
                        max_len = max(len(prev_rec.values), len(rec.values))
                        for i in range(max_len):
                            col_name = (
                                rec.column_names[i]
                                if i < len(rec.column_names)
                                else (prev_rec.column_names[i] if i < len(prev_rec.column_names) else f"col_{i}")
                            )
                            old_v = prev_rec.values[i] if i < len(prev_rec.values) else None
                            new_v = rec.values[i] if i < len(rec.values) else None
                            if old_v != new_v:
                                diffs.append(ColumnDiff(col_name, old_v, new_v))

                        mutations.append(
                            RowMutation(
                                mutation_type=MutationType.UPDATE,
                                frame_index=frame.frame_index,
                                page_id=frame.page_id,
                                table_name=rec.matched_table,
                                rowid=rec.rowid,
                                old_values=prev_rec.values,
                                new_values=rec.values,
                                column_diffs=diffs,
                                is_commit=frame.is_commit,
                                details=f"Updated in {rec.matched_table or 'Unknown Table'}",
                            )
                        )
                        row_state[key] = rec

            # Check for records deleted in this page
            # If a row was previously on this page_id in row_state, but no longer in active cells of this page
            for key, prev_rec in list(row_state.items()):
                if prev_rec.page_id == frame.page_id and key not in current_frame_keys:
                    # Check if found in freeblock / slack of this frame
                    deleted_match = next((dr for dr in deleted_frame_records if dr.rowid == key[1]), None)
                    mutations.append(
                        RowMutation(
                            mutation_type=MutationType.DELETE,
                            frame_index=frame.frame_index,
                            page_id=frame.page_id,
                            table_name=prev_rec.matched_table,
                            rowid=prev_rec.rowid,
                            old_values=prev_rec.values,
                            is_commit=frame.is_commit,
                            details="Row deleted (moved to page freeblock/slack)" if deleted_match else "Row deleted",
                        )
                    )
                    del row_state[key]

        return mutations
