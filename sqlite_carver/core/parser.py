"""
SQLite Binary Format Parser.

Parses SQLite database headers, B-Tree pages (Leaf/Interior Table/Index),
cell pointer arrays, freeblocks, cell payloads, chained overflow pages,
and freelist trunk/leaf structures.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from sqlite_carver.core.varint import (
    VarintError,
    decode_serial_value,
    read_varint,
    safe_read_varint,
    serial_type_length,
)


class PageType(enum.IntEnum):
    INDEX_INTERIOR = 0x02
    TABLE_INTERIOR = 0x05
    INDEX_LEAF = 0x0A
    TABLE_LEAF = 0x0D
    UNKNOWN = 0x00


@dataclass
class DatabaseHeader:
    """Represents the 100-byte SQLite database header."""
    magic: bytes = b"SQLite format 3\x00"
    page_size: int = 4096
    write_version: int = 1  # 1 = legacy, 2 = WAL
    read_version: int = 1   # 1 = legacy, 2 = WAL
    reserved_space: int = 0
    max_payload_fraction: int = 64
    min_payload_fraction: int = 32
    leaf_payload_fraction: int = 32
    file_change_counter: int = 0
    in_header_db_size_pages: int = 0
    first_freelist_trunk_page: int = 0
    total_freelist_pages: int = 0
    schema_cookie: int = 0
    schema_format: int = 4
    default_page_cache_size: int = 0
    largest_root_btree_page: int = 0
    text_encoding_raw: int = 1  # 1 = UTF-8, 2 = UTF-16le, 3 = UTF-16be
    user_version: int = 0
    incremental_vacuum_flag: int = 0
    application_id: int = 0
    version_valid_for: int = 0
    sqlite_version_number: int = 0

    @property
    def encoding(self) -> str:
        if self.text_encoding_raw == 1:
            return "utf-8"
        elif self.text_encoding_raw == 2:
            return "utf-16-le"
        elif self.text_encoding_raw == 3:
            return "utf-16-be"
        return "utf-8"

    @property
    def usable_page_size(self) -> int:
        return self.page_size - self.reserved_space

    @classmethod
    def from_bytes(cls, data: bytes | memoryview) -> "DatabaseHeader":
        if len(data) < 100:
            raise ValueError(f"Header too short: {len(data)} bytes (expected 100)")
        
        magic = bytes(data[:16])
        raw_page_size = struct.unpack(">H", data[16:18])[0]
        page_size = 65536 if raw_page_size == 1 else (raw_page_size if raw_page_size >= 512 else 4096)
        
        write_ver, read_ver, reserved = struct.unpack(">BBB", data[18:21])
        max_pf, min_pf, leaf_pf = struct.unpack(">BBB", data[21:24])
        change_cnt, db_size = struct.unpack(">II", data[24:32])
        free_trunk, total_free = struct.unpack(">II", data[32:40])
        schema_cookie, schema_fmt = struct.unpack(">II", data[40:48])
        cache_size, largest_root = struct.unpack(">II", data[48:56])
        text_enc, user_ver = struct.unpack(">II", data[56:64])
        incr_vac, app_id = struct.unpack(">II", data[64:72])
        v_valid, sqlite_ver = struct.unpack(">II", data[92:100])

        return cls(
            magic=magic,
            page_size=page_size,
            write_version=write_ver,
            read_version=read_ver,
            reserved_space=reserved,
            max_payload_fraction=max_pf,
            min_payload_fraction=min_pf,
            leaf_payload_fraction=leaf_pf,
            file_change_counter=change_cnt,
            in_header_db_size_pages=db_size,
            first_freelist_trunk_page=free_trunk,
            total_freelist_pages=total_free,
            schema_cookie=schema_cookie,
            schema_format=schema_fmt,
            default_page_cache_size=cache_size,
            largest_root_btree_page=largest_root,
            text_encoding_raw=text_enc,
            user_version=user_ver,
            incremental_vacuum_flag=incr_vac,
            application_id=app_id,
            version_valid_for=v_valid,
            sqlite_version_number=sqlite_ver,
        )


@dataclass
class DecodedRecord:
    """Represents a decoded SQLite record payload (Record Format)."""
    header_size: int
    serial_types: List[int]
    values: List[Any]
    column_types: List[str]
    raw_payload: bytes
    is_partial: bool = False


@dataclass
class Cell:
    """Represents a B-tree cell or carved record."""
    page_id: int
    offset_in_page: int
    page_type: PageType
    payload_size: int
    rowid: Optional[int] = None
    left_child_page: Optional[int] = None
    overflow_page: Optional[int] = None
    raw_cell: bytes = b""
    raw_payload: bytes = b""
    record: Optional[DecodedRecord] = None
    source: str = "active"  # 'active', 'freeblock', 'slack', 'unallocated', 'wal'
    confidence: float = 1.0


@dataclass
class Freeblock:
    """Represents a linked freeblock on a B-tree page."""
    offset: int
    size: int
    next_offset: int
    raw_bytes: bytes


@dataclass
class PageHeader:
    """Header of a SQLite B-tree page."""
    page_type: PageType
    first_freeblock: int
    cell_count: int
    cell_content_offset: int  # 0 indicates 65536
    fragmented_free_bytes: int
    rightmost_pointer: Optional[int] = None
    header_offset: int = 0  # 100 on page 1, 0 on other pages
    header_size: int = 8    # 8 for leaf, 12 for interior

    @property
    def cell_content_start(self) -> int:
        return 65536 if self.cell_content_offset == 0 else self.cell_content_offset

    @classmethod
    def from_bytes(cls, page_data: bytes | memoryview, is_page_1: bool = False) -> "PageHeader":
        hdr_offset = 100 if is_page_1 else 0
        if len(page_data) < hdr_offset + 8:
            return cls(
                page_type=PageType.UNKNOWN,
                first_freeblock=0,
                cell_count=0,
                cell_content_offset=0,
                fragmented_free_bytes=0,
                header_offset=hdr_offset,
                header_size=8,
            )

        raw_type = page_data[hdr_offset]
        try:
            ptype = PageType(raw_type)
        except ValueError:
            ptype = PageType.UNKNOWN

        first_fb, cell_cnt, cell_content, frag = struct.unpack(
            ">HHHB", page_data[hdr_offset + 1 : hdr_offset + 8]
        )

        rightmost = None
        hdr_size = 8
        if ptype in (PageType.TABLE_INTERIOR, PageType.INDEX_INTERIOR):
            hdr_size = 12
            if len(page_data) >= hdr_offset + 12:
                rightmost = struct.unpack(">I", page_data[hdr_offset + 8 : hdr_offset + 12])[0]

        return cls(
            page_type=ptype,
            first_freeblock=first_fb,
            cell_count=cell_cnt,
            cell_content_offset=cell_content,
            fragmented_free_bytes=frag,
            rightmost_pointer=rightmost,
            header_offset=hdr_offset,
            header_size=hdr_size,
        )


def calculate_local_payload_size(payload_size: int, page_size: int, reserved_space: int = 0) -> int:
    """
    Computes local payload size stored on the page vs overflow pages.
    SQLite specification formulas:
    - U = page_size - reserved_space
    - max_local = U - 35
    - min_local = ((U - 12) * 32) // 255 - 23
    """
    u = page_size - reserved_space
    max_local = u - 35
    min_local = ((u - 12) * 32) // 255 - 23
    if payload_size <= max_local:
        return payload_size
    k = min_local + ((payload_size - min_local) % (u - 4))
    if k <= max_local:
        return k
    return min_local


def decode_record_payload(
    payload: bytes | memoryview,
    encoding: str = "utf-8",
    allow_partial: bool = True,
) -> Optional[DecodedRecord]:
    """
    Parses a SQLite record payload (Header size varint + serial types varints + values).
    Handles truncated and corrupt payloads gracefully when allow_partial is True.
    """
    payload_len = len(payload)
    if payload_len == 0:
        return None

    # Step 1: Read record header size
    header_res = safe_read_varint(payload, 0)
    if header_res is None:
        return None
    header_size, bytes_read = header_res

    if header_size < bytes_read or (not allow_partial and header_size > payload_len):
        return None

    # Clamp header size to available payload length if partial
    effective_header_size = min(header_size, payload_len)
    
    # Step 2: Read serial types within header
    serial_types: List[int] = []
    curr_offset = bytes_read
    while curr_offset < effective_header_size:
        st_res = safe_read_varint(payload, curr_offset)
        if st_res is None:
            break
        st_val, st_len = st_res
        serial_types.append(st_val)
        curr_offset += st_len

    if not allow_partial and curr_offset != header_size:
        return None

    if not serial_types:
        return None

    # Step 3: Decode values
    values: List[Any] = []
    col_types: List[str] = []
    body_offset = header_size  # Values start immediately after the full header
    
    for st in serial_types:
        if body_offset >= payload_len:
            if allow_partial:
                values.append(None)
                col_types.append(f"MISSING_{st}")
                continue
            else:
                break
        
        val, type_name, consumed = decode_serial_value(
            st, payload, body_offset, encoding=encoding
        )
        values.append(val)
        col_types.append(type_name)
        body_offset += consumed

    is_partial = (header_size > payload_len) or (body_offset > payload_len)
    return DecodedRecord(
        header_size=header_size,
        serial_types=serial_types,
        values=values,
        column_types=col_types,
        raw_payload=bytes(payload),
        is_partial=is_partial,
    )


class DatabaseParser:
    """
    Low-level SQLite parser for raw databases, pages, and overflow chains.
    """

    def __init__(self, raw_data: bytes | memoryview):
        self.data = memoryview(raw_data)
        self.size = len(raw_data)
        self.header = self._parse_header()
        self.page_size = self.header.page_size if self.header else 4096
        self.reserved_space = self.header.reserved_space if self.header else 0
        self.usable_page_size = self.page_size - self.reserved_space
        self.total_pages = self.size // self.page_size if self.page_size > 0 else 0

    def _parse_header(self) -> Optional[DatabaseHeader]:
        if self.size >= 100 and self.data[:16] == b"SQLite format 3\x00":
            try:
                return DatabaseHeader.from_bytes(self.data[:100])
            except Exception:
                return None
        return None

    def get_page_bytes(self, page_id: int) -> Optional[memoryview]:
        """Returns the memoryview slice for a 1-indexed page_id."""
        if page_id < 1 or self.page_size <= 0:
            return None
        start = (page_id - 1) * self.page_size
        end = start + self.page_size
        if start >= self.size:
            return None
        return self.data[start:min(end, self.size)]

    def parse_page_header(self, page_id: int) -> PageHeader:
        page_bytes = self.get_page_bytes(page_id)
        if page_bytes is None:
            return PageHeader(PageType.UNKNOWN, 0, 0, 0, 0)
        return PageHeader.from_bytes(page_bytes, is_page_1=(page_id == 1))

    def reassemble_overflow_chain(self, first_overflow_page: int, needed_bytes: int) -> bytes:
        """
        Reassembles chained payload bytes across overflow pages.
        Format of overflow page:
        - 4-byte big-endian pointer to next overflow page (0 if last)
        - Rest of usable page space is payload chunk.
        """
        collected = bytearray()
        curr_page_id = first_overflow_page
        visited = set()

        while curr_page_id > 0 and curr_page_id not in visited and len(collected) < needed_bytes:
            visited.add(curr_page_id)
            page_data = self.get_page_bytes(curr_page_id)
            if page_data is None or len(page_data) < 4:
                break

            next_page_id = struct.unpack(">I", page_data[:4])[0]
            usable_chunk = page_data[4:self.usable_page_size]
            remaining_needed = needed_bytes - len(collected)
            chunk_to_take = usable_chunk[:remaining_needed]
            collected.extend(chunk_to_take)

            curr_page_id = next_page_id

        return bytes(collected)

    def parse_cell(
        self,
        page_id: int,
        page_data: memoryview,
        page_header: PageHeader,
        cell_offset: int,
        source: str = "active",
    ) -> Optional[Cell]:
        """Parses a cell at cell_offset within page_data."""
        if cell_offset < 0 or cell_offset >= len(page_data):
            return None

        ptype = page_header.page_type
        encoding = self.header.encoding if self.header else "utf-8"

        try:
            if ptype == PageType.TABLE_LEAF:
                # Table Leaf cell:
                # [payload_size varint] [rowid varint] [initial payload] [overflow page id (optional 4 bytes)]
                p_res = safe_read_varint(page_data, cell_offset)
                if p_res is None:
                    return None
                payload_size, p_len = p_res

                row_res = safe_read_varint(page_data, cell_offset + p_len)
                if row_res is None:
                    return None
                rowid, row_len = row_res

                body_start = cell_offset + p_len + row_len
                local_size = calculate_local_payload_size(
                    payload_size, self.page_size, self.reserved_space
                )
                
                # Extract local payload
                local_payload = bytes(page_data[body_start : body_start + local_size])
                overflow_page = None
                
                if local_size < payload_size:
                    # Next 4 bytes after local payload is the overflow page pointer
                    of_offset = body_start + local_size
                    if of_offset + 4 <= len(page_data):
                        overflow_page = struct.unpack(">I", page_data[of_offset : of_offset + 4])[0]
                        overflow_data = self.reassemble_overflow_chain(
                            overflow_page, payload_size - local_size
                        )
                        full_payload = local_payload + overflow_data
                    else:
                        full_payload = local_payload
                else:
                    full_payload = local_payload

                record = decode_record_payload(full_payload, encoding=encoding)
                cell_total_len = p_len + row_len + local_size + (4 if overflow_page else 0)
                raw_cell = bytes(page_data[cell_offset : cell_offset + cell_total_len])

                return Cell(
                    page_id=page_id,
                    offset_in_page=cell_offset,
                    page_type=ptype,
                    payload_size=payload_size,
                    rowid=rowid,
                    overflow_page=overflow_page,
                    raw_cell=raw_cell,
                    raw_payload=full_payload,
                    record=record,
                    source=source,
                )

            elif ptype == PageType.TABLE_INTERIOR:
                # Table Interior cell: [4-byte left child pointer] [rowid varint]
                if cell_offset + 4 > len(page_data):
                    return None
                left_child = struct.unpack(">I", page_data[cell_offset : cell_offset + 4])[0]
                row_res = safe_read_varint(page_data, cell_offset + 4)
                if row_res is None:
                    return None
                rowid, row_len = row_res
                raw_cell = bytes(page_data[cell_offset : cell_offset + 4 + row_len])

                return Cell(
                    page_id=page_id,
                    offset_in_page=cell_offset,
                    page_type=ptype,
                    payload_size=0,
                    rowid=rowid,
                    left_child_page=left_child,
                    raw_cell=raw_cell,
                    source=source,
                )

            elif ptype in (PageType.INDEX_LEAF, PageType.INDEX_INTERIOR):
                # Index cells contain payload (and left child pointer if interior)
                curr = cell_offset
                left_child = None
                if ptype == PageType.INDEX_INTERIOR:
                    if curr + 4 > len(page_data):
                        return None
                    left_child = struct.unpack(">I", page_data[curr : curr + 4])[0]
                    curr += 4

                p_res = safe_read_varint(page_data, curr)
                if p_res is None:
                    return None
                payload_size, p_len = p_res
                curr += p_len

                local_payload = bytes(page_data[curr : curr + payload_size])
                record = decode_record_payload(local_payload, encoding=encoding)

                return Cell(
                    page_id=page_id,
                    offset_in_page=cell_offset,
                    page_type=ptype,
                    payload_size=payload_size,
                    left_child_page=left_child,
                    raw_cell=bytes(page_data[cell_offset : curr + len(local_payload)]),
                    raw_payload=local_payload,
                    record=record,
                    source=source,
                )

        except Exception:
            return None

        return None

    def get_freeblocks(self, page_id: int) -> List[Freeblock]:
        """Traverses the linked list of freeblocks on a page."""
        page_data = self.get_page_bytes(page_id)
        if page_data is None:
            return []

        hdr = self.parse_page_header(page_id)
        freeblocks: List[Freeblock] = []
        curr_offset = hdr.first_freeblock
        visited = set()

        while curr_offset > 0 and curr_offset not in visited and curr_offset + 4 <= len(page_data):
            visited.add(curr_offset)
            next_fb, fb_size = struct.unpack(">HH", page_data[curr_offset : curr_offset + 4])
            fb_size = max(fb_size, 4)
            raw = bytes(page_data[curr_offset : min(curr_offset + fb_size, len(page_data))])
            freeblocks.append(
                Freeblock(
                    offset=curr_offset,
                    size=fb_size,
                    next_offset=next_fb,
                    raw_bytes=raw,
                )
            )
            curr_offset = next_fb

        return freeblocks

    def get_active_cells(self, page_id: int) -> List[Cell]:
        """Extracts all active cells referenced in the cell pointer array."""
        page_data = self.get_page_bytes(page_id)
        if page_data is None:
            return []

        hdr = self.parse_page_header(page_id)
        if hdr.page_type == PageType.UNKNOWN or hdr.cell_count == 0:
            return []

        cells: List[Cell] = []
        ptr_start = hdr.header_offset + hdr.header_size
        
        for i in range(hdr.cell_count):
            ptr_offset = ptr_start + i * 2
            if ptr_offset + 2 > len(page_data):
                break
            cell_offset = struct.unpack(">H", page_data[ptr_offset : ptr_offset + 2])[0]
            cell = self.parse_cell(page_id, page_data, hdr, cell_offset, source="active")
            if cell:
                cells.append(cell)

        return cells

    def parse_freelist_pages(self) -> List[int]:
        """Traverses the database freelist trunk and leaf hierarchy."""
        if not self.header or self.header.first_freelist_trunk_page == 0:
            return []

        freelist_pages: List[int] = []
        curr_trunk = self.header.first_freelist_trunk_page
        visited_trunks = set()

        while curr_trunk > 0 and curr_trunk not in visited_trunks:
            visited_trunks.add(curr_trunk)
            freelist_pages.append(curr_trunk)
            page_data = self.get_page_bytes(curr_trunk)
            if page_data is None or len(page_data) < 8:
                break

            next_trunk, leaf_count = struct.unpack(">II", page_data[:8])
            # Leaf page pointers follow the 8-byte trunk header
            ptr_offset = 8
            for _ in range(leaf_count):
                if ptr_offset + 4 > len(page_data):
                    break
                leaf_page = struct.unpack(">I", page_data[ptr_offset : ptr_offset + 4])[0]
                if leaf_page > 0:
                    freelist_pages.append(leaf_page)
                ptr_offset += 4

            curr_trunk = next_trunk

        return freelist_pages
