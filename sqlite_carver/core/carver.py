"""
SQLite Forensic Carver & Schema-Guided Deleted Record Recovery Engine.

Extracts deleted records, freelists, unallocated spaces, and cell slack bytes.
Includes schema-guided heuristics, table matching, and partial record reconstruction.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlite_carver.core.parser import (
    Cell,
    DatabaseHeader,
    DatabaseParser,
    DecodedRecord,
    PageHeader,
    PageType,
    calculate_local_payload_size,
    decode_record_payload,
)
from sqlite_carver.core.varint import (
    decode_serial_value,
    safe_read_varint,
    serial_type_length,
)


@dataclass
class ColumnDef:
    name: str
    affinity: str  # 'INTEGER', 'TEXT', 'BLOB', 'REAL', 'NUMERIC'


@dataclass
class TableSchema:
    name: str
    root_page: int
    sql: str
    columns: List[ColumnDef] = field(default_factory=list)

    @classmethod
    def from_sql(cls, name: str, root_page: int, sql: str) -> "TableSchema":
        columns: List[ColumnDef] = []
        if not sql:
            return cls(name=name, root_page=root_page, sql="", columns=[])

        # Parse column definitions between parentheses
        match = re.search(r"\((.*)\)", sql, re.DOTALL)
        if match:
            cols_str = match.group(1)
            # Split top-level commas (ignoring nested parens)
            raw_cols = []
            depth = 0
            cur = []
            for char in cols_str:
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                elif char == "," and depth == 0:
                    raw_cols.append("".join(cur).strip())
                    cur = []
                    continue
                cur.append(char)
            if cur:
                raw_cols.append("".join(cur).strip())

            for col in raw_cols:
                col_clean = col.strip()
                if not col_clean:
                    continue
                # Ignore table constraints like PRIMARY KEY (...), FOREIGN KEY, UNIQUE, CHECK
                upper = col_clean.upper()
                if upper.startswith(("PRIMARY KEY", "FOREIGN KEY", "UNIQUE", "CHECK", "CONSTRAINT")):
                    continue
                
                parts = col_clean.split(None, 2)
                col_name = parts[0].strip('"`[]')
                col_type = parts[1].upper() if len(parts) > 1 else "BLOB"

                affinity = "BLOB"
                if "INT" in col_type:
                    affinity = "INTEGER"
                elif "CHAR" in col_type or "TEXT" in col_type or "CLOB" in col_type:
                    affinity = "TEXT"
                elif "REAL" in col_type or "FLOA" in col_type or "DOUB" in col_type:
                    affinity = "REAL"
                elif "BLOB" in col_type or not col_type:
                    affinity = "BLOB"
                else:
                    affinity = "NUMERIC"

                columns.append(ColumnDef(name=col_name, affinity=affinity))

        return cls(name=name, root_page=root_page, sql=sql, columns=columns)


@dataclass
class CarvedRecord:
    page_id: int
    offset_in_page: int
    source: str  # 'active', 'freeblock', 'slack', 'unallocated', 'freelist', 'raw_scan'
    confidence: float
    matched_table: Optional[str]
    rowid: Optional[int]
    values: List[Any]
    column_names: List[str]
    column_types: List[str]
    serial_types: List[int]
    raw_payload: bytes
    is_partial: bool = False
    details: str = ""


def decode_truncated_record(
    data: bytes | memoryview,
    offset: int = 0,
    encoding: str = "utf-8",
    max_cols: int = 32,
) -> Optional[DecodedRecord]:
    """
    Recovers incomplete records when the record header size or rowid was overwritten
    (e.g. by freeblock linked-list pointers or page slack overwrite).
    Evaluates candidate serial type sequences to find the exact payload boundary fit.
    """
    data_len = len(data)
    available = data_len - offset
    if available < 2:
        return None

    candidates: List[DecodedRecord] = []
    serial_types: List[int] = []
    st_bytes = 0
    curr = offset

    for _ in range(max_cols):
        res = safe_read_varint(data, curr)
        if res is None:
            break
        st, slen = res
        if st in (10, 11) or st > 1000000:
            break
        # Ignore leading zeros / constants at start of truncated header (likely freeblock pointer or zero padding)
        if not serial_types and st in (0, 8, 9):
            break
        serial_types.append(st)
        st_bytes += slen
        curr += slen

        body_len = sum(serial_type_length(s) for s in serial_types)
        total_len = st_bytes + body_len
        min_prefix_len = st_bytes + sum(serial_type_length(s) for s in serial_types[:-1])
        if body_len > 0 and (total_len <= available or min_prefix_len < available):
            # Attempt decoding values
            values = []
            col_types = []
            val_offset = curr
            valid = True

            for s in serial_types:
                val, tname, consumed = decode_serial_value(s, data, val_offset, encoding=encoding)
                if tname.startswith("TRUNCATED_"):
                    if tname.startswith("TRUNCATED_TEXT") and isinstance(val, bytes) and len(val) >= 2:
                        try:
                            val = val.decode(encoding, errors="replace")
                            tname = "TEXT (truncated)"
                        except Exception:
                            valid = False
                            break
                    elif tname.startswith("TRUNCATED_BLOB") and isinstance(val, bytes) and len(val) > 0:
                        tname = "BLOB (truncated)"
                    else:
                        valid = False
                        break
                values.append(val)
                col_types.append(tname)
                val_offset += consumed

            if valid and len(values) >= 1:
                # Sanity: if TEXT columns are present, ensure ALL text columns are strictly printable
                has_text = any("TEXT" in t for t in col_types)
                if has_text:
                    all_text_valid = all(
                        all(c.isprintable() or c in "\r\n\t" for c in v)
                        for v in values
                        if isinstance(v, str) and len(v) > 0
                    )
                    if not all_text_valid:
                        continue

                rec = DecodedRecord(
                    header_size=st_bytes,
                    serial_types=list(serial_types),
                    values=values,
                    column_types=col_types,
                    raw_payload=bytes(data[offset:val_offset]),
                    is_partial=True,
                )
                candidates.append(rec)
                # If exact match to available buffer length, this is the optimal candidate
                if total_len == available:
                    return rec

    if candidates:
        # Pick candidate with most columns / highest payload coverage
        return max(candidates, key=lambda r: (len(r.values), len(r.raw_payload)))

    return None


class SQLiteCarver:
    """
    Forensic carver for SQLite databases.
    """

    def __init__(self, raw_data: bytes | memoryview, user_schemas: Optional[List[TableSchema]] = None):
        self.parser = DatabaseParser(raw_data)
        self.schemas: Dict[str, TableSchema] = {}
        if user_schemas:
            for s in user_schemas:
                self.schemas[s.name] = s
        else:
            self._load_schemas_from_db()

    def _load_schemas_from_db(self) -> None:
        """Loads schemas from the sqlite_schema / sqlite_master table on page 1."""
        if not self.parser.header:
            return
        
        active_cells = self.parser.get_active_cells(1)
        for cell in active_cells:
            if not cell.record or len(cell.record.values) < 5:
                continue
            # sqlite_schema layout: (type, name, tbl_name, rootpage, sql)
            obj_type = cell.record.values[0]
            obj_name = cell.record.values[1]
            root_page = cell.record.values[3]
            sql = cell.record.values[4]

            if obj_type == "table" and obj_name and isinstance(sql, str):
                try:
                    rpage = int(root_page) if root_page is not None else 0
                except (ValueError, TypeError):
                    rpage = 0
                schema = TableSchema.from_sql(str(obj_name), rpage, sql)
                self.schemas[str(obj_name)] = schema

    def match_schema(self, serial_types: List[int], values: List[Any]) -> Tuple[Optional[str], float, List[str]]:
        """
        Matches serial types and values against known table schemas.
        Returns: (matched_table_name, confidence, column_names)
        """
        # Calculate intrinsic baseline confidence for unmapped/orphaned records
        col_count = len(values)
        if col_count == 0:
            return None, 0.50, []
        
        # Intrinsic score: evaluate types sanity
        valid_types = sum(1 for st in serial_types if (0 <= st <= 11 or st >= 12))
        type_ratio = valid_types / col_count if col_count > 0 else 0.0
        
        # Text printability sanity
        text_cols = [v for v in values if isinstance(v, str) and len(v) > 0]
        text_ratio = 1.0
        if text_cols:
            printable_count = sum(1 for v in text_cols if all(c.isprintable() or c in "\r\n\t" for c in v))
            text_ratio = printable_count / len(text_cols)
        
        intrinsic_confidence = max(0.50, min(0.75, 0.50 + (0.15 * type_ratio) + (0.10 * text_ratio)))

        if not self.schemas:
            # Generate generic column names with dynamic intrinsic confidence
            return None, round(intrinsic_confidence, 2), [f"col_{i}" for i in range(len(values))]

        best_match = None
        best_score = 0.0
        best_col_names = [f"col_{i}" for i in range(len(values))]

        for tbl_name, schema in self.schemas.items():
            if not schema.columns:
                continue
            
            # Try full schema or schema omitting ROWID alias (first INTEGER column)
            candidate_col_lists = [schema.columns]
            if len(schema.columns) > 1 and schema.columns[0].affinity == "INTEGER":
                candidate_col_lists.append(schema.columns[1:])

            for target_cols in candidate_col_lists:
                col_count_diff = abs(len(target_cols) - len(serial_types))
                if col_count_diff > max(2, len(target_cols) // 2):
                    continue

                score = 0.0
                total_checks = min(len(target_cols), len(serial_types))
                if total_checks == 0:
                    continue

                for i in range(total_checks):
                    col_def = target_cols[i]
                    st = serial_types[i]
                    
                    # Check type affinity
                    if col_def.affinity == "INTEGER" and (1 <= st <= 6 or st in (8, 9)):
                        score += 1.0
                    elif col_def.affinity == "TEXT" and st >= 13 and (st % 2 == 1):
                        score += 1.0
                    elif col_def.affinity == "REAL" and st == 7:
                        score += 1.0
                    elif col_def.affinity == "BLOB" and st >= 12 and (st % 2 == 0):
                        score += 1.0
                    elif col_def.affinity == "NONE" or col_def.affinity == "":
                        score += 0.5
                    elif st == 0:  # NULL is allowed for any affinity
                        score += 0.8

                match_ratio = score / len(target_cols)
                if match_ratio > best_score:
                    best_score = match_ratio
                    best_match = tbl_name
                    # Build matched column names
                    col_names = []
                    for i in range(len(values)):
                        if i < len(target_cols):
                            col_names.append(target_cols[i].name)
                        else:
                            col_names.append(f"extra_col_{i}")
                    best_col_names = col_names

        if best_score >= 0.60:
            return best_match, min(1.0, 0.60 + best_score * 0.40), best_col_names
        
        return None, round(intrinsic_confidence, 2), [f"col_{i}" for i in range(len(values))]

    def scan_bytes_for_records(
        self,
        data: bytes | memoryview,
        page_id: int,
        base_offset: int,
        source: str,
        known_offsets: Set[int],
    ) -> List[CarvedRecord]:
        """
        High-performance sliding-window scanner to discover SQLite records in arbitrary byte chunks.
        Includes fast zero-skipping and exact body range advancing to prevent ghost overlaps.
        """
        results: List[CarvedRecord] = []
        data_len = len(data)
        if data_len < 3:
            return results

        encoding = self.parser.header.encoding if self.parser.header else "utf-8"
        idx = 0

        while idx < data_len - 2:
            # Optimization: Fast-skip runs of consecutive zero bytes (padding)
            if data[idx] == 0:
                zero_start = idx
                while idx < data_len and data[idx] == 0:
                    idx += 1
                if idx - zero_start > 1:
                    continue
                # If only single zero, revert to test potential single-byte NULL / varint
                idx = zero_start

            # 1. Try cell format: [payload_size varint] [rowid varint] [record header...]
            # Note: genuine cells require header_size varint >= 2 and header_size <= payload_size
            p_res = safe_read_varint(data, idx)
            if p_res is not None:
                payload_size, p_len = p_res
                if 2 <= payload_size <= self.parser.page_size * 2:
                    row_res = safe_read_varint(data, idx + p_len)
                    if row_res is not None:
                        rowid, r_len = row_res
                        body_start = idx + p_len + r_len
                        if body_start + 2 <= data_len:
                            # Read record header size varint
                            h_res = safe_read_varint(data, body_start)
                            if h_res is not None:
                                h_size, h_len = h_res
                                if 2 <= h_size <= payload_size and body_start + payload_size <= data_len:
                                    rec = decode_record_payload(
                                        data[body_start : body_start + payload_size],
                                        encoding=encoding,
                                        allow_partial=False,
                                    )
                                    if rec and len(rec.values) > 0 and rec.header_size == h_size:
                                        # Validate exact SQLite invariant: payload_size == header_size + body_len
                                        expected_body_len = sum(serial_type_length(st) for st in rec.serial_types)
                                        if expected_body_len + rec.header_size == payload_size:
                                            # Validate serial types sanity & text printability
                                            valid_st = all(0 <= st <= 11 or st >= 12 for st in rec.serial_types)
                                            text_ok = all(
                                                all(c.isprintable() or c in "\r\n\t" for c in v)
                                                for v in rec.values
                                                if isinstance(v, str) and len(v) > 0
                                            )
                                            if valid_st and text_ok:
                                                tbl, conf, cols = self.match_schema(rec.serial_types, rec.values)
                                                abs_offset = base_offset + idx
                                                if abs_offset not in known_offsets:
                                                    known_offsets.add(abs_offset)
                                                    detail_msg = f"Cell carved from {source}"
                                                    if not tbl:
                                                        detail_msg += " (unmapped schema)"
                                                    results.append(
                                                        CarvedRecord(
                                                            page_id=page_id,
                                                            offset_in_page=abs_offset,
                                                            source=source,
                                                            confidence=conf,
                                                            matched_table=tbl,
                                                            rowid=rowid,
                                                            values=rec.values,
                                                            column_names=cols,
                                                            column_types=rec.column_types,
                                                            serial_types=rec.serial_types,
                                                            raw_payload=rec.raw_payload,
                                                            is_partial=rec.is_partial,
                                                            details=detail_msg,
                                                        )
                                                    )
                                                    idx += max(1, p_len + r_len + payload_size)
                                                    continue

            # 2. Try raw record header directly: [header_size varint] [serial types...]
            rec_res = decode_record_payload(data[idx:], encoding=encoding, allow_partial=False)
            if rec_res and len(rec_res.values) >= 2 and rec_res.header_size >= 3:
                expected_body_len = sum(serial_type_length(st) for st in rec_res.serial_types)
                text_ok = all(
                    all(c.isprintable() or c in "\r\n\t" for c in v)
                    for v in rec_res.values
                    if isinstance(v, str) and len(v) > 0
                )
                not_truncated = not any(t.startswith("TRUNCATED_") for t in rec_res.column_types)
                if expected_body_len > 0 and (rec_res.header_size + expected_body_len <= data_len - idx) and not_truncated and text_ok:
                    tbl, conf, cols = self.match_schema(rec_res.serial_types, rec_res.values)
                    abs_offset = base_offset + idx
                    if abs_offset not in known_offsets:
                        known_offsets.add(abs_offset)
                        detail_msg = f"Raw record header carved from {source}"
                        if not tbl:
                            detail_msg += " (unmapped schema)"
                        results.append(
                            CarvedRecord(
                                page_id=page_id,
                                offset_in_page=abs_offset,
                                source=source,
                                confidence=conf * 0.9,
                                matched_table=tbl,
                                rowid=None,
                                values=rec_res.values,
                                column_names=cols,
                                column_types=rec_res.column_types,
                                serial_types=rec_res.serial_types,
                                raw_payload=rec_res.raw_payload,
                                is_partial=rec_res.is_partial,
                                details=detail_msg,
                            )
                        )
                        # Advance past entire record
                        idx += max(1, rec_res.header_size + expected_body_len)
                        continue

            # 3. Try truncated record header (damaged header in freeblock / slack)
            trunc_res = decode_truncated_record(data, offset=idx, encoding=encoding)
            if trunc_res and len(trunc_res.values) >= 2:
                tbl, conf, cols = self.match_schema(trunc_res.serial_types, trunc_res.values)
                abs_offset = base_offset + idx
                if abs_offset not in known_offsets:
                    known_offsets.add(abs_offset)
                    detail_msg = f"Incomplete record carved from {source}"
                    if not tbl:
                        detail_msg += " (unmapped schema)"
                    results.append(
                        CarvedRecord(
                            page_id=page_id,
                            offset_in_page=abs_offset,
                            source=source,
                            confidence=conf * 0.85,
                            matched_table=tbl,
                            rowid=None,
                            values=trunc_res.values,
                            column_names=cols,
                            column_types=trunc_res.column_types,
                            serial_types=trunc_res.serial_types,
                            raw_payload=trunc_res.raw_payload,
                            is_partial=True,
                            details=detail_msg,
                        )
                    )
                    idx += max(1, trunc_res.header_size + sum(serial_type_length(s) for s in trunc_res.serial_types))
                    continue

            idx += 1

        return results

    def carve_page(self, page_id: int, include_active: bool = True) -> List[CarvedRecord]:
        """
        Performs in-depth forensic carving on a single database page:
        - Active cells
        - Freeblocks (deleted cells in page freelist)
        - Unallocated space (gap between cell pointers and cell content area)
        - Cell Slack space (unreferenced gaps between active cell intervals)
        """
        page_bytes = self.parser.get_page_bytes(page_id)
        if page_bytes is None:
            return []

        hdr = self.parser.parse_page_header(page_id)
        records: List[CarvedRecord] = []
        known_offsets: Set[int] = set()

        # Track exact [start, end) intervals of occupied regions in the page
        occupied_intervals: List[Tuple[int, int]] = []

        # 1. Active Cells
        active_cells = self.parser.get_active_cells(page_id)
        for c in active_cells:
            known_offsets.add(c.offset_in_page)
            cell_len = len(c.raw_payload) + 4  # Lower bound / estimated size
            occupied_intervals.append((c.offset_in_page, min(len(page_bytes), c.offset_in_page + cell_len)))
            if include_active and c.record:
                tbl, conf, cols = self.match_schema(c.record.serial_types, c.record.values)
                records.append(
                    CarvedRecord(
                        page_id=page_id,
                        offset_in_page=c.offset_in_page,
                        source="active",
                        confidence=1.0,
                        matched_table=tbl,
                        rowid=c.rowid,
                        values=c.record.values,
                        column_names=cols,
                        column_types=c.record.column_types,
                        serial_types=c.record.serial_types,
                        raw_payload=c.raw_payload,
                        is_partial=c.record.is_partial,
                        details="Active B-tree cell",
                    )
                )

        # 2. Freeblocks (First 4 bytes are next_offset and size pointers)
        freeblocks = self.parser.get_freeblocks(page_id)
        for fb in freeblocks:
            known_offsets.add(fb.offset)
            occupied_intervals.append((fb.offset, min(len(page_bytes), fb.offset + fb.size)))
            if len(fb.raw_bytes) > 4:
                fb_records = self.scan_bytes_for_records(
                    fb.raw_bytes[4:],
                    page_id=page_id,
                    base_offset=fb.offset + 4,
                    source="freeblock",
                    known_offsets=known_offsets,
                )
                records.extend(fb_records)

        # 3. Unallocated Space (Between end of cell pointer array and cell content start)
        ptr_array_end = hdr.header_offset + hdr.header_size + (hdr.cell_count * 2)
        cell_start = hdr.cell_content_start
        if ptr_array_end < cell_start and cell_start <= len(page_bytes):
            unalloc_bytes = page_bytes[ptr_array_end:cell_start]
            unalloc_recs = self.scan_bytes_for_records(
                unalloc_bytes,
                page_id=page_id,
                base_offset=ptr_array_end,
                source="unallocated",
                known_offsets=known_offsets,
            )
            records.extend(unalloc_recs)

        # 4. Gaps in cell content area (True Cell Slack)
        # Accurately compute unreferenced gaps between occupied intervals and boundary areas
        if hdr.page_type in (PageType.TABLE_LEAF, PageType.INDEX_LEAF) and occupied_intervals:
            # Include cell_content_start boundary and page_size boundary
            all_boundaries = [(cell_start, cell_start)] + list(occupied_intervals) + [(len(page_bytes), len(page_bytes))]
            all_boundaries.sort(key=lambda x: x[0])
            
            for i in range(len(all_boundaries) - 1):
                cur_end = all_boundaries[i][1]
                next_start = all_boundaries[i + 1][0]
                
                # Check for genuine gap between consecutive occupied intervals
                if next_start > cur_end and (next_start - cur_end) >= 8:
                    gap_data = page_bytes[cur_end:next_start]
                    gap_recs = self.scan_bytes_for_records(
                        gap_data,
                        page_id=page_id,
                        base_offset=cur_end,
                        source="slack",
                        known_offsets=known_offsets,
                    )
                    records.extend(gap_recs)

        return records

    def carve_all(self, include_active: bool = True) -> List[CarvedRecord]:
        """Carves all pages in the database file including active, freelists, and unallocated pages."""
        all_records: List[CarvedRecord] = []
        total_pages = self.parser.total_pages

        for page_id in range(1, total_pages + 1):
            page_recs = self.carve_page(page_id, include_active=include_active)
            all_records.extend(page_recs)

        # Also carve freelist pages specifically if identified
        freelist_pages = set(self.parser.parse_freelist_pages())
        for fl_page in freelist_pages:
            page_bytes = self.parser.get_page_bytes(fl_page)
            if page_bytes:
                fl_recs = self.scan_bytes_for_records(
                    page_bytes,
                    page_id=fl_page,
                    base_offset=0,
                    source="freelist",
                    known_offsets=set(),
                )
                all_records.extend(fl_recs)

        return all_records
