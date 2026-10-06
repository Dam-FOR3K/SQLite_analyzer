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
from sqlite_carver.core.integrity import compute_record_evidence_hash
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
class IndexSchema:
    name: str
    table_name: str
    root_page: int
    sql: str
    indexed_columns: List[str] = field(default_factory=list)

    @classmethod
    def from_sql(cls, name: str, tbl_name: str, root_page: int, sql: str) -> "IndexSchema":
        cols = []
        if sql:
            m = re.search(r"\((.*?)\)", sql, re.DOTALL)
            if m:
                raw_cols = [c.strip().strip('"`[]') for c in m.group(1).split(",") if c.strip()]
                for rc in raw_cols:
                    col = rc.split()[0].strip('"`[]')
                    cols.append(col)
        return cls(name=name, table_name=tbl_name, root_page=root_page, sql=sql, indexed_columns=cols)


@dataclass
class TableSchema:
    name: str
    root_page: int
    sql: str
    columns: List[ColumnDef] = field(default_factory=list)
    pk_col_idx: Optional[int] = None
    is_without_rowid: bool = False
    is_virtual: bool = False
    virtual_module: str = ""

    @classmethod
    def from_sql(cls, name: str, root_page: int, sql: str) -> "TableSchema":
        columns: List[ColumnDef] = []
        if not sql:
            return cls(name=name, root_page=root_page, sql="", columns=[])

        is_without_rowid = bool(re.search(r"\bWITHOUT\s+ROWID\b", sql, re.IGNORECASE))
        is_virtual = bool(re.search(r"\bVIRTUAL\s+TABLE\b", sql, re.IGNORECASE))
        virtual_module = ""
        if is_virtual:
            vm = re.search(r"\bUSING\s+([a-zA-Z0-9_]+)", sql, re.IGNORECASE)
            if vm:
                virtual_module = vm.group(1).lower()

        # Extract table name and column definition body
        m = re.match(
            r"^\s*CREATE\s+(?:TEMPORARY\s+|TEMP\s+)?(?:VIRTUAL\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?",
            sql,
            re.IGNORECASE,
        )
        pos = m.end() if m else 0
        while pos < len(sql) and sql[pos].isspace():
            pos += 1

        parsed_tbl_name = name
        if pos < len(sql):
            first_ch = sql[pos]
            if first_ch in ("'", '"', "`"):
                q = first_ch
                pos += 1
                name_chars = []
                while pos < len(sql):
                    if sql[pos] == q:
                        if pos + 1 < len(sql) and sql[pos + 1] == q:
                            name_chars.append(q)
                            pos += 2
                        else:
                            pos += 1
                            break
                    else:
                        name_chars.append(sql[pos])
                        pos += 1
                parsed_tbl_name = "".join(name_chars)
            elif first_ch == "[":
                pos += 1
                name_chars = []
                while pos < len(sql):
                    if sql[pos] == "]":
                        pos += 1
                        break
                    name_chars.append(sql[pos])
                    pos += 1
                parsed_tbl_name = "".join(name_chars)
            else:
                name_chars = []
                while pos < len(sql) and not sql[pos].isspace() and sql[pos] != "(":
                    name_chars.append(sql[pos])
                    pos += 1
                parsed_tbl_name = "".join(name_chars)

        final_name = name if (name is not None and name != "") else parsed_tbl_name

        open_paren = sql.find("(", pos)
        close_paren = sql.rfind(")")
        pk_idx: Optional[int] = None

        if open_paren != -1 and close_paren > open_paren:
            body = sql[open_paren + 1 : close_paren]

            # Tokenize column definitions tracking quotes, brackets, and nested parens
            col_defs: List[str] = []
            cur: List[str] = []
            in_quote: Optional[str] = None
            depth = 0
            i = 0
            while i < len(body):
                ch = body[i]
                if in_quote:
                    cur.append(ch)
                    if in_quote == "[" and ch == "]":
                        in_quote = None
                    elif ch == in_quote:
                        if i + 1 < len(body) and body[i + 1] == in_quote:
                            cur.append(body[i + 1])
                            i += 1
                        else:
                            in_quote = None
                else:
                    if ch in ('"', "'", "`"):
                        in_quote = ch
                        cur.append(ch)
                    elif ch == "[":
                        in_quote = "["
                        cur.append(ch)
                    elif ch == "(":
                        depth += 1
                        cur.append(ch)
                    elif ch == ")":
                        depth = max(0, depth - 1)
                        cur.append(ch)
                    elif ch == "," and depth == 0:
                        col_defs.append("".join(cur).strip())
                        cur = []
                        i += 1
                        continue
                    else:
                        cur.append(ch)
                i += 1
            if cur:
                col_defs.append("".join(cur).strip())

            for c in col_defs:
                c = c.strip()
                if not c:
                    continue
                upper = c.upper()
                if upper.startswith(("PRIMARY KEY", "FOREIGN KEY", "UNIQUE", "CHECK", "CONSTRAINT")):
                    continue

                col_name = ""
                rest = ""
                if c[0] in ('"', "'", "`"):
                    q = c[0]
                    end = c.find(q, 1)
                    while end != -1 and end + 1 < len(c) and c[end + 1] == q:
                        end = c.find(q, end + 2)
                    if end != -1:
                        col_name = c[1:end].replace(q + q, q)
                        rest = c[end + 1 :].strip()
                    else:
                        col_name = c[1:].strip()
                elif c[0] == "[":
                    end = c.find("]", 1)
                    if end != -1:
                        col_name = c[1:end]
                        rest = c[end + 1 :].strip()
                    else:
                        col_name = c[1:].strip()
                else:
                    parts = c.split(None, 1)
                    col_name = parts[0]
                    rest = parts[1] if len(parts) > 1 else ""

                rest_upper = rest.upper()
                if "INT" in rest_upper:
                    affinity = "INTEGER"
                elif any(k in rest_upper for k in ("CHAR", "TEXT", "CLOB")):
                    affinity = "TEXT"
                elif any(k in rest_upper for k in ("REAL", "FLOA", "DOUB")):
                    affinity = "REAL"
                elif "BLOB" in rest_upper or not rest_upper:
                    affinity = "BLOB" if "BLOB" in rest_upper else "NONE"
                else:
                    affinity = "NUMERIC"

                if "INTEGER" in rest_upper and "PRIMARY KEY" in rest_upper and pk_idx is None:
                    pk_idx = len(columns)

                columns.append(ColumnDef(name=col_name, affinity=affinity))

        if final_name == "sqlite_sequence" and (not columns or len(columns) == 2):
            columns = [ColumnDef(name="name", affinity="TEXT"), ColumnDef(name="seq", affinity="INTEGER")]

        return cls(
            name=final_name,
            root_page=root_page,
            sql=sql,
            columns=columns,
            pk_col_idx=pk_idx,
            is_without_rowid=is_without_rowid,
            is_virtual=is_virtual,
            virtual_module=virtual_module,
        )


def unpack_rtree_leaf_node(
    data: bytes | memoryview,
    schema: TableSchema,
    page_id: int,
    cell_offset: int,
    nodeno: Optional[int] = None,
) -> List["CarvedRecord"]:
    """
    Unpacks leaf nodes of an SQLite R-Tree virtual table (depth == 0).
    Header (4 bytes): uint16 depth, uint16 n_entries.
    Each leaf entry: int64 rowid (8 bytes), followed by 2*D float32 coordinates (4 bytes each).
    """
    if len(data) < 4:
        return []
    depth, n_entries = struct.unpack(">HH", data[:4])
    if depth != 0 or n_entries == 0:
        return []

    cols = [c.name for c in schema.columns] if schema.columns else ["id", "minX", "maxX", "minY", "maxY"]
    coord_count = max(2, len(cols) - 1)
    entry_sz = 8 + 4 * coord_count
    if 4 + n_entries * entry_sz > len(data):
        return []

    col_types = ["INTEGER"] + ["REAL"] * coord_count
    records: List["CarvedRecord"] = []
    for i in range(n_entries):
        off = 4 + i * entry_sz
        rowid = struct.unpack(">q", data[off : off + 8])[0]
        coords = []
        for c_idx in range(coord_count):
            c_off = off + 8 + c_idx * 4
            val = struct.unpack(">f", data[c_off : c_off + 4])[0]
            coords.append(round(val, 6))

        entry_offset = cell_offset + off
        records.append(
            CarvedRecord(
                page_id=page_id,
                offset_in_page=entry_offset,
                source="active",
                confidence=1.0,
                matched_table=schema.name,
                rowid=rowid,
                values=[rowid] + coords,
                column_names=cols[: len(coords) + 1],
                column_types=col_types[: len(coords) + 1],
                serial_types=[len(struct.pack(">q", rowid)) * 2 + 1] + [7] * coord_count,
                raw_payload=bytes(data[off : off + entry_sz]),
                is_partial=False,
                details=f"Virtual table R-Tree leaf record from node {nodeno or 'blob'}",
            )
        )
    return records


@dataclass
class CarvedRecord:
    page_id: int
    offset_in_page: int
    source: str  # 'active', 'freeblock', 'slack', 'unallocated', 'freelist', 'raw_scan', 'index_active', etc.
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
    foreign_keys: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    evidence_hash: str = ""
    is_mutation: bool = False
    mutation_diff: Dict[str, Any] = field(default_factory=dict)


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
        if st in (10, 11) or st > 65536 or serial_type_length(st) > 65536:
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
                    # In incomplete/truncated records, only allow truncated TEXT if printable and within reasonable bounds.
                    # Never accept truncated BLOBs when total_len > available as they absorb buffer noise.
                    if tname.startswith("TRUNCATED_TEXT") and isinstance(val, bytes) and 2 <= len(val) <= 2048:
                        try:
                            val = val.decode(encoding, errors="replace")
                            tname = "TEXT (truncated)"
                        except Exception:
                            valid = False
                            break
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
        # Prioritize candidates with fully satisfied columns (no truncation), then column count, then payload coverage
        return max(
            candidates,
            key=lambda r: (
                not any("truncated" in t.lower() for t in r.column_types),
                len(r.values),
                len(r.raw_payload),
            ),
        )

    return None


class SQLiteCarver:
    """
    Forensic carver for SQLite databases.
    """

    def __init__(self, raw_data: bytes | memoryview, user_schemas: Optional[List[TableSchema]] = None):
        self.parser = DatabaseParser(raw_data)
        self.schemas: Dict[str, TableSchema] = {}
        self.index_schemas: Dict[str, IndexSchema] = {}
        self.index_root_map: Dict[int, IndexSchema] = {}
        self.table_root_map: Dict[int, TableSchema] = {}
        self.virtual_schemas: Dict[str, TableSchema] = {}
        self.recovered_schemas: Dict[str, TableSchema] = {}
        if user_schemas:
            for s in user_schemas:
                self.schemas[s.name] = s
        else:
            self._load_schemas_from_db()

    def close(self) -> None:
        """Release underlying parser views."""
        if hasattr(self, "parser") and self.parser is not None:
            self.parser.close()

    def __enter__(self) -> "SQLiteCarver":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _load_schemas_from_db(self) -> None:
        """Loads schemas from the sqlite_schema / sqlite_master table (starting on page 1)."""
        if not self.parser.header:
            return

        leaf_pages = self.parser.get_table_leaf_pages(1)
        if not leaf_pages:
            leaf_pages = [1]

        for pid in leaf_pages:
            active_cells = self.parser.get_active_cells(pid)
            for cell in active_cells:
                if not cell.record or len(cell.record.values) < 5:
                    continue
                # sqlite_schema layout: (type, name, tbl_name, rootpage, sql)
                obj_type = cell.record.values[0]
                obj_name = cell.record.values[1]
                tbl_name = cell.record.values[2]
                root_page = cell.record.values[3]
                sql = cell.record.values[4]

                try:
                    rpage = int(root_page) if root_page is not None else 0
                except (ValueError, TypeError):
                    rpage = 0

                if obj_type == "table" and (obj_name is not None) and isinstance(sql, str):
                    schema = TableSchema.from_sql(str(obj_name), rpage, sql)
                    self.schemas[schema.name] = schema
                    if schema.is_virtual:
                        self.virtual_schemas[schema.name] = schema
                    if rpage > 0:
                        self.table_root_map[rpage] = schema
                        # If table B-tree spans multiple pages, map its leaf pages too
                        tbl_leaves = self.parser.get_table_leaf_pages(rpage)
                        for lp in tbl_leaves:
                            self.table_root_map[lp] = schema
                elif obj_type == "index" and (obj_name is not None) and isinstance(sql, str):
                    idx_schema = IndexSchema.from_sql(str(obj_name), str(tbl_name), rpage, sql)
                    self.index_schemas[str(obj_name)] = idx_schema
                    if rpage > 0:
                        self.index_root_map[rpage] = idx_schema
                        # If index B-tree spans multiple pages, map its leaf pages too
                        idx_leaves = self.parser.get_table_leaf_pages(rpage)
                        for lp in idx_leaves:
                            self.index_root_map[lp] = idx_schema

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

                max_cols = max(len(target_cols), len(serial_types))
                col_penalty = (col_count_diff / max_cols) * 0.25
                match_ratio = max(0.0, (score / max_cols) - col_penalty)
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

            # 1. Try cell format:
            # - Table Leaf Cell: [payload_size varint] [rowid varint] [record header...]
            # - Index Leaf Cell: [payload_size varint] [record header...] (rowid is inside payload)
            is_index_source = source.startswith("index_")
            p_res = safe_read_varint(data, idx)
            if p_res is not None:
                payload_size, p_len = p_res
                if 2 <= payload_size <= 100 * 1024 * 1024:
                    usable_sz = self.parser.usable_page_size if self.parser and self.parser.usable_page_size > 0 else 4096
                    local_size = calculate_local_payload_size(payload_size, usable_sz, is_index=is_index_source)
                    has_overflow = payload_size > local_size

                    full_payload = None
                    advance_len = 0
                    overflow_page = None

                    if is_index_source:
                        rowid = None
                        r_len = 0
                        body_start = idx + p_len
                        if not has_overflow:
                            if body_start + payload_size <= data_len:
                                full_payload = data[body_start : body_start + payload_size]
                                advance_len = p_len + payload_size
                        else:
                            if body_start + local_size + 4 <= data_len:
                                overflow_page = struct.unpack(">I", data[body_start + local_size : body_start + local_size + 4])[0]
                                advance_len = p_len + local_size + 4
                                if 1 <= overflow_page <= self.parser.total_pages:
                                    overflow_chunk = self.parser.reassemble_overflow_chain(
                                        overflow_page, payload_size - local_size
                                    )
                                    full_payload = bytes(data[body_start : body_start + local_size]) + overflow_chunk
                    else:
                        row_res = safe_read_varint(data, idx + p_len)
                        if row_res is not None:
                            rowid, r_len = row_res
                            body_start = idx + p_len + r_len
                            if not has_overflow:
                                if body_start + payload_size <= data_len:
                                    full_payload = data[body_start : body_start + payload_size]
                                    advance_len = p_len + r_len + payload_size
                            else:
                                if body_start + local_size + 4 <= data_len:
                                    overflow_page = struct.unpack(">I", data[body_start + local_size : body_start + local_size + 4])[0]
                                    advance_len = p_len + r_len + local_size + 4
                                    if 1 <= overflow_page <= self.parser.total_pages:
                                        overflow_chunk = self.parser.reassemble_overflow_chain(
                                            overflow_page, payload_size - local_size
                                        )
                                        full_payload = bytes(data[body_start : body_start + local_size]) + overflow_chunk

                    if full_payload is not None and len(full_payload) >= 2:
                        # Read record header size varint
                        h_res = safe_read_varint(full_payload, 0)
                        if h_res is not None:
                            h_size, h_len = h_res
                            if 2 <= h_size <= payload_size:
                                rec = decode_record_payload(
                                    full_payload,
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
                                                if overflow_page:
                                                    detail_msg += f" (overflow reassembled from page {overflow_page})"
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
                                                idx += max(1, advance_len)
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
                    adv_step = len(trunc_res.raw_payload) if trunc_res.raw_payload else trunc_res.header_size
                    adv_step = min(adv_step, data_len - idx)
                    idx += max(1, adv_step)
                    continue

            idx += 1

        return results

    def carve_page_data(
        self,
        page_bytes: bytes | memoryview,
        page_id: int = 1,
        is_page_1: bool = False,
        include_active: bool = True,
    ) -> List[CarvedRecord]:
        """
        Performs in-depth forensic carving directly on raw page bytes:
        - Active cells
        - Freeblocks (deleted cells in page freelist)
        - Unallocated space (gap between cell pointers and cell content area)
        - Cell Slack space (unreferenced gaps between active cell intervals)
        """
        page_mem = memoryview(page_bytes)
        hdr = self.parser.parse_page_header_from_bytes(page_mem, is_page_1=is_page_1)
        records: List[CarvedRecord] = []
        known_offsets: Set[int] = set()
        encoding = self.parser.header.encoding if (self.parser and self.parser.header) else "utf-8"

        # Track exact [start, end) intervals of occupied regions in the page
        occupied_intervals: List[Tuple[int, int]] = []
        is_index_page = hdr.page_type in (PageType.INDEX_LEAF, PageType.INDEX_INTERIOR)
        idx_schema = self.index_root_map.get(page_id)
        table_schema = self.table_root_map.get(page_id)

        # 1. Active Cells
        active_cells = self.parser.get_active_cells_from_bytes(page_mem, page_id=page_id, is_page_1=is_page_1)
        for c in active_cells:
            known_offsets.add(c.offset_in_page)
            cell_len = len(c.raw_payload) + 4  # Lower bound / estimated size
            occupied_intervals.append((c.offset_in_page, min(len(page_mem), c.offset_in_page + cell_len)))
            if include_active and c.record:
                if is_index_page:
                    if table_schema and table_schema.is_without_rowid:
                        tbl = table_schema.name
                        cols = [col.name for col in table_schema.columns]
                        records.append(
                            CarvedRecord(
                                page_id=page_id,
                                offset_in_page=c.offset_in_page,
                                source="active",
                                confidence=1.0,
                                matched_table=tbl,
                                rowid=None,
                                values=c.record.values,
                                column_names=cols[: len(c.record.values)],
                                column_types=c.record.column_types,
                                serial_types=c.record.serial_types,
                                raw_payload=c.raw_payload,
                                is_partial=c.record.is_partial,
                                details=f"Active cell from WITHOUT ROWID table '{tbl}'",
                            )
                        )
                    else:
                        tbl = idx_schema.table_name if idx_schema else None
                        rowid = (
                            c.record.values[-1]
                            if (c.record.values and isinstance(c.record.values[-1], int))
                            else c.rowid
                        )
                        if idx_schema:
                            cols = list(idx_schema.indexed_columns) + (
                                ["rowid"] if len(c.record.values) > len(idx_schema.indexed_columns) else []
                            )
                            detail = f"Active index cell from '{idx_schema.name}' ({idx_schema.table_name})"
                        else:
                            cols = [f"idx_col_{i}" for i in range(len(c.record.values))]
                            detail = "Active index cell"
                        records.append(
                            CarvedRecord(
                                page_id=page_id,
                                offset_in_page=c.offset_in_page,
                                source="index_active",
                                confidence=0.95,
                                matched_table=tbl,
                                rowid=rowid,
                                values=c.record.values,
                                column_names=cols,
                                column_types=c.record.column_types,
                                serial_types=c.record.serial_types,
                                raw_payload=c.raw_payload,
                                is_partial=c.record.is_partial,
                                details=detail,
                            )
                        )
                else:
                    if table_schema:
                        tbl = table_schema.name
                        conf = 1.0
                        cols = [col.name for col in table_schema.columns]
                        if table_schema.pk_col_idx is not None and table_schema.pk_col_idx < len(c.record.values):
                            if c.record.values[table_schema.pk_col_idx] is None and c.rowid is not None:
                                c.record.values[table_schema.pk_col_idx] = c.rowid
                    else:
                        tbl, conf, cols = self.match_schema(c.record.serial_types, c.record.values)
                        if tbl and tbl in self.schemas:
                            s = self.schemas[tbl]
                            if s.pk_col_idx is not None and s.pk_col_idx < len(c.record.values):
                                if c.record.values[s.pk_col_idx] is None and c.rowid is not None:
                                    c.record.values[s.pk_col_idx] = c.rowid

                    records.append(
                        CarvedRecord(
                            page_id=page_id,
                            offset_in_page=c.offset_in_page,
                            source="active",
                            confidence=conf,
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

                    # Virtual Table R-Tree Leaf Node unpacking
                    if table_schema and table_schema.name.endswith("_node"):
                        base_vname = table_schema.name[:-5]
                        v_schema = self.virtual_schemas.get(base_vname)
                        if v_schema and v_schema.virtual_module == "rtree":
                            if len(c.record.values) >= 2 and isinstance(c.record.values[1], (bytes, bytearray, memoryview)):
                                rtree_recs = unpack_rtree_leaf_node(
                                    c.record.values[1],
                                    v_schema,
                                    page_id=page_id,
                                    cell_offset=c.offset_in_page,
                                    nodeno=c.rowid or c.record.values[0],
                                )
                                records.extend(rtree_recs)

                    # Virtual Table FTS Content Mapping
                    if table_schema and table_schema.name.endswith("_content"):
                        base_vname = table_schema.name[:-8]
                        v_schema = self.virtual_schemas.get(base_vname)
                        if v_schema and v_schema.virtual_module.startswith("fts"):
                            fts_vals = [c.rowid] + [v for v in c.record.values[1:]]
                            fts_cols = ["docid"] + [col.name for col in v_schema.columns]
                            records.append(
                                CarvedRecord(
                                    page_id=page_id,
                                    offset_in_page=c.offset_in_page,
                                    source="active",
                                    confidence=1.0,
                                    matched_table=v_schema.name,
                                    rowid=c.rowid,
                                    values=fts_vals,
                                    column_names=fts_cols[: len(fts_vals)],
                                    column_types=["INTEGER"] + ["TEXT"] * (len(fts_vals) - 1),
                                    serial_types=c.record.serial_types,
                                    raw_payload=c.raw_payload,
                                    is_partial=c.record.is_partial,
                                    details=f"Virtual table FTS record mapped from shadow table '{table_schema.name}'",
                                )
                            )

        # 2. Freeblocks (First 4 bytes are next_offset and size pointers)
        fb_src = "index_freeblock" if is_index_page else "freeblock"
        freeblocks = self.parser.get_freeblocks_from_bytes(page_mem, is_page_1=is_page_1)
        for fb in freeblocks:
            known_offsets.add(fb.offset)
            occupied_intervals.append((fb.offset, min(len(page_mem), fb.offset + fb.size)))
            if len(fb.raw_bytes) > 4:
                fb_records = self.scan_bytes_for_records(
                    fb.raw_bytes[4:],
                    page_id=page_id,
                    base_offset=fb.offset + 4,
                    source=fb_src,
                    known_offsets=known_offsets,
                )
                if is_index_page and idx_schema:
                    for r in fb_records:
                        if not r.matched_table:
                            r.matched_table = idx_schema.table_name
                            r.column_names = list(idx_schema.indexed_columns) + (
                                ["rowid"] if len(r.values) > len(idx_schema.indexed_columns) else []
                            )
                            r.details = f"Carved from index '{idx_schema.name}' freeblock ({idx_schema.table_name})"
                        if len(r.values) > len(idx_schema.indexed_columns) and isinstance(r.values[-1], int):
                            r.rowid = r.values[-1]

                    # Fallback healer: if standard record scan found nothing because freeblock pointers
                    # (first 4 bytes) overwrote the record header, recover trailing payload & rowid
                    if not fb_records and len(fb.raw_bytes) >= 6:
                        fb_len = len(fb.raw_bytes)
                        for r_len in range(1, min(9, fb_len - 4)):
                            cand_off = fb_len - r_len
                            v_res = safe_read_varint(fb.raw_bytes, cand_off)
                            if v_res and v_res[1] == r_len:
                                cand_rowid = v_res[0]
                                payload_bytes = fb.raw_bytes[4:cand_off]
                                try:
                                    text_val = payload_bytes.decode(encoding)
                                    if len(text_val) > 0 and all(c.isprintable() or c in "\r\n\t" for c in text_val):
                                        records.append(
                                            CarvedRecord(
                                                page_id=page_id,
                                                offset_in_page=fb.offset + 4,
                                                source=fb_src,
                                                confidence=0.88,
                                                matched_table=idx_schema.table_name,
                                                rowid=cand_rowid,
                                                values=[text_val, cand_rowid],
                                                column_names=list(idx_schema.indexed_columns) + ["rowid"],
                                                column_types=["TEXT", "INTEGER"],
                                                serial_types=[(len(payload_bytes) * 2) + 13, 1],
                                                raw_payload=bytes(fb.raw_bytes[4:]),
                                                is_partial=False,
                                                details=f"Carved from index '{idx_schema.name}' freeblock with overwritten header ({idx_schema.table_name})",
                                            )
                                        )
                                        break
                                except Exception:
                                    pass
                records.extend(fb_records)

        # 3. Unallocated Space (Between end of cell pointer array and cell content start)
        unalloc_src = "index_unallocated" if is_index_page else "unallocated"
        ptr_array_end = hdr.header_offset + hdr.header_size + (hdr.cell_count * 2)
        cell_start = hdr.cell_content_start
        if ptr_array_end < cell_start and cell_start <= len(page_mem):
            unalloc_bytes = bytes(page_mem[ptr_array_end:cell_start])
            unalloc_recs = self.scan_bytes_for_records(
                unalloc_bytes,
                page_id=page_id,
                base_offset=ptr_array_end,
                source=unalloc_src,
                known_offsets=known_offsets,
            )
            if unalloc_recs:
                if is_index_page and idx_schema:
                    for r in unalloc_recs:
                        if not r.matched_table:
                            r.matched_table = idx_schema.table_name
                            r.column_names = list(idx_schema.indexed_columns) + (
                                ["rowid"] if len(r.values) > len(idx_schema.indexed_columns) else []
                            )
                            r.details = f"Carved from index '{idx_schema.name}' unallocated ({idx_schema.table_name})"
                        if len(r.values) > len(idx_schema.indexed_columns) and isinstance(r.values[-1], int):
                            r.rowid = r.values[-1]
                records.extend(unalloc_recs)
            elif any(b != 0 for b in unalloc_bytes):
                records.append(
                    CarvedRecord(
                        page_id=page_id,
                        offset_in_page=ptr_array_end,
                        source=unalloc_src,
                        confidence=0.1,
                        matched_table="[Raw Unallocated Fragment]",
                        rowid=None,
                        values=[f"0x{unalloc_bytes[:64].hex()}..."],
                        column_names=["raw_hex"],
                        column_types=["BLOB"],
                        serial_types=[len(unalloc_bytes) * 2 + 12],
                        raw_payload=unalloc_bytes,
                        is_partial=True,
                        details="Unstructured data (non-zero bytes) found in unallocated space gap.",
                    )
                )

        # 4. Gaps in cell content area (True Cell Slack)
        slack_src = "index_slack" if is_index_page else "slack"
        if hdr.page_type in (PageType.TABLE_LEAF, PageType.INDEX_LEAF) and occupied_intervals:
            # Merge overlapping or contiguous occupied intervals
            merged_intervals: List[Tuple[int, int]] = []
            for s, e in sorted(occupied_intervals, key=lambda x: (x[0], x[1])):
                if not merged_intervals or s > merged_intervals[-1][1]:
                    merged_intervals.append((s, e))
                else:
                    merged_intervals[-1] = (merged_intervals[-1][0], max(merged_intervals[-1][1], e))

            cur_pos = max(cell_start, hdr.header_offset + hdr.header_size + (hdr.cell_count * 2))
            for s, e in merged_intervals:
                if s > cur_pos and (s - cur_pos) >= 8:
                    gap_data = bytes(page_mem[cur_pos:s])
                    gap_recs = self.scan_bytes_for_records(
                        gap_data,
                        page_id=page_id,
                        base_offset=cur_pos,
                        source=slack_src,
                        known_offsets=known_offsets,
                    )
                    if gap_recs:
                        if is_index_page and idx_schema:
                            for r in gap_recs:
                                if not r.matched_table:
                                    r.matched_table = idx_schema.table_name
                                    r.column_names = list(idx_schema.indexed_columns) + (
                                        ["rowid"] if len(r.values) > len(idx_schema.indexed_columns) else []
                                    )
                                    r.details = f"Carved from index '{idx_schema.name}' slack ({idx_schema.table_name})"
                                if len(r.values) > len(idx_schema.indexed_columns) and isinstance(r.values[-1], int):
                                    r.rowid = r.values[-1]
                        records.extend(gap_recs)
                    elif any(b != 0 for b in gap_data):
                        records.append(
                            CarvedRecord(
                                page_id=page_id,
                                offset_in_page=cur_pos,
                                source=slack_src,
                                confidence=0.1,
                                matched_table="[Raw Slack Fragment]",
                                rowid=None,
                                values=[f"0x{gap_data[:64].hex()}..."],
                                column_names=["raw_hex"],
                                column_types=["BLOB"],
                                serial_types=[len(gap_data) * 2 + 12],
                                raw_payload=gap_data,
                                is_partial=True,
                                details="Unstructured data (non-zero bytes) found in cell slack gap.",
                            )
                        )
                cur_pos = max(cur_pos, e)

            # Trailing slack between last occupied interval and end of usable page
            res_sz = self.parser.reserved_space if self.parser else 0
            usable_end = len(page_mem) - res_sz
            if usable_end > cur_pos and (usable_end - cur_pos) >= 8:
                gap_data = bytes(page_mem[cur_pos:usable_end])
                gap_recs = self.scan_bytes_for_records(
                    gap_data,
                    page_id=page_id,
                    base_offset=cur_pos,
                    source=slack_src,
                    known_offsets=known_offsets,
                )
                if gap_recs:
                    if is_index_page and idx_schema:
                        for r in gap_recs:
                            if not r.matched_table:
                                r.matched_table = idx_schema.table_name
                                r.column_names = list(idx_schema.indexed_columns) + (
                                    ["rowid"] if len(r.values) > len(idx_schema.indexed_columns) else []
                                )
                                r.details = f"Carved from index '{idx_schema.name}' slack ({idx_schema.table_name})"
                            if len(r.values) > len(idx_schema.indexed_columns) and isinstance(r.values[-1], int):
                                r.rowid = r.values[-1]
                    records.extend(gap_recs)
                elif any(b != 0 for b in gap_data):
                    records.append(
                        CarvedRecord(
                            page_id=page_id,
                            offset_in_page=cur_pos,
                            source=slack_src,
                            confidence=0.1,
                            matched_table="[Raw Slack Fragment]",
                            rowid=None,
                            values=[f"0x{gap_data[:64].hex()}..."],
                            column_names=["raw_hex"],
                            column_types=["BLOB"],
                            serial_types=[len(gap_data) * 2 + 12],
                            raw_payload=gap_data,
                            is_partial=True,
                            details="Unstructured data (non-zero bytes) found in trailing cell slack gap.",
                        )
                    )

        # 5. Page Reserved Space (Steganography / Anti-Forensics at page boundary)
        res_sz = self.parser.reserved_space if self.parser else 0
        if res_sz > 0 and len(page_mem) >= res_sz:
            res_offset = len(page_mem) - res_sz
            res_bytes = bytes(page_mem[res_offset:])
            if any(b != 0 for b in res_bytes):
                # Try carving structured SQLite record first
                res_recs = self.scan_bytes_for_records(
                    res_bytes,
                    page_id=page_id,
                    base_offset=res_offset,
                    source="page_reserved_space",
                    known_offsets=known_offsets,
                )
                if res_recs:
                    records.extend(res_recs)
                else:
                    # Unstructured forensic payload / steganography / hidden text
                    text_clean = ""
                    try:
                        decoded = res_bytes.decode("utf-8", errors="replace")
                        printable = [c for c in decoded if c.isprintable()]
                        if len(printable) >= max(3, int(len(decoded) * 0.4)):
                            text_clean = "".join(c if c.isprintable() else " " for c in decoded).strip()
                    except Exception:
                        pass

                    display_val = text_clean if text_clean else f"0x{res_bytes.hex()}"
                    vals = [display_val]
                    cols = ["reserved_payload"]
                    col_types = ["TEXT" if text_clean else "BLOB"]
                    serial_type = len(display_val) * 2 + 13 if text_clean else len(res_bytes) * 2 + 12

                    records.append(
                        CarvedRecord(
                            page_id=page_id,
                            offset_in_page=res_offset,
                            source="page_reserved_space",
                            confidence=1.0,
                            matched_table="[Page Reserved Area]",
                            rowid=None,
                            values=vals,
                            column_names=cols,
                            column_types=col_types,
                            serial_types=[serial_type],
                            raw_payload=res_bytes,
                            is_partial=False,
                            details=f"Extracted {res_sz} bytes from page {page_id} reserved space (steganography / anti-forensics)",
                        )
                    )

        # Page 1 Dropped Table Schema Recovery:
        # If Page 1 contains unallocated or freeblock records matching sqlite_master format,
        # recover the dropped table schemas so orphaned freelist/unallocated records can be typed!
        if page_id == 1:
            for r in records:
                if r.values and len(r.values) >= 5 and r.values[0] == "table":
                    tname = str(r.values[1]) if r.values[1] is not None else ""
                    sql_str = str(r.values[4]) if r.values[4] is not None else ""
                    if tname and tname not in self.schemas and "CREATE TABLE" in sql_str.upper():
                        root_p = int(r.values[3]) if r.values[3] else 0
                        recov_schema = TableSchema.from_sql(tname, root_p, sql_str)
                        self.schemas[recov_schema.name] = recov_schema
                        self.recovered_schemas[recov_schema.name] = recov_schema
                        if root_p > 0:
                            self.table_root_map[root_p] = recov_schema
                            child_l = self.parser.get_table_leaf_pages(root_p)
                            for cl in child_l:
                                self.table_root_map[cl] = recov_schema

        # Cryptographic evidence hash for chain of custody
        for r in records:
            if not r.evidence_hash:
                r.evidence_hash = compute_record_evidence_hash(
                    r.page_id, r.offset_in_page, r.source, r.matched_table, r.rowid, r.values
                )

        return records

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
        return self.carve_page_data(
            page_bytes,
            page_id=page_id,
            is_page_1=(page_id == 1),
            include_active=include_active,
        )

    def resurrect_records_from_indices(self, records: List[CarvedRecord]) -> List[CarvedRecord]:
        """
        Cross-Index-to-Table Record Recovery (FQLite-style forensic enhancement).
        Examines carved index records (active, freeblocks, slack, unallocated).
        If an indexed rowid is missing from active table rows (i.e. deleted from table B-Tree,
        or table leaf was wiped/compacted), reconstructs a partial table record with high confidence.
        """
        active_table_rowids = {
            (r.matched_table, r.rowid)
            for r in records
            if r.source == "active" and r.matched_table and r.rowid is not None
        }

        resurrected: List[CarvedRecord] = []
        candidates_by_row: Dict[Tuple[str, int], List[CarvedRecord]] = {}

        for r in records:
            if not r.source.startswith("index_"):
                continue
            if not r.matched_table or r.rowid is None:
                continue
            if (r.matched_table, r.rowid) in active_table_rowids:
                continue

            candidates_by_row.setdefault((r.matched_table, r.rowid), []).append(r)

        for (tbl_name, rowid), idx_recs in candidates_by_row.items():
            tbl_schema = self.schemas.get(tbl_name)
            if not tbl_schema or not tbl_schema.columns:
                continue

            col_names = [c.name for c in tbl_schema.columns]
            col_types = [c.affinity for c in tbl_schema.columns]
            reconstructed_values: List[Any] = [None] * len(tbl_schema.columns)
            reconstructed_st: List[int] = [0] * len(tbl_schema.columns)
            recovered_cols_count = 0
            contributing_indices: List[str] = []

            # If table has an INTEGER PRIMARY KEY column, assign rowid directly
            if tbl_schema.pk_col_idx is not None and 0 <= tbl_schema.pk_col_idx < len(reconstructed_values):
                reconstructed_values[tbl_schema.pk_col_idx] = rowid
                reconstructed_st[tbl_schema.pk_col_idx] = 1
                recovered_cols_count += 1

            for ir in idx_recs:
                idx_schema = self.index_root_map.get(ir.page_id)
                idx_name = idx_schema.name if idx_schema else "index"
                contributing_indices.append(idx_name)

                for col_idx, col_name in enumerate(ir.column_names):
                    if col_name == "rowid":
                        continue
                    if col_name in col_names:
                        target_pos = col_names.index(col_name)
                        if col_idx < len(ir.values) and reconstructed_values[target_pos] is None:
                            reconstructed_values[target_pos] = ir.values[col_idx]
                            if col_idx < len(ir.serial_types):
                                reconstructed_st[target_pos] = ir.serial_types[col_idx]
                            recovered_cols_count += 1

            if recovered_cols_count > 0:
                is_partial = any(v is None for v in reconstructed_values)
                indices_str = ", ".join(sorted(set(contributing_indices)))
                primary_idx_rec = idx_recs[0]
                resurrected.append(
                    CarvedRecord(
                        page_id=primary_idx_rec.page_id,
                        offset_in_page=primary_idx_rec.offset_in_page,
                        source="resurrected_from_index",
                        confidence=0.92,
                        matched_table=tbl_name,
                        rowid=rowid,
                        values=reconstructed_values,
                        column_names=col_names,
                        column_types=col_types,
                        serial_types=reconstructed_st,
                        raw_payload=primary_idx_rec.raw_payload,
                        is_partial=is_partial,
                        details=f"Resurrected deleted table row from index ({indices_str}, rowid={rowid})",
                    )
                )

        return resurrected

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

        # Also carve EOF slack bytes (hidden or trailing data past logical database size)
        eof_slack = self.parser.get_eof_slack_bytes()
        if eof_slack and len(eof_slack) > 0:
            slack_recs = self.scan_bytes_for_records(
                eof_slack,
                page_id=total_pages + 1,
                base_offset=self.parser.logical_size,
                source="eof_slack",
                known_offsets=set(),
            )
            all_records.extend(slack_recs)

        # Re-match unmapped records if dropped table schemas were recovered from Page 1
        if self.recovered_schemas:
            for r in all_records:
                if r.matched_table is None:
                    tbl, conf, cols = self.match_schema(r.serial_types, r.values)
                    if tbl in self.recovered_schemas and conf >= 0.60:
                        r.matched_table = tbl
                        r.confidence = conf
                        r.column_names = cols
                        r.details += f" (recovered from dropped table '{tbl}')"

        # Resurrect deleted rows from surviving index entries (FQLite forensic enhancement)
        resurrected_recs = self.resurrect_records_from_indices(all_records)
        all_records.extend(resurrected_recs)

        for r in all_records:
            if not r.evidence_hash:
                r.evidence_hash = compute_record_evidence_hash(
                    r.page_id, r.offset_in_page, r.source, r.matched_table, r.rowid, r.values
                )

        from sqlite_carver.core.mutations import detect_record_mutations
        all_records, _ = detect_record_mutations(all_records, self.schemas)

        return all_records

    @classmethod
    def carve_raw_pages(
        cls,
        raw_data: bytes | memoryview,
        page_size: int = 4096,
        user_schemas: Optional[List[TableSchema]] = None,
        include_active: bool = True,
        workers: int = 1,
    ) -> List[CarvedRecord]:
        """
        Raw Page Hunter: scans an arbitrary memory dump, raw disk image, or unformatted binary slice
        for candidate SQLite B-tree pages and carves all active and deleted records.
        Supports multi-threaded parallel execution across chunks of pages via workers parameter.
        """
        buf = memoryview(raw_data)
        total_len = len(buf)
        if total_len < page_size:
            return []

        step = page_size
        num_blocks = total_len // step
        dummy_db_header = b"SQLite format 3\x00" + struct.pack(">H", page_size) + b"\x00" * 82

        def process_block_range(start_idx: int, end_idx: int) -> List[CarvedRecord]:
            local_carver = cls(dummy_db_header.ljust(page_size, b"\x00"), user_schemas=user_schemas)
            range_records: List[CarvedRecord] = []

            for i in range(start_idx, end_idx):
                block_offset = i * step
                block = buf[block_offset : block_offset + page_size]
                if len(block) < page_size:
                    break

                is_p1 = (block[:16] == b"SQLite format 3\x00")
                hdr_offset = 100 if is_p1 else 0

                ptype_byte = block[hdr_offset]
                if ptype_byte not in (0x02, 0x05, 0x0A, 0x0D):
                    continue

                try:
                    first_fb, cell_count, cell_content, frag = struct.unpack(
                        ">HHHB", block[hdr_offset + 1 : hdr_offset + 8]
                    )
                except Exception:
                    continue

                # Validate header sanity
                hdr_size = 12 if ptype_byte in (0x02, 0x05) else 8
                ptr_array_end = hdr_offset + hdr_size + (cell_count * 2)
                if ptr_array_end > page_size:
                    continue
                if cell_content != 0 and (cell_content < ptr_array_end or cell_content > page_size):
                    continue
                if first_fb != 0 and (first_fb < ptr_array_end or first_fb > page_size - 4):
                    continue

                page_id = i + 1
                recs = local_carver.carve_page_data(
                    block,
                    page_id=page_id,
                    is_page_1=is_p1,
                    include_active=include_active,
                )
                range_records.extend(recs)

            local_carver.close()
            return range_records

        all_records: List[CarvedRecord] = []
        actual_workers = max(1, workers)

        if actual_workers > 1 and num_blocks >= 16:
            import concurrent.futures
            chunk_size = max(1, (num_blocks + actual_workers - 1) // actual_workers)
            futures = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers) as executor:
                for w in range(actual_workers):
                    s_idx = w * chunk_size
                    e_idx = min(num_blocks, s_idx + chunk_size)
                    if s_idx < num_blocks:
                        futures.append(executor.submit(process_block_range, s_idx, e_idx))
                for fut in futures:
                    all_records.extend(fut.result())
        else:
            all_records = process_block_range(0, num_blocks)

        for r in all_records:
            if not r.evidence_hash:
                r.evidence_hash = compute_record_evidence_hash(
                    r.page_id, r.offset_in_page, r.source, r.matched_table, r.rowid, r.values
                )

        all_records.sort(key=lambda r: (r.page_id, r.offset_in_page))
        return all_records
