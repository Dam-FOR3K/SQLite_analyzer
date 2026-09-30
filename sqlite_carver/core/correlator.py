"""
Forensic Entity Correlator for SQLite Databases.

Automatically detects foreign key relationships (both explicit via SQL REFERENCES
and conventional via `<entity>_id` naming patterns) and resolves identifiers
to human-readable values (e.g., resolving `handle_id: 3` -> `+16455048614`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlite_carver.core.carver import CarvedRecord, TableSchema


@dataclass
class FKLink:
    source_table: str
    source_column: str
    target_table: str
    target_column: str


@dataclass
class FKResolution:
    target_table: str
    target_column: str
    target_id: int
    display_value: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_table": self.target_table,
            "target_column": self.target_column,
            "target_id": self.target_id,
            "display_value": self.display_value,
        }


class EntityCorrelator:
    """
    Builds relationship indexes across SQLite tables to provide automatic
    contextual resolution for active and carved/deleted records.
    """

    DISPLAY_COLUMN_PRIORITY = [
        "display_name", "username", "name", "full_name", "title", "label",
        "phone", "email", "chat_identifier", "identifier", "filename",
        "guid", "id", "text", "body", "number"
    ]

    def __init__(self, schemas: Dict[str, TableSchema]):
        self.schemas = schemas
        self.table_names: Set[str] = {t.lower() for t in schemas.keys()}
        self.fk_links: List[FKLink] = self._discover_fk_links()
        self.entity_index: Dict[Tuple[str, int], str] = {}

    def _discover_fk_links(self) -> List[FKLink]:
        """Discovers both explicit and conventional FK relations."""
        links: List[FKLink] = []

        for tbl_name, schema in self.schemas.items():
            sql = schema.sql or ""

            # 1. Explicit SQL REFERENCES clauses: e.g. REFERENCES handle(ROWID) or REFERENCES other_table(id)
            ref_matches = re.finditer(
                r'FOREIGN\s+KEY\s*\(([`"\[]?(\w+)[`"\]]?)\)\s*REFERENCES\s+([`"\[]?(\w+)[`"\]]?)\s*(?:\(([`"\[]?(\w+)[`"\]]?)\))?',
                sql,
                re.IGNORECASE,
            )
            for m in ref_matches:
                src_col = m.group(2)
                tgt_tbl = m.group(4)
                tgt_col = m.group(6) or "ROWID"
                links.append(FKLink(tbl_name, src_col, tgt_tbl, tgt_col))

            # Inline REFERENCES: col_name INTEGER REFERENCES tgt_tbl(id)
            inline_matches = re.finditer(
                r'([`"\[]?(\w+)[`"\]]?)\s+[\w\(\)]+\s+REFERENCES\s+([`"\[]?(\w+)[`"\]]?)\s*(?:\(([`"\[]?(\w+)[`"\]]?)\))?',
                sql,
                re.IGNORECASE,
            )
            for m in inline_matches:
                src_col = m.group(2)
                tgt_tbl = m.group(4)
                tgt_col = m.group(6) or "ROWID"
                if not any(l.source_table == tbl_name and l.source_column == src_col for l in links):
                    links.append(FKLink(tbl_name, src_col, tgt_tbl, tgt_col))

            # 2. Heuristic convention: col_name like `<entity>_id`
            for col in schema.columns:
                col_lower = col.name.lower()
                if col_lower.endswith("_id") and len(col_lower) > 3:
                    candidate = col_lower[:-3]
                    target_candidate = None
                    for t in self.table_names:
                        if t == candidate or t == f"{candidate}s" or t == f"{candidate}es":
                            target_candidate = t
                            break
                    if target_candidate:
                        if not any(l.source_table == tbl_name and l.source_column == col.name for l in links):
                            links.append(FKLink(tbl_name, col.name, target_candidate, "ROWID"))

        return links

    def build_index_from_records(self, records: List[CarvedRecord]) -> None:
        """Indexes active records by (table_name, rowid) -> display_value."""
        display_col_map: Dict[str, str] = {}
        for tbl_name, schema in self.schemas.items():
            t_low = tbl_name.lower()
            col_names = [c.name.lower() for c in schema.columns]
            best_col = None
            for cand in self.DISPLAY_COLUMN_PRIORITY:
                if cand in col_names:
                    best_col = cand
                    break
            if not best_col and schema.columns:
                text_cols = [c.name.lower() for c in schema.columns if c.affinity == "TEXT"]
                if text_cols:
                    best_col = text_cols[0]
            if best_col:
                display_col_map[t_low] = best_col

        for r in records:
            if r.source != "active" or not r.matched_table or r.rowid is None:
                continue
            t_low = r.matched_table.lower()
            disp_col = display_col_map.get(t_low)
            disp_val = None

            if disp_col and disp_col in r.column_names:
                idx = r.column_names.index(disp_col)
                if idx < len(r.values):
                    val = r.values[idx]
                    if val is not None and str(val).strip():
                        disp_val = str(val).strip()

            if not disp_val:
                for v in r.values:
                    if isinstance(v, str) and v.strip() and len(v) < 100:
                        disp_val = v.strip()
                        break

            if disp_val:
                self.entity_index[(t_low, r.rowid)] = disp_val

    def resolve_record_fks(self, record: CarvedRecord) -> Dict[str, Dict[str, Any]]:
        """Resolves any foreign keys present in the record values."""
        if not record.matched_table:
            return {}

        res: Dict[str, Dict[str, Any]] = {}
        t_low = record.matched_table.lower()

        table_links = [l for l in self.fk_links if l.source_table.lower() == t_low]
        if not table_links:
            return {}

        for link in table_links:
            if link.source_column in record.column_names:
                idx = record.column_names.index(link.source_column)
                if idx < len(record.values):
                    raw_val = record.values[idx]
                    if isinstance(raw_val, int) and raw_val > 0:
                        tgt_key = (link.target_table.lower(), raw_val)
                        if tgt_key in self.entity_index:
                            disp = self.entity_index[tgt_key]
                            res[link.source_column] = {
                                "target_table": link.target_table,
                                "target_column": link.target_column,
                                "target_id": raw_val,
                                "display_value": disp,
                            }

        return res

    def correlate_records(self, records: List[CarvedRecord]) -> None:
        """First indexes active entities, then enriches all records with FK resolutions."""
        self.build_index_from_records(records)
        for r in records:
            fks = self.resolve_record_fks(r)
            if fks:
                r.foreign_keys = fks
