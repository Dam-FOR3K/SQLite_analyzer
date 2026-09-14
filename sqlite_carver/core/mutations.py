"""
Forensic Mutation & Record Alteration Tracking Engine.

Correlates carved residual records (from freeblocks, freelist, slack, WAL)
against live active B-tree records to identify historical updates, edits,
and malicious data alterations on the same logical row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlite_carver.core.carver import CarvedRecord, TableSchema


@dataclass
class MutationDelta:
    table: str
    rowid: Optional[int]
    carved_source: str
    carved_page: int
    carved_offset: int
    active_page: int
    active_offset: int
    changes: List[Dict[str, Any]]  # List of {"column": str, "old_value": Any, "new_value": Any}
    evidence_hash: str = ""


def detect_record_mutations(
    records: List[CarvedRecord],
    schemas: Optional[Dict[str, TableSchema]] = None,
) -> Tuple[List[CarvedRecord], List[MutationDelta]]:
    """
    Scans records to correlate deleted/carved instances with active counterparts.
    Flags records where is_mutation = True and returns a list of MutationDelta items.
    """
    if not records:
        return records, []

    # Step 1: Index active records by (table, rowid) and by primary key values
    active_by_rowid: Dict[Tuple[str, int], CarvedRecord] = {}
    active_by_pk: Dict[Tuple[str, str, Any], CarvedRecord] = {}

    for r in records:
        if r.source == "active" and r.matched_table:
            tbl = r.matched_table
            if r.rowid is not None:
                active_by_rowid[(tbl, r.rowid)] = r
            
            # Index by primary key column or candidate ID column
            for i, col in enumerate(r.column_names):
                col_lower = str(col).lower()
                if col_lower in ("id", "guid", "uuid", "pk", "message_id", "rowid", "entry_id", "key"):
                    if i < len(r.values) and r.values[i] is not None:
                        active_by_pk[(tbl, col_lower, r.values[i])] = r

    mutations: List[MutationDelta] = []

    # Step 2: Compare carved residual records against active records
    for r in records:
        if r.source in ("active", "index_active") or not r.matched_table:
            continue

        tbl = r.matched_table
        active_match: Optional[CarvedRecord] = None

        # 1. Match by rowid
        if r.rowid is not None and (tbl, r.rowid) in active_by_rowid:
            active_match = active_by_rowid[(tbl, r.rowid)]
        
        # 2. Match by primary key column value if rowid match not found
        if not active_match:
            for i, col in enumerate(r.column_names):
                col_lower = str(col).lower()
                if col_lower in ("id", "guid", "uuid", "pk", "message_id", "rowid", "entry_id", "key"):
                    if i < len(r.values) and r.values[i] is not None:
                        pk_key = (tbl, col_lower, r.values[i])
                        if pk_key in active_by_pk:
                            active_match = active_by_pk[pk_key]
                            break

        if not active_match:
            continue

        # Prevent false-positive matching against identical active row
        if (
            r.page_id == active_match.page_id
            and r.offset_in_page == active_match.offset_in_page
        ):
            continue

        # Step 3: Compute field-by-field diff
        changes: List[Dict[str, Any]] = []
        for i, col in enumerate(r.column_names):
            if i >= len(r.values):
                continue
            old_val = r.values[i]
            
            # Find matching column in active record
            if col in active_match.column_names:
                act_idx = active_match.column_names.index(col)
                if act_idx < len(active_match.values):
                    new_val = active_match.values[act_idx]
                    # Check for genuine differences
                    if old_val != new_val and old_val is not None:
                        # Ignore float representation precision noise
                        if isinstance(old_val, float) and isinstance(new_val, float):
                            if abs(old_val - new_val) < 1e-6:
                                continue
                        changes.append({
                            "column": col,
                            "old_value": old_val,
                            "new_value": new_val,
                        })

        if changes:
            r.is_mutation = True
            r.mutation_diff = {
                "active_page": active_match.page_id,
                "active_offset": active_match.offset_in_page,
                "active_rowid": active_match.rowid,
                "changes": changes,
            }
            for ch in changes:
                r.mutation_diff[ch["column"]] = {
                    "active": ch["new_value"],
                    "carved": ch["old_value"],
                }
            if not r.details:
                r.details = f"Historical mutation of row in '{tbl}' ({len(changes)} column(s) altered)"
            else:
                r.details += f" • Mutation diff: {len(changes)} column(s) changed"

            mutations.append(
                MutationDelta(
                    table=tbl,
                    rowid=active_match.rowid,
                    carved_source=r.source,
                    carved_page=r.page_id,
                    carved_offset=r.offset_in_page,
                    active_page=active_match.page_id,
                    active_offset=active_match.offset_in_page,
                    changes=changes,
                    evidence_hash=r.evidence_hash,
                )
            )

    return records, mutations
