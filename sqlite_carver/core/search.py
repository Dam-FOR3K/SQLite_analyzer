"""
Forensic Deep Search Engine.

Recursively searches strings, numbers, hex signatures, and embedded binary formats
(Apple bplist, Protocol Buffers, zlib decompressed streams, raw byte streams)
across active database records, carved freeblocks, slack spaces, and WAL transaction diffs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlite_carver.core.carver import CarvedRecord, SQLiteCarver, TableSchema
from sqlite_carver.core.wal_diff import RowMutation, WalDiffEngine
from sqlite_carver.decoders.blobs import inspect_blob


@dataclass
class SearchMatch:
    """Represents a matched keyword/hex pattern inside a record or WAL mutation."""
    record_source: str  # 'active', 'freeblock', 'slack', 'unallocated', 'wal'
    page_id: int
    offset_in_page: int
    confidence: float
    table_name: Optional[str]
    rowid: Optional[int]
    matched_column: str
    matched_value_snippet: str
    container_format: str  # 'text', 'bplist', 'protobuf', 'zlib', 'raw_bytes', 'numeric'
    record: Union[CarvedRecord, RowMutation]


def recursive_search_in_data(
    data: Any,
    query: str,
    is_hex: bool = False,
    current_path: str = "",
) -> Tuple[bool, str, str]:
    """
    Recursively searches for query inside primitive types, dicts, lists,
    and decoded payloads.

    Returns:
        (found: bool, container_format: str, snippet: str)
    """
    target = query.lower()

    if data is None:
        return False, "null", ""

    if isinstance(data, str):
        if is_hex:
            # Check if query hex matches string encoding
            if target in data.encode("utf-8", errors="ignore").hex().lower():
                return True, "text", f"{current_path}: '{data}'"
        else:
            if target in data.lower():
                return True, "text", f"{current_path}: '{data}'" if current_path else f"'{data}'"
        return False, "text", ""

    elif isinstance(data, (int, float)):
        val_str = str(data)
        if not is_hex and target in val_str.lower():
            return True, "numeric", f"{current_path}: {val_str}" if current_path else val_str
        return False, "numeric", ""

    elif isinstance(data, bytes):
        # 1. Inspect and decode blob
        blob_info = inspect_blob(data)
        if blob_info.detected_format in ("bplist", "protobuf", "zlib+bplist", "zlib+protobuf", "zlib+text"):
            found, fmt, snip = recursive_search_in_data(
                blob_info.data, query, is_hex=is_hex, current_path=f"[{blob_info.detected_format}]"
            )
            if found:
                return True, blob_info.detected_format, snip

        # 2. Search in UTF-8 text interpretation of bytes
        raw_text = data.decode("utf-8", errors="ignore").lower()
        if not is_hex and target in raw_text:
            cleaned = data.decode("utf-8", errors="replace")
            return True, "raw_text", f"{current_path}: '{cleaned[:100]}'" if current_path else f"'{cleaned[:100]}'"

        # 3. Search in hex representation
        raw_hex = data.hex().lower()
        clean_target_hex = target.replace(" ", "").replace("0x", "")
        if clean_target_hex in raw_hex:
            return True, "raw_hex", f"{current_path}: hex(0x{raw_hex[:40]}...)" if current_path else f"hex(0x{raw_hex[:40]}...)"

        return False, "bytes", ""

    elif isinstance(data, dict):
        for k, v in data.items():
            path = f"{current_path}.{k}" if current_path else str(k)
            # Check key itself
            if not is_hex and target in str(k).lower():
                return True, "dict_key", f"Key '{path}'"
            # Check value
            found, fmt, snip = recursive_search_in_data(v, query, is_hex=is_hex, current_path=path)
            if found:
                return True, fmt, snip
        return False, "dict", ""

    elif isinstance(data, (list, tuple, set)):
        for idx, item in enumerate(data):
            path = f"{current_path}[{idx}]"
            found, fmt, snip = recursive_search_in_data(item, query, is_hex=is_hex, current_path=path)
            if found:
                return True, fmt, snip
        return False, "list", ""

    else:
        val_str = str(data)
        if not is_hex and target in val_str.lower():
            return True, "other", f"{current_path}: {val_str}" if current_path else val_str
        return False, "other", ""


class ForensicSearchEngine:
    """
    Coordinates global forensic search across database pages, freelists,
    slack spaces, and WAL journals.
    """

    def __init__(
        self,
        db_data: bytes | memoryview,
        wal_data: Optional[bytes | memoryview] = None,
        user_schemas: Optional[List[TableSchema]] = None,
    ):
        self.carver = SQLiteCarver(db_data, user_schemas=user_schemas)
        self.wal_data = wal_data
        self.wal_engine = (
            WalDiffEngine(db_data, wal_data, user_schemas=user_schemas)
            if wal_data and len(wal_data) >= 32
            else None
        )

    def search(
        self,
        query: str,
        is_hex: bool = False,
        include_active: bool = True,
        deleted_only: bool = False,
        table_filter: Optional[str] = None,
        min_confidence: float = 0.5,
        include_wal: bool = True,
    ) -> List[SearchMatch]:
        """
        Executes a deep forensic search for a query string or hex pattern.
        """
        matches: List[SearchMatch] = []

        # 1. Search carved database records
        carve_include_active = not deleted_only and include_active
        records = self.carver.carve_all(include_active=carve_include_active)

        for rec in records:
            if deleted_only and rec.source == "active":
                continue
            if table_filter and rec.matched_table and table_filter.lower() != rec.matched_table.lower():
                continue
            if rec.confidence < min_confidence:
                continue

            for i, val in enumerate(rec.values):
                col_name = rec.column_names[i] if i < len(rec.column_names) else f"col_{i}"
                found, fmt, snippet = recursive_search_in_data(val, query, is_hex=is_hex, current_path=col_name)
                if found:
                    matches.append(
                        SearchMatch(
                            record_source=rec.source,
                            page_id=rec.page_id,
                            offset_in_page=rec.offset_in_page,
                            confidence=rec.confidence,
                            table_name=rec.matched_table,
                            rowid=rec.rowid,
                            matched_column=col_name,
                            matched_value_snippet=snippet,
                            container_format=fmt,
                            record=rec,
                        )
                    )

        # 2. Search WAL mutations if available
        if include_wal and self.wal_engine and not deleted_only:
            try:
                mutations = self.wal_engine.compute_timeline_diff()
                for mut in mutations:
                    if table_filter and mut.table_name and table_filter.lower() != mut.table_name.lower():
                        continue

                    # Search in new_values or old_values
                    search_vals = mut.new_values or mut.old_values or []
                    for i, val in enumerate(search_vals):
                        col_name = f"col_{i}"
                        found, fmt, snippet = recursive_search_in_data(val, query, is_hex=is_hex, current_path=col_name)
                        if found:
                            matches.append(
                                SearchMatch(
                                    record_source=f"wal_{mut.mutation_type.value.lower()}",
                                    page_id=mut.page_id,
                                    offset_in_page=0,
                                    confidence=1.0,
                                    table_name=mut.table_name,
                                    rowid=mut.rowid,
                                    matched_column=col_name,
                                    matched_value_snippet=f"[Frame {mut.frame_index} {mut.mutation_type.value}] {snippet}",
                                    container_format=fmt,
                                    record=mut,
                                )
                            )
            except Exception:
                pass

        return matches
