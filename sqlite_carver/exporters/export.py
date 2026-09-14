"""
Export Engines for Carved SQLite Forensics Data.

Supports:
- JSON Lines (.jsonl)
- CSV (.csv)
- Apache Parquet (.parquet via pyarrow)
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from sqlite_carver.core.carver import CarvedRecord
from sqlite_carver.core.wal_diff import RowMutation
from sqlite_carver.decoders.blobs import inspect_blob
from sqlite_carver.decoders.geolocation import extract_coordinates
from sqlite_carver.decoders.timestamps import decode_timestamp


def json_safe_default(obj: Any) -> Any:
    """Universal fallback serializer for json.dumps ensuring zero JSON serialization crashes."""
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    return str(obj)


def serialize_value(val: Any) -> Any:
    """Serializes values for JSON/CSV/Parquet export with robust error handling."""
    if val is None:
        return None
    elif isinstance(val, (int, float, str, bool)):
        return val
    elif isinstance(val, (bytes, bytearray, memoryview)):
        raw_b = bytes(val)
        # Check if it has an embedded structure (bplist, protobuf, zlib, text)
        try:
            blob_info = inspect_blob(raw_b)
            if blob_info.detected_format not in ("unknown", "raw_hex", "raw"):
                if blob_info.detected_format == "text":
                    return blob_info.data
                return {
                    "_blob_format": blob_info.detected_format,
                    "_decoded": blob_info.data,
                    "_metadata": blob_info.metadata,
                    "_raw_hex": raw_b.hex(),
                }
        except Exception:
            pass
        return raw_b.hex()
    elif isinstance(val, dict):
        return {str(k): serialize_value(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple, set)):
        return [serialize_value(x) for x in val]
    return str(val)


def record_to_dict(rec: CarvedRecord) -> Dict[str, Any]:
    """Converts a CarvedRecord to a serializable dictionary."""
    cols_dict = {}
    timestamps_dict = {}
    for i, col_name in enumerate(rec.column_names):
        val = rec.values[i] if i < len(rec.values) else None
        cols_dict[col_name] = serialize_value(val)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            ts = decode_timestamp(val, col_name)
            if ts:
                timestamps_dict[col_name] = {
                    "iso_utc": ts.iso_utc,
                    "format": ts.format_name,
                    "description": ts.description,
                }

    res = {
        "page_id": rec.page_id,
        "offset_in_page": rec.offset_in_page,
        "source": rec.source,
        "confidence": round(rec.confidence, 3),
        "matched_table": rec.matched_table,
        "rowid": rec.rowid,
        "is_partial": rec.is_partial,
        "details": rec.details,
        "columns": cols_dict,
        "raw_values": [serialize_value(v) for v in rec.values],
        "serial_types": rec.serial_types,
    }
    if timestamps_dict:
        res["_timestamps"] = timestamps_dict
    if getattr(rec, "foreign_keys", None):
        res["_foreign_keys"] = rec.foreign_keys
    coord = extract_coordinates(cols_dict)
    if coord:
        res["_geo"] = {
            "latitude": coord.latitude,
            "longitude": coord.longitude,
            "altitude": coord.altitude,
            "lat_col": coord.lat_col,
            "lon_col": coord.lon_col,
            "url": coord.open_street_map_url,
        }
    if getattr(rec, "evidence_hash", None):
        res["_evidence_hash"] = rec.evidence_hash
    res["is_mutation"] = getattr(rec, "is_mutation", False)
    if getattr(rec, "mutation_diff", None):
        res["mutation_diff"] = serialize_value(rec.mutation_diff)
    return res


def mutation_to_dict(mut: RowMutation) -> Dict[str, Any]:
    """Converts a RowMutation to a serializable dictionary."""
    diffs = [
        {
            "column": d.column_name,
            "old": serialize_value(d.old_value),
            "new": serialize_value(d.new_value),
        }
        for d in mut.column_diffs
    ]
    return {
        "mutation_type": mut.mutation_type.value,
        "frame_index": mut.frame_index,
        "page_id": mut.page_id,
        "table_name": mut.table_name,
        "rowid": mut.rowid,
        "is_commit": mut.is_commit,
        "is_wal_only_table": getattr(mut, "is_wal_only_table", False),
        "diff_state": getattr(mut, "diff_state", "diff_from_db"),
        "journal_source": getattr(mut, "journal_source", "wal"),
        "column_diffs": diffs,
        "old_values": [serialize_value(v) for v in mut.old_values] if mut.old_values else None,
        "new_values": [serialize_value(v) for v in mut.new_values] if mut.new_values else None,
        "details": mut.details,
    }


def export_jsonl(records: List[CarvedRecord | RowMutation], output_path: str | Path) -> None:
    """Exports records or WAL mutations to JSON Lines format."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            if isinstance(r, CarvedRecord):
                d = record_to_dict(r)
            elif isinstance(r, RowMutation):
                d = mutation_to_dict(r)
            else:
                d = serialize_value(r)
            f.write(json.dumps(d, ensure_ascii=False, default=json_safe_default) + "\n")


def export_csv(records: List[CarvedRecord], output_path: str | Path) -> None:
    """Exports carved records to CSV format with full forensic details."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not records:
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write("page_id,offset_in_page,source,confidence,matched_table,rowid,is_partial,details,values\n")
        return

    # Find all unique column names
    all_col_names = ["page_id", "offset_in_page", "source", "confidence", "matched_table", "rowid", "is_partial", "details"]
    dynamic_cols: set[str] = set()
    for r in records:
        for c in r.column_names:
            dynamic_cols.add(c)
    
    sorted_dynamic = sorted(dynamic_cols)
    header = all_col_names + sorted_dynamic

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for r in records:
            d = record_to_dict(r)
            row = {
                "page_id": d["page_id"],
                "offset_in_page": d["offset_in_page"],
                "source": d["source"],
                "confidence": d["confidence"],
                "matched_table": d["matched_table"] or "",
                "rowid": d["rowid"] if d["rowid"] is not None else "",
                "is_partial": d["is_partial"],
                "details": d["details"] or "",
            }
            for k, v in d["columns"].items():
                if isinstance(v, (dict, list)):
                    row[k] = json.dumps(v, ensure_ascii=False, default=json_safe_default)
                else:
                    row[k] = v if v is not None else ""
            writer.writerow(row)


def export_json(records: List[CarvedRecord | RowMutation], output_path: str | Path) -> None:
    """Exports records or WAL mutations to a formatted, pretty-printed JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = []
    for r in records:
        if isinstance(r, CarvedRecord):
            serialized.append(record_to_dict(r))
        elif isinstance(r, RowMutation):
            serialized.append(mutation_to_dict(r))
        else:
            serialized.append(serialize_value(r))

    with open(path, "w", encoding="utf-8") as f:
        json.dump(serialized, f, ensure_ascii=False, indent=2, default=json_safe_default)


def export_html(
    records: List[CarvedRecord | RowMutation],
    output_path: str | Path,
    title: str = "SQLite Forensic Investigation Report",
    storage_breakdown: Optional[Dict[str, Any]] = None,
    integrity_info: Optional[Dict[str, Any]] = None,
    shm_info: Optional[Dict[str, Any]] = None,
    lang: Optional[str] = None,
) -> None:
    """Exports records to an interactive standalone HTML dashboard."""
    from sqlite_carver.exporters.html_report import generate_html_report
    generate_html_report(
        records,
        output_path,
        title=title,
        storage_breakdown=storage_breakdown,
        integrity_info=integrity_info,
        shm_info=shm_info,
        lang=lang,
    )


def export_parquet(records: List[CarvedRecord], output_path: str | Path) -> None:
    """Exports carved records to Apache Parquet format via pyarrow."""
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        raise ImportError(
            "pyarrow is required for Parquet export. Install it with `pip install pyarrow`."
        )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for r in records:
        d = record_to_dict(r)
        rows.append(
            {
                "page_id": d["page_id"],
                "offset_in_page": d["offset_in_page"],
                "source": d["source"],
                "confidence": d["confidence"],
                "matched_table": str(d["matched_table"] or ""),
                "rowid": d["rowid"] if d["rowid"] is not None else -1,
                "is_partial": d["is_partial"],
                "details": d["details"],
                "data_json": json.dumps(d["columns"], ensure_ascii=False, default=json_safe_default),
            }
        )

    table = pa.Table.from_pylist(rows)
    pq.write_table(table, str(path))


def export_sqlite(
    records: List[CarvedRecord | RowMutation],
    output_path: str | Path,
    schemas: Optional[Dict[str, Any]] = None,
    storage_breakdown: Optional[Dict[str, Any]] = None,
    integrity_info: Optional[Dict[str, Any]] = None,
    shm_info: Optional[Dict[str, Any]] = None,
    title: str = "SQLite Forensic Investigation Report",
) -> None:
    """
    Exports carved evidence and transaction diffs to a reconstructed SQLite database (.sqlite / .db).
    Recreates original table structures and columns, appending forensic provenance metadata
    (_forensic_source, _forensic_confidence, _forensic_page, etc.) to enable direct SQL querying.
    """
    import sqlite3
    from datetime import datetime, timezone
    from sqlite_carver import __version__

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            path.unlink()
        except Exception:
            pass

    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    cursor = conn.cursor()

    # Separate records by category
    carved_by_table: Dict[str, List[CarvedRecord]] = {}
    unmatched_records: List[CarvedRecord] = []
    wal_mutations: List[RowMutation] = []

    for r in records:
        if isinstance(r, CarvedRecord):
            tbl = (r.matched_table or "").strip()
            if tbl and tbl.lower() not in ("unknown", "unmatched"):
                carved_by_table.setdefault(tbl, []).append(r)
            else:
                unmatched_records.append(r)
        elif isinstance(r, RowMutation):
            wal_mutations.append(r)

    def sanitize_sqlite_affinity(raw_type: Any) -> str:
        if not raw_type:
            return "BLOB"
        u = str(raw_type).upper()
        if "INT" in u:
            return "INTEGER"
        elif "CHAR" in u or "TEXT" in u or "CLOB" in u:
            return "TEXT"
        elif "REAL" in u or "FLOA" in u or "DOUB" in u:
            return "REAL"
        elif "BLOB" in u:
            return "BLOB"
        else:
            return "NUMERIC"

    # Reconstruct tables
    all_table_names = set(carved_by_table.keys())
    if schemas:
        all_table_names.update(schemas.keys())

    import re

    for tbl_name in sorted(all_table_names):
        tbl_records = carved_by_table.get(tbl_name, [])
        col_names: List[str] = []
        col_affinities: Dict[str, str] = {}
        seen_cols_lower: set[str] = set()

        # SQLite reserves table names starting with sqlite_ (e.g. sqlite_stat1, sqlite_sequence)
        safe_tbl_name = f"_{tbl_name}" if tbl_name.lower().startswith("sqlite_") else tbl_name

        try:
            # 1. From schema if available
            if schemas and tbl_name in schemas:
                schema_obj = schemas[tbl_name]
                if hasattr(schema_obj, "columns"):
                    for col_def in schema_obj.columns:
                        clower = col_def.name.lower()
                        if clower not in seen_cols_lower:
                            seen_cols_lower.add(clower)
                            col_names.append(col_def.name)
                            col_affinities[clower] = sanitize_sqlite_affinity(getattr(col_def, "affinity", "BLOB"))

            # 2. From records if schema was missing or incomplete
            for rec in tbl_records:
                for idx, cn in enumerate(rec.column_names):
                    clower = cn.lower()
                    if clower not in seen_cols_lower:
                        seen_cols_lower.add(clower)
                        col_names.append(cn)
                        raw_aff = rec.column_types[idx] if idx < len(rec.column_types) else "BLOB"
                        col_affinities[clower] = sanitize_sqlite_affinity(raw_aff)

            if not col_names:
                col_names = ["data"]
                col_affinities["data"] = "TEXT"

            # Construct CREATE TABLE without restrictive UNIQUE/PRIMARY KEY constraints
            col_defs_sql = []
            for cn in col_names:
                safe_cn = cn.replace('"', '""')
                aff = sanitize_sqlite_affinity(col_affinities.get(cn.lower(), "BLOB"))
                col_defs_sql.append(f'"{safe_cn}" {aff}')

            # Add forensic audit columns
            col_defs_sql.append('"_forensic_source" TEXT')
            col_defs_sql.append('"_forensic_confidence" REAL')
            col_defs_sql.append('"_forensic_page" INTEGER')
            col_defs_sql.append('"_forensic_offset" INTEGER')
            col_defs_sql.append('"_forensic_is_partial" INTEGER')
            col_defs_sql.append('"_forensic_hash" TEXT')
            col_defs_sql.append('"_forensic_details" TEXT')
            col_defs_sql.append('"_forensic_is_mutation" INTEGER')
            col_defs_sql.append('"_forensic_diff" TEXT')

            safe_tbl = safe_tbl_name.replace('"', '""')
            create_sql = f'CREATE TABLE "{safe_tbl}" (\n  ' + ",\n  ".join(col_defs_sql) + "\n);"
            cursor.execute(create_sql)

            # Create indexing on forensic source
            safe_idx = re.sub(r"[^a-zA-Z0-9_]", "_", safe_tbl_name)
            cursor.execute(f'CREATE INDEX IF NOT EXISTS "idx_{safe_idx}__forensic_source" ON "{safe_tbl}" ("_forensic_source");')

            # Insert rows for this table
            if tbl_records:
                escaped_col_names = ['"' + cn.replace('"', '""') + '"' for cn in col_names]
                insert_cols = escaped_col_names + [
                    '"_forensic_source"',
                    '"_forensic_confidence"',
                    '"_forensic_page"',
                    '"_forensic_offset"',
                    '"_forensic_is_partial"',
                    '"_forensic_hash"',
                    '"_forensic_details"',
                    '"_forensic_is_mutation"',
                    '"_forensic_diff"',
                ]
                placeholders = ", ".join(["?"] * len(insert_cols))
                insert_sql = f'INSERT INTO "{safe_tbl}" ({", ".join(insert_cols)}) VALUES ({placeholders})'

                rows_to_insert = []
                for rec in tbl_records:
                    row_vals = []
                    rec_cols_map = {cn.lower(): rec.values[i] for i, cn in enumerate(rec.column_names) if i < len(rec.values)}
                    for cn in col_names:
                        val = rec_cols_map.get(cn.lower(), None)
                        if isinstance(val, (dict, list)):
                            val = json.dumps(val, ensure_ascii=False, default=json_safe_default)
                        row_vals.append(val)

                    # Forensic metadata
                    row_vals.append(rec.source)
                    row_vals.append(round(rec.confidence, 3))
                    row_vals.append(rec.page_id)
                    row_vals.append(rec.offset_in_page)
                    row_vals.append(1 if rec.is_partial else 0)
                    row_vals.append(rec.evidence_hash)
                    row_vals.append(rec.details or "")
                    row_vals.append(1 if getattr(rec, "is_mutation", False) else 0)
                    row_vals.append(json.dumps(getattr(rec, "mutation_diff", {}), ensure_ascii=False, default=json_safe_default) if getattr(rec, "is_mutation", False) else "")
                    rows_to_insert.append(row_vals)

                    if len(rows_to_insert) >= 5000:
                        cursor.executemany(insert_sql, rows_to_insert)
                        rows_to_insert.clear()

                if rows_to_insert:
                    cursor.executemany(insert_sql, rows_to_insert)
                    rows_to_insert.clear()

        except Exception as e:
            # If creating or inserting a specific table fails, safely re-route its records to unmatched
            unmatched_records.extend(tbl_records)

    # 3. Create _unmatched_evidence table if any unmatched records exist
    if unmatched_records:
        cursor.execute("""
        CREATE TABLE "_unmatched_evidence" (
            "id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "page_id" INTEGER,
            "offset_in_page" INTEGER,
            "source" TEXT,
            "confidence" REAL,
            "is_partial" INTEGER,
            "values_json" TEXT,
            "serial_types" TEXT,
            "raw_payload" BLOB,
            "evidence_hash" TEXT,
            "details" TEXT
        );
        """)
        cursor.execute('CREATE INDEX "idx_unmatched_source" ON "_unmatched_evidence" ("source");')

        unmatched_rows = []
        for rec in unmatched_records:
            val_serialized = [serialize_value(v) for v in rec.values]
            unmatched_rows.append((
                rec.page_id,
                rec.offset_in_page,
                rec.source,
                round(rec.confidence, 3),
                1 if rec.is_partial else 0,
                json.dumps(val_serialized, ensure_ascii=False, default=json_safe_default),
                json.dumps(rec.serial_types, default=json_safe_default),
                rec.raw_payload,
                rec.evidence_hash,
                rec.details or "",
            ))
            if len(unmatched_rows) >= 5000:
                cursor.executemany(
                    'INSERT INTO "_unmatched_evidence" (page_id, offset_in_page, source, confidence, is_partial, values_json, serial_types, raw_payload, evidence_hash, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    unmatched_rows
                )
                unmatched_rows.clear()
        if unmatched_rows:
            cursor.executemany(
                'INSERT INTO "_unmatched_evidence" (page_id, offset_in_page, source, confidence, is_partial, values_json, serial_types, raw_payload, evidence_hash, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                unmatched_rows
            )

    # 4. Create _wal_journal_timeline table if any WAL/Journal mutations exist
    if wal_mutations:
        cursor.execute("""
        CREATE TABLE "_wal_journal_timeline" (
            "id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "frame_number" INTEGER,
            "page_id" INTEGER,
            "journal_source" TEXT,
            "mutation_type" TEXT,
            "table_name" TEXT,
            "rowid" INTEGER,
            "timestamp_utc" TEXT,
            "diff_content_json" TEXT,
            "values_json" TEXT
        );
        """)
        cursor.execute('CREATE INDEX "idx_wal_table" ON "_wal_journal_timeline" ("table_name");')
        cursor.execute('CREATE INDEX "idx_wal_type" ON "_wal_journal_timeline" ("mutation_type");')

        wal_rows = []
        for m in wal_mutations:
            diff_dict = [
                {"column": d.column_name, "old": serialize_value(d.old_value), "new": serialize_value(d.new_value)}
                for d in getattr(m, "column_diffs", [])
            ]
            diff_str = json.dumps(diff_dict, ensure_ascii=False, default=json_safe_default)
            vals = getattr(m, "new_values", None) or getattr(m, "old_values", None) or getattr(m, "values", [])
            vals_str = json.dumps([serialize_value(v) for v in vals], ensure_ascii=False, default=json_safe_default)
            mut_type = m.mutation_type.value if hasattr(m.mutation_type, "value") else str(m.mutation_type)
            frame_num = getattr(m, "frame_index", getattr(m, "frame_number", None))
            wal_rows.append((
                frame_num,
                getattr(m, "page_id", None),
                getattr(m, "journal_source", "wal"),
                mut_type,
                getattr(m, "table_name", None),
                getattr(m, "rowid", None),
                getattr(m, "timestamp_utc", None),
                diff_str,
                vals_str,
            ))
        cursor.executemany(
            'INSERT INTO "_wal_journal_timeline" (frame_number, page_id, journal_source, mutation_type, table_name, rowid, timestamp_utc, diff_content_json, values_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            wal_rows
        )

    # 5. Create _mutations_diff table for altered/mutated rows
    mutations_records = [r for r in records if isinstance(r, CarvedRecord) and getattr(r, "is_mutation", False) and getattr(r, "mutation_diff", None)]
    if mutations_records:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS "_mutations_diff" (
            "id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "table_name" TEXT,
            "rowid" INTEGER,
            "carved_source" TEXT,
            "carved_page" INTEGER,
            "carved_offset" INTEGER,
            "active_page" INTEGER,
            "active_offset" INTEGER,
            "column_name" TEXT,
            "old_carved_value" TEXT,
            "new_active_value" TEXT,
            "evidence_hash" TEXT
        );
        """)
        cursor.execute('CREATE INDEX IF NOT EXISTS "idx_mutations_tbl_rowid" ON "_mutations_diff" ("table_name", "rowid");')
        diff_rows = []
        for mr in mutations_records:
            act_p = mr.mutation_diff.get("active_page", 0)
            act_o = mr.mutation_diff.get("active_offset", 0)
            act_r = mr.mutation_diff.get("active_rowid", mr.rowid)
            changes = list(mr.mutation_diff.get("changes", []))
            if not changes:
                for k, v in mr.mutation_diff.items():
                    if k not in ("active_page", "active_offset", "active_rowid") and isinstance(v, dict):
                        changes.append({
                            "column": k,
                            "old_value": v.get("carved", ""),
                            "new_value": v.get("active", ""),
                        })
            for ch in changes:
                diff_rows.append((
                    mr.matched_table,
                    act_r,
                    mr.source,
                    mr.page_id,
                    mr.offset_in_page,
                    act_p,
                    act_o,
                    str(ch.get("column", "")),
                    str(ch.get("old_value", "")),
                    str(ch.get("new_value", "")),
                    mr.evidence_hash,
                ))
        if diff_rows:
            cursor.executemany("""
            INSERT INTO "_mutations_diff" (
                "table_name", "rowid", "carved_source", "carved_page", "carved_offset",
                "active_page", "active_offset", "column_name", "old_carved_value", "new_active_value", "evidence_hash"
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, diff_rows)

    # 6. Create _forensic_metadata table
    cursor.execute("""
    CREATE TABLE "_forensic_metadata" (
        "property" TEXT PRIMARY KEY,
        "value" TEXT
    );
    """)
    meta_entries = [
        ("report_title", title),
        ("generator", f"SQLite-Carver-Pro v{__version__}"),
        ("export_timestamp_utc", datetime.now(timezone.utc).isoformat()),
        ("total_evidence_records", str(len(records))),
        ("carved_records_count", str(sum(len(v) for v in carved_by_table.values()) + len(unmatched_records))),
        ("wal_mutations_count", str(len(wal_mutations))),
        ("unmatched_records_count", str(len(unmatched_records))),
    ]
    if storage_breakdown:
        meta_entries.append(("storage_breakdown_json", json.dumps(storage_breakdown, ensure_ascii=False, default=json_safe_default)))
    if integrity_info:
        meta_entries.append(("integrity_hashes_json", json.dumps(integrity_info, ensure_ascii=False, default=json_safe_default)))
    if shm_info:
        meta_entries.append(("shm_diagnostics_json", json.dumps(shm_info, ensure_ascii=False, default=json_safe_default)))

    cursor.executemany('INSERT INTO "_forensic_metadata" (property, value) VALUES (?, ?)', meta_entries)

    conn.commit()
    conn.close()


def dispatch_export(
    records: List[Any],
    output_path: str | Path,
    title: str = "SQLite Forensic Investigation Report",
    schemas: Optional[Dict[str, Any]] = None,
    storage_breakdown: Optional[Dict[str, Any]] = None,
    integrity_info: Optional[Dict[str, Any]] = None,
    shm_info: Optional[Dict[str, Any]] = None,
    lang: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Centralized, unified export router supporting .html, .json, .jsonl, .csv, .parquet, .sqlite, and .db.
    Returns metadata about the export including total records and actual count written.
    """
    path = Path(output_path)
    suffix = path.suffix.lower()

    carved_records = [r for r in records if isinstance(r, CarvedRecord)]
    wal_mutations = [r for r in records if isinstance(r, RowMutation)]

    if suffix == ".html":
        export_html(
            records,
            path,
            title=title,
            storage_breakdown=storage_breakdown,
            integrity_info=integrity_info,
            shm_info=shm_info,
            lang=lang,
        )
        return {"status": "ok", "format": "HTML", "written": len(records), "skipped_wal": 0, "path": path}

    elif suffix == ".json":
        export_json(records, path)
        return {"status": "ok", "format": "JSON", "written": len(records), "skipped_wal": 0, "path": path}

    elif suffix == ".jsonl":
        export_jsonl(records, path)
        return {"status": "ok", "format": "JSONL", "written": len(records), "skipped_wal": 0, "path": path}

    elif suffix == ".csv":
        export_csv(carved_records, path)
        skipped = len(wal_mutations)
        return {"status": "ok", "format": "CSV", "written": len(carved_records), "skipped_wal": skipped, "path": path}

    elif suffix == ".parquet":
        export_parquet(carved_records, path)
        skipped = len(wal_mutations)
        return {"status": "ok", "format": "Parquet", "written": len(carved_records), "skipped_wal": skipped, "path": path}

    elif suffix in (".sqlite", ".db"):
        export_sqlite(
            records,
            path,
            schemas=schemas,
            storage_breakdown=storage_breakdown,
            integrity_info=integrity_info,
            shm_info=shm_info,
            title=title,
        )
        return {"status": "ok", "format": "SQLite", "written": len(records), "skipped_wal": 0, "path": path}

    else:
        raise ValueError(
            f"Unsupported export format '{suffix}'. Supported formats: .html, .json, .jsonl, .csv, .parquet, .sqlite, .db"
        )


