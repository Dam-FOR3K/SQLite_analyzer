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


def serialize_value(val: Any) -> Any:
    """Serializes values for JSON/CSV/Parquet export with robust error handling."""
    if val is None:
        return None
    elif isinstance(val, (int, float, str, bool)):
        return val
    elif isinstance(val, bytes):
        # Check if it has an embedded structure (bplist, protobuf, zlib, text)
        try:
            blob_info = inspect_blob(val)
            if blob_info.detected_format not in ("unknown", "raw_hex", "raw"):
                if blob_info.detected_format == "text":
                    return blob_info.data
                return {
                    "_blob_format": blob_info.detected_format,
                    "_decoded": blob_info.data,
                    "_metadata": blob_info.metadata,
                    "_raw_hex": val.hex(),
                }
        except Exception:
            pass
        return val.hex()
    elif isinstance(val, dict):
        return {str(k): serialize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [serialize_value(x) for x in val]
    return str(val)


def record_to_dict(rec: CarvedRecord) -> Dict[str, Any]:
    """Converts a CarvedRecord to a serializable dictionary."""
    cols_dict = {}
    for i, col_name in enumerate(rec.column_names):
        val = rec.values[i] if i < len(rec.values) else None
        cols_dict[col_name] = serialize_value(val)

    return {
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
            f.write(json.dumps(d, ensure_ascii=False) + "\n")


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
                    row[k] = json.dumps(v, ensure_ascii=False)
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
        json.dump(serialized, f, ensure_ascii=False, indent=2)


def export_html(records: List[CarvedRecord | RowMutation], output_path: str | Path, title: str = "SQLite Forensic Investigation Report") -> None:
    """Exports records to an interactive standalone HTML dashboard."""
    from sqlite_carver.exporters.html_report import generate_html_report
    generate_html_report(records, output_path, title=title)


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
                "data_json": json.dumps(d["columns"], ensure_ascii=False),
            }
        )

    table = pa.Table.from_pylist(rows)
    pq.write_table(table, str(path))


def dispatch_export(
    records: List[Any],
    output_path: str | Path,
    title: str = "SQLite Forensic Investigation Report",
) -> Dict[str, Any]:
    """
    Centralized, unified export router supporting .html, .json, .jsonl, .csv, and .parquet.
    Returns metadata about the export including total records and actual count written.
    """
    path = Path(output_path)
    suffix = path.suffix.lower()

    carved_records = [r for r in records if isinstance(r, CarvedRecord)]
    wal_mutations = [r for r in records if isinstance(r, RowMutation)]

    if suffix == ".html":
        export_html(records, path, title=title)
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

    else:
        raise ValueError(
            f"Unsupported export format '{suffix}'. Supported formats: .html, .json, .jsonl, .csv, .parquet"
        )


