"""
sqlite-carver-pro
~~~~~~~~~~~~~~~~~

Modern, modular, production-ready Python forensic CLI and library to extract,
carve, and analyze deleted records, freelists, unallocated spaces, and WAL
transaction diffs from SQLite databases.
"""

from sqlite_carver.core.carver import CarvedRecord, SQLiteCarver, TableSchema
from sqlite_carver.core.parser import Cell, DatabaseHeader, DatabaseParser, PageHeader, PageType
from sqlite_carver.core.search import ForensicSearchEngine, SearchMatch, recursive_search_in_data
from sqlite_carver.core.varint import decode_serial_value, encode_varint, read_varint, safe_read_varint
from sqlite_carver.core.wal_diff import ColumnDiff, MutationType, RowMutation, WalDiffEngine, WalFrame, WalHeader
from sqlite_carver.decoders.blobs import DecodedBlobPayload, decode_bplist, decode_protobuf_wire, decode_zlib, inspect_blob
from sqlite_carver.exporters.export import export_csv, export_html, export_json, export_jsonl, export_parquet
from sqlite_carver.exporters.html_report import generate_html_report

__version__ = "1.2.0"
__all__ = [
    "SQLiteCarver",
    "CarvedRecord",
    "TableSchema",
    "DatabaseParser",
    "DatabaseHeader",
    "PageHeader",
    "PageType",
    "Cell",
    "read_varint",
    "safe_read_varint",
    "encode_varint",
    "decode_serial_value",
    "WalDiffEngine",
    "WalHeader",
    "WalFrame",
    "RowMutation",
    "ColumnDiff",
    "MutationType",
    "ForensicSearchEngine",
    "SearchMatch",
    "recursive_search_in_data",
    "inspect_blob",
    "decode_bplist",
    "decode_protobuf_wire",
    "decode_zlib",
    "DecodedBlobPayload",
    "export_jsonl",
    "export_json",
    "export_html",
    "generate_html_report",
    "export_csv",
    "export_parquet",
]
