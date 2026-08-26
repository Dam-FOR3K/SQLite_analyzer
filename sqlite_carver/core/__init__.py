"""Core SQLite parsing, carving, and WAL diff engines."""

from sqlite_carver.core.carver import CarvedRecord, SQLiteCarver, TableSchema
from sqlite_carver.core.parser import Cell, DatabaseHeader, DatabaseParser, PageHeader, PageType
from sqlite_carver.core.search import ForensicSearchEngine, SearchMatch, recursive_search_in_data
from sqlite_carver.core.varint import decode_serial_value, encode_varint, read_varint, safe_read_varint
from sqlite_carver.core.wal_diff import ColumnDiff, MutationType, RowMutation, WalDiffEngine, WalFrame, WalHeader

__all__ = [
    "read_varint",
    "safe_read_varint",
    "encode_varint",
    "decode_serial_value",
    "DatabaseHeader",
    "DatabaseParser",
    "PageHeader",
    "PageType",
    "Cell",
    "TableSchema",
    "CarvedRecord",
    "SQLiteCarver",
    "WalHeader",
    "WalFrame",
    "MutationType",
    "ColumnDiff",
    "RowMutation",
    "WalDiffEngine",
    "ForensicSearchEngine",
    "SearchMatch",
    "recursive_search_in_data",
]
