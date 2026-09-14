"""
sqlite-carver-pro
~~~~~~~~~~~~~~~~~

Modern, modular, comprehensive Python forensic CLI and library to extract,
carve, and analyze deleted records, freelists, unallocated spaces, and WAL
transaction diffs from SQLite databases.
"""

__version__ = "1.7.0"

from sqlite_carver.core.carver import CarvedRecord, IndexSchema, SQLiteCarver, TableSchema
from sqlite_carver.core.correlator import EntityCorrelator, FKLink, FKResolution
from sqlite_carver.core.integrity import compute_record_evidence_hash, hash_bytes, hash_file
from sqlite_carver.core.parser import Cell, DatabaseHeader, DatabaseParser, PageHeader, PageType, StorageBreakdown
from sqlite_carver.core.search import ForensicSearchEngine, SearchMatch, recursive_search_in_data
from sqlite_carver.core.shm import ShmAnalyzer, ShmHeader
from sqlite_carver.core.varint import decode_serial_value, encode_varint, read_varint, safe_read_varint
from sqlite_carver.core.wal_diff import (
    ColumnDiff,
    JournalDiffEngine,
    JournalFrame,
    JournalHeader,
    MutationType,
    RowMutation,
    WalDiffEngine,
    WalFrame,
    WalHeader,
)
from sqlite_carver.decoders.blobs import (
    DecodedBlobPayload,
    decode_bplist,
    decode_protobuf_wire,
    decode_zlib,
    detect_file_signature,
    dump_blob_to_file,
    inspect_blob,
)
from sqlite_carver.decoders.geolocation import DecodedCoordinate, extract_coordinates
from sqlite_carver.decoders.timestamps import DecodedTimestamp, decode_timestamp, get_all_possible_timestamps
from sqlite_carver.core.encryption import EncryptionAnalysis, analyze_database_encryption, calculate_shannon_entropy
from sqlite_carver.core.mutations import MutationDelta, detect_record_mutations
from sqlite_carver.exporters.html_report import generate_html_report

__all__ = [
    "SQLiteCarver",
    "CarvedRecord",
    "TableSchema",
    "IndexSchema",
    "EntityCorrelator",
    "EncryptionAnalysis",
    "analyze_database_encryption",
    "calculate_shannon_entropy",
    "MutationDelta",
    "detect_record_mutations",
    "FKLink",
    "FKResolution",
    "ShmAnalyzer",
    "ShmHeader",
    "DecodedCoordinate",
    "extract_coordinates",
    "hash_file",
    "hash_bytes",
    "compute_record_evidence_hash",
    "DatabaseParser",
    "DatabaseHeader",
    "PageHeader",
    "PageType",
    "StorageBreakdown",
    "JournalDiffEngine",
    "JournalHeader",
    "JournalFrame",
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
    "detect_file_signature",
    "dump_blob_to_file",
    "DecodedBlobPayload",
    "decode_timestamp",
    "get_all_possible_timestamps",
    "DecodedTimestamp",
    "export_jsonl",
    "export_json",
    "export_html",
    "generate_html_report",
    "export_csv",
    "export_parquet",
    "export_sqlite",
    "dispatch_export",
]
