# SQLite-Carver-Pro 🔍

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows | Linux | macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![i18n: EN | FR](https://img.shields.io/badge/language-English%20%7C%20Fran%C3%A7ais-green.svg)]()

**SQLite-Carver-Pro v1.3.0** is an offline digital forensics parser and analysis toolkit engineered to inspect B-Tree structures, carve deleted records from slack space & freeblocks, reassemble overflow chains, compute WAL transaction differential timelines, decode multi-format timestamps, carve embedded file BLOBs, and decode nested binary structures (`bplist`, `protobuf`, `zlib`).

---

## ⚠️ Important Verification Notice & Disclaimer

> **Forensic Analysis Advisory**:
> Binary carving and slack space recovery utilize heuristic pattern recognition to reconstruct partially overwritten or unreferenced database cells. As with any data recovery or forensic analysis tool, **all carved artifacts, timestamps, and reconstructed rows must be independently verified, corroborated, and cross-referenced** with complementary system logs or primary sources before reaching definitive analytical, investigative, or legal conclusions. The software is provided "as is", without warranty of any kind.

---

## 📑 Documentation & Reference Guides

- 🇬🇧 **[Complete English Forensic Guide (PDF)](./SQLite_Carver_Pro_Forensic_Guide_v1.3.0_EN.pdf)** — Technical reference manual, mathematical score formulas, and CLI guides.
- 🇫🇷 **[Guide Forensique Intégral (PDF)](./Guide_Forensique_SQLite_Carver_Pro_v1.3.0_FR.pdf)** — Manuel de référence complet avec schémas d'architecture B-Tree et barème de scoring.

---

## 📑 Table of Contents

1. [Important Verification Notice & Disclaimer](#️-important-verification-notice--disclaimer)
2. [Core Features](#-core-features)
3. [Interactive HTML Dashboard Preview](#-interactive-html-dashboard-preview)
4. [Architecture Overview](#-architecture-overview)
5. [Installation & Standalone Binary](#-installation--standalone-binary)
6. [CLI Usage Guide & Previews](#-cli-usage-guide--previews)
   - [1. Database Inspection (`info`)](#1-database-inspection-info)
   - [2. Forensic Deleted Record Carving (`carve`)](#2-forensic-deleted-record-carving-carve)
   - [3. Deep Forensic Search (`search`)](#3-deep-forensic-search-search)
   - [4. WAL Transaction Diffing & Timeline (`wal-diff`)](#4-wal-transaction-diffing--timeline-wal-diff)
   - [5. Embedded BLOB Microscope (`decode-blob`)](#5-embedded-blob-microscope-decode-blob)
7. [Supported Export Formats](#-supported-export-formats)
8. [Python API Quickstart](#-python-api-quickstart)
9. [Automated Test Suite](#-automated-test-suite)
10. [Author & Credits](#-author--credits)

---

## 🚀 Core Features

- **Low-Level B-Tree Parsing**: Full dissection of 100-byte database headers, Table Leaf (`0x0D`), Table Interior (`0x05`), Index Leaf (`0x0A`), and Index Interior (`0x02`) pages.
- **Deleted Record Carving**: Recovers deleted cells from **Cell Slack Space**, **Freeblocks** (linked lists), and **Unallocated Page Margins** with heuristic schema matching.
- **Overflow Reassembly**: Transparently chains 4-byte overflow pointers across multi-page payloads.
- **Multi-Format Forensic Timestamp Engine**: Automatic decoding and UTC normalization of Unix Epoch (s, ms, µs), WebKit/Chrome/Safari (µs since 1601), Windows FILETIME (100ns since 1601), Apple Cocoa Absolute Time (seconds since 2001), and GPS Time.
- **BLOB File Signature Carving**: Heuristic magic byte identification and automated extraction of embedded PNG, JPEG, GIF, PDF, ZIP, GZIP, SQLite databases, TIFF, and WebP files (`--dump-blobs`).
- **WAL-Only Table Isolation**: Identifies ephemeral or uncommitted tables created exclusively inside Write-Ahead Log frames (`[★ WAL-ONLY TABLE]`).
- **WAL Diff Engine**: Parses Write-Ahead Log frames to reconstruct row-level `INSERT`, `UPDATE` (with before/after diffs), and `DELETE` mutations.
- **Embedded Binary Decoders**:
  - **Apple Binary Plist (`bplist00`)**: Parses dictionaries, arrays, UIDs, and timestamps.
  - **Google Protocol Buffers (`protobuf`)**: Dynamic wire parser without `.proto` definitions (strict false-positive elimination).
  - **Compression**: Automatic detection and extraction of `zlib`/`deflate` streams.
- **Dual-Language Support**: Native CLI localization (`--lang en` / `--lang fr`) and one-click language switcher inside the HTML report.
- **Zero-Dependency Standalone Binary**: 100% portable `.exe` running out-of-the-box on clean, air-gapped forensic workstations.

---

## 🖥 Interactive HTML Dashboard Preview

When exporting with `--export report.html`, `sqlite-carver-pro` generates a **100% Standalone Air-Gapped Web Application** featuring live instant search, confidence slider, 60 FPS pagination, decoded timestamp badges, and a one-click bilingual toggle (🇬🇧 English / 🇫🇷 Français):

### 📋 All Evidence & Carved Records View
![Dashboard Preview](./docs/images/dashboard_preview.png)

### ⏱️ WAL Transaction Timeline & Diff View
![WAL Timeline Preview](./docs/images/wal_timeline_preview.png)

---

## 🏛 Architecture Overview

```
sqlite-carver-pro/
├── sqlite_carver/
│   ├── core/
│   │   ├── varint.py        # SQLite Varint & Serial Type Codec
│   │   ├── parser.py        # Header, B-Tree Page, Cell, Overflow & Freelist Parser
│   │   ├── carver.py        # Deleted Record Carver, Schema Matcher & Heuristics
│   │   ├── search.py        # Recursive Multi-Container Forensic Search Engine
│   │   └── wal_diff.py      # WAL & Rollback Journal Frame Parser, Timeline & WAL-Only Table Engine
│   ├── decoders/
│   │   ├── blobs.py         # Apple bplist, Protobuf wire parser, zlib, File Signatures & BLOB Dumper
│   │   └── timestamps.py    # Multi-Format Forensic Timestamp Engine (Unix, WebKit, FILETIME, Cocoa, GPS)
│   ├── exporters/
│   │   ├── export.py        # Unified Export Router (HTML, JSON, JSONL, CSV, Parquet)
│   │   └── html_report.py   # Dual-View Interactive Web Application (60 FPS Pagination, Badges)
│   ├── i18n.py              # Internationalization Engine (English & French)
│   ├── cli.py               # Rich CLI with Colorized Outputs, Timestamps & Blob Dumper
│   └── __init__.py          # Unified Python Forensics API
├── dist/
│   └── sqlite-carver-v1.3.0.exe  # Standalone Air-Gapped Binary (Windows 64-bit)
└── tests/
    └── ...                  # 36 Automated Test Suites (100% Pass)
```

---

## 📦 Installation & Standalone Binary

### Option A: Direct Standalone Binary (Zero Python Required)
Download `sqlite-carver-v1.3.0.exe` directly from the [`dist/`](./dist/sqlite-carver-v1.3.0.exe) directory or GitHub Releases.

```powershell
# Check version
.\sqlite-carver-v1.3.0.exe --version
```

### Option B: Python Package Installation
```bash
# Clone the repository
git clone https://github.com/Dam-FOR3K/sqlite-carver-pro.git
cd sqlite-carver-pro

# Install in editable mode
pip install -e .

# Or install with parquet support
pip install -e ".[parquet]"
```

---

## 🖥 CLI Usage Guide & Previews

### 1. Database Inspection (`info`)
Inspect database header flags, page allocation metrics, freelist trunk chains, and discovered schemas:

```bash
# English interface (default)
sqlite-carver info evidence.db

# French interface
sqlite-carver info evidence.db --lang fr
```

**Terminal Output Preview:**
```
╔════════════════════════════════════════════════════════════════╗
║             SQLite-Carver-Pro v1.3.0                           ║
║  Forensic Parser, Slack Carver, Freelist & WAL Diff Engine     ║
╚════════════════════════════════════════════════════════════════╝
╭─────────────────────── SQLite Database Header Analysis ────────────────────────╮
│ Page Size               4096 bytes                                             │
│ Page Count              48 pages (196,608 bytes)                               │
│ File Format Version     Read: 2, Write: 2 (WAL Mode)                           │
│ Text Encoding           UTF-8 (1)                                              │
│ Freelist Pages          3 (Trunk Root Page: 6)                                 │
│ Schema Cookie / Version 4 / user_version: 0                                    │
│ Application ID          0x00000000                                             │
╰────────────────────────────────────────────────────────────────────────────────╯
Found 3 Freelist Page(s): [6, 7, 5]

Discovered Schema Tables:
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Table Name   ┃ Root Page ┃ Columns                        ┃ SQL Definition   ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ users        │         2 │ id: INTEGER, name: TEXT...     │ CREATE TABLE...  │
│ messages     │         3 │ id: INTEGER, body: TEXT...     │ CREATE TABLE...  │
└──────────────┴───────────┴────────────────────────────────┴──────────────────┘
```

---

### 2. Forensic Deleted Record Carving (`carve`)
Carve active cells, freeblock remnants, unallocated page margins, cell slack, and companion WAL journals:

```bash
# 1. Carve all records with automatic embedded file BLOB extraction
sqlite-carver carve evidence.db --dump-blobs ./extracted_blobs

# 2. Isolate ONLY carved deleted records
sqlite-carver carve evidence.db --deleted-only

# 3. Filter by table and strict confidence threshold
sqlite-carver carve evidence.db --table messages --min-confidence 0.80

# 4. Generate the full interactive web report with decoded timestamp badges
sqlite-carver carve evidence.db --export forensic_report.html
```

---

### 3. Deep Forensic Search (`search`)
Recursively search for text keywords or hex signatures across **active records, deleted freeblocks, slack space, WAL transactions, and embedded payloads (`bplist`, `protobuf`, `zlib`, files)**:

```bash
# 1. Search text token across database and WAL journal, dumping any discovered BLOBs
sqlite-carver search evidence.db "session_token_xyz" --dump-blobs ./carved_evidence

# 2. Search hex pattern inside binary BLOB fields
sqlite-carver search evidence.db "deadbeef" --hex

# 3. Target deleted records only
sqlite-carver search evidence.db "malware" --deleted-only

# 4. Export search matches to spreadsheet or JSON
sqlite-carver search evidence.db "admin" --export matches.csv
```

---

### 4. WAL Transaction Diffing & Timeline (`wal-diff`)
Reconstruct chronological transaction mutations across Write-Ahead Log frames, isolating any `[★ WAL-ONLY TABLE]` mutations:

```bash
# Analyze WAL transaction timeline
sqlite-carver wal-diff evidence.db evidence.db-wal

# Target a specific table and export timeline
sqlite-carver wal-diff evidence.db evidence.db-wal --table users --export wal_diff.html
```

---

### 5. Embedded BLOB Microscope (`decode-blob`)
Directly inspect and decode embedded binary structures and file signatures:

```bash
# Inspect hex string
sqlite-carver decode-blob --hex 62706c6973743030d3010203...

# Inspect raw binary file
sqlite-carver decode-blob --file extracted_payload.bin
```

---

## 📊 Supported Export Formats

| Format | Extension | Key Capabilities |
|---|---|---|
| **Interactive HTML Report** | `.html` | Dual-view web app, 60 FPS pagination, live search, WAL timeline tab, decoded timestamp badges, language toggle. |
| **Indented JSON** | `.json` | Full hierarchical representation formatted for text editors with `_timestamps` metadata. |
| **JSON Lines** | `.jsonl` | Single-line JSON streaming format for SIEM ingestion (Splunk, ElasticSearch). |
| **Excel CSV** | `.csv` | Tabular spreadsheet with detailed forensic provenance column. |
| **Apache Parquet** | `.parquet` | High-performance compressed columnar data for Polars, DuckDB, Pandas. |

---

## 🐍 Python API Quickstart

```python
from pathlib import Path
from sqlite_carver import (
    SQLiteCarver, WalDiffEngine, ForensicSearchEngine, export_html,
    TimestampDecoder, detect_file_signature, dump_blob_to_file
)

# 1. Programmatic Carving (v1.3.0)
raw_db = Path("evidence.db").read_bytes()
carver = SQLiteCarver(raw_db)

records = [r for r in carver.carve_all() if r.confidence >= 0.80]
for r in records:
    if r.source != "active":
        print(f"[{r.source.upper()}] Page {r.page_id} | Table: {r.matched_table} | Conf: {r.confidence:.2f}")

# 2. Forensic Multi-Format Timestamp Decoding
ts_decoder = TimestampDecoder()
decoded = ts_decoder.decode(13398765432000000, column_name="visit_time")
if decoded:
    print(f"Decoded WebKit timestamp: {decoded.iso_string} UTC ({decoded.format_name})")

# 3. Carve & Dump Embedded BLOB Files
for r in records:
    for idx, val in enumerate(r.values):
        if isinstance(val, (bytes, bytearray)):
            sig = detect_file_signature(val)
            if sig:
                print(f"Detected file: {sig.mime_type} ({sig.extension})")
                dump_blob_to_file(val, f"./dump/page_{r.page_id}_col_{idx}")

# 4. Recursive Evidence Search
engine = ForensicSearchEngine(raw_db)
matches = engine.search("session_token_xyz")
print(f"Found {len(matches)} token occurrences across database and BLOBs!")

# 5. Export Interactive HTML Report
export_html(records, "automated_report.html")
```

---

## 🧪 Automated Test Suite

```bash
python -m pytest tests/ -v
```

```
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.0.2, pluggy-1.6.0
collected 36 items

tests/test_blobs.py::test_apple_binary_plist PASSED                      [  2%]
tests/test_blobs.py::test_protobuf_dynamic_wire_parser PASSED            [  5%]
tests/test_blobs.py::test_zlib_compressed_stream PASSED                  [  8%]
tests/test_blobs.py::test_inspect_blob_router PASSED                     [ 11%]
tests/test_blobs.py::test_protobuf_false_positive_rejection PASSED       [ 13%]
tests/test_carver.py::test_table_schema_from_sql PASSED                  [ 16%]
tests/test_carver.py::test_schema_matching PASSED                        [ 19%]
tests/test_carver.py::test_carve_real_sqlite_deleted_records PASSED      [ 22%]
tests/test_cli.py::test_exporters PASSED                                 [ 25%]
tests/test_file_blobs.py::test_detect_image_signatures PASSED            [ 27%]
tests/test_file_blobs.py::test_inspect_blob_file_types PASSED            [ 30%]
tests/test_file_blobs.py::test_dump_blob_to_file PASSED                  [ 33%]
tests/test_parser.py::test_database_header_parsing PASSED                [ 36%]
tests/test_parser.py::test_page_header_parsing PASSED                    [ 38%]
tests/test_parser.py::test_decode_record_payload PASSED                  [ 41%]
tests/test_parser.py::test_overflow_reassembly PASSED                    [ 44%]
tests/test_parser.py::test_freelist_traversal PASSED                     [ 47%]
tests/test_search.py::test_recursive_search_in_data_primitives PASSED    [ 50%]
tests/test_search.py::test_recursive_search_in_bplist_and_hex PASSED     [ 52%]
tests/test_search.py::test_forensic_search_engine_active_and_deleted PASSED [ 55%]
tests/test_timestamps.py::test_webkit_chrome_timestamp PASSED            [ 58%]
tests/test_timestamps.py::test_windows_filetime_timestamp PASSED         [ 61%]
tests/test_timestamps.py::test_unix_ms_timestamp PASSED                  [ 63%]
tests/test_timestamps.py::test_unix_sec_timestamp PASSED                 [ 66%]
tests/test_timestamps.py::test_cocoa_mac_timestamp PASSED                [ 69%]
tests/test_timestamps.py::test_invalid_negative_or_zero PASSED           [ 72%]
tests/test_timestamps.py::test_get_all_possible_timestamps PASSED        [ 75%]
tests/test_varint.py::test_single_byte_varint PASSED                     [ 77%]
tests/test_varint.py::test_multi_byte_varint PASSED                      [ 80%]
tests/test_varint.py::test_nine_byte_varint PASSED                       [ 83%]
tests/test_varint.py::test_truncated_varint PASSED                       [ 86%]
tests/test_varint.py::test_serial_type_lengths PASSED                    [ 88%]
tests/test_varint.py::test_decode_serial_values PASSED                   [ 91%]
tests/test_varint.py::test_truncated_serial_value PASSED                 [ 94%]
tests/test_wal_diff.py::test_wal_header_parsing PASSED                   [ 97%]
tests/test_wal_diff.py::test_wal_diff_end_to_end PASSED                  [100%]

============================= 36 passed in 0.64s ==============================
```

---

## 👤 Author & Credits

- **Author & Design :** **Dam-FOR3K**
- **Technical & Systems Engineering :** Antigravity AI (Google DeepMind)

---

## 📜 License

This project is licensed under the **MIT License**. See the [`LICENSE`](./LICENSE) file for details.
