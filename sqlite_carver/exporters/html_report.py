"""
Interactive Offline HTML Forensic Report Generator with Dedicated WAL Diff Timeline.

Generates a standalone, beautiful, responsive, air-gapped HTML dashboard featuring:
- Dual-View Navigation: Unified Evidence Table & Dedicated WAL Transaction Timeline.
- Real-time keyword search & filtering across carved cells and WAL mutations.
- Interactive Side-by-Side Column Diffs for UPDATE / INSERT / DELETE events.
- Collapsible inspect boxes for Apple bplist, Protocol Buffers, and zlib streams.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List, Union

from sqlite_carver import __version__
from sqlite_carver.core.carver import CarvedRecord
from sqlite_carver.core.wal_diff import RowMutation
from sqlite_carver.exporters.export import mutation_to_dict, record_to_dict


def generate_html_report(
    records: List[Union[CarvedRecord, RowMutation]],
    output_path: str | Path,
    title: str = "SQLite Forensic Investigation Report",
    storage_breakdown: Optional[Dict[str, Any]] = None,
    integrity_info: Optional[Dict[str, Any]] = None,
    shm_info: Optional[Dict[str, Any]] = None,
    lang: Optional[str] = None,
) -> None:
    """Generates a standalone, interactive HTML forensic dashboard with WAL/Journal diff timeline."""
    from sqlite_carver.i18n import get_language
    active_lang = (lang or get_language() or "en").lower()
    if active_lang not in ("en", "fr"):
        active_lang = "en"

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert records to JSON serializable objects
    serialized_records = []
    wal_mutations = []
    source_stats: Dict[str, int] = {}
    table_stats: Dict[str, int] = {}

    for r in records:
        if isinstance(r, CarvedRecord):
            d = record_to_dict(r)
            d["_record_kind"] = "carved"
            src = d["source"]
            tbl = d["matched_table"] or "Unknown / Unmatched"
        elif isinstance(r, RowMutation):
            d = mutation_to_dict(r)
            d["_record_kind"] = "journal" if getattr(r, "journal_source", "wal") == "rollback_journal" else "wal"
            src_prefix = "journal" if getattr(r, "journal_source", "wal") == "rollback_journal" else "wal"
            src = f"{src_prefix}_{d['mutation_type'].lower()}"
            tbl = d["table_name"] or "Unknown / Unmatched"
            wal_mutations.append(d)
        else:
            d = {"raw": str(r)}
            src = "unknown"
            tbl = "Unknown"

        source_stats[src] = source_stats.get(src, 0) + 1
        table_stats[tbl] = table_stats.get(tbl, 0) + 1
        serialized_records.append(d)

    mutations_count = sum(1 for d in serialized_records if d.get("is_mutation"))

    active_table_count = source_stats.get('active', 0)
    active_index_count = source_stats.get('index_active', 0)
    total_active_count = active_table_count + active_index_count

    fb_table_count = source_stats.get('freeblock', 0)
    fb_index_count = source_stats.get('index_freeblock', 0)
    total_freeblock_count = fb_table_count + fb_index_count

    slack_table_count = source_stats.get('slack', 0) + source_stats.get('unallocated', 0)
    slack_index_count = source_stats.get('index_slack', 0) + source_stats.get('index_unallocated', 0)
    total_slack_count = slack_table_count + slack_index_count

    freelist_count = source_stats.get('freelist', 0)
    reserved_count = source_stats.get('page_reserved_space', 0) + source_stats.get('reserved_space', 0)

    res_b_per_page = 0
    if storage_breakdown and hasattr(storage_breakdown, 'reserved_space_per_page'):
        res_b_per_page = storage_breakdown.reserved_space_per_page
    elif isinstance(storage_breakdown, dict):
        res_b_per_page = storage_breakdown.get('reserved_space_per_page', 0)
    
    if active_lang == "fr":
        reserved_sub = f"{res_b_per_page} octets/page" if res_b_per_page > 0 else "Stéganographie / Slack"
    else:
        reserved_sub = f"{res_b_per_page} B/page" if res_b_per_page > 0 else "Steganography / Slack"

    active_sub = f"Table: {active_table_count:,} | Index: {active_index_count:,}" if active_index_count > 0 else "Allocated Cells"
    fb_sub = f"Table: {fb_table_count:,} | Index: {fb_index_count:,}" if fb_index_count > 0 else "Deleted Linked Blocks"
    slack_sub = f"Table: {slack_table_count:,} | Index: {slack_index_count:,}" if slack_index_count > 0 else "Gaps & Margins"

    def json_safe_default(obj: Any) -> Any:
        if isinstance(obj, (bytes, bytearray, memoryview)):
            return bytes(obj).hex()
        return str(obj)

    json_payload = json.dumps(serialized_records, ensure_ascii=False, default=json_safe_default).replace("</", r"\u003c/")
    wal_payload = json.dumps(wal_mutations, ensure_ascii=False, default=json_safe_default).replace("</", r"\u003c/")
    storage_payload = json.dumps(storage_breakdown or {}, ensure_ascii=False, default=json_safe_default).replace("</", r"\u003c/")
    integrity_payload = json.dumps(integrity_info or {}, ensure_ascii=False, default=json_safe_default).replace("</", r"\u003c/")
    shm_payload = json.dumps(shm_info or {}, ensure_ascii=False, default=json_safe_default).replace("</", r"\u003c/")

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #182234;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent: #38bdf8;
            --accent-hover: #0284c7;
            --color-active: #22c55e;
            --color-freeblock: #ef4444;
            --color-freelist: #a855f7;
            --color-slack: #f59e0b;
            --color-unallocated: #ec4899;
            --color-wal: #06b6d4;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 24px;
        }}

        .container {{
            max-width: 1500px;
            margin: 0 auto;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 18px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }}

        .title-group h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .title-group p {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 4px;
        }}

        /* Navigation Tabs */
        .tabs-nav {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}

        .tab-btn {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .tab-btn.active {{
            background: var(--accent);
            color: #0f172a;
            border-color: var(--accent);
            font-weight: 700;
        }}

        .tab-badge {{
            background: rgba(0, 0, 0, 0.2);
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
        }}

        .tab-btn.active .tab-badge {{
            background: rgba(15, 23, 42, 0.3);
            color: #0f172a;
        }}

        .tab-pane {{
            display: none;
        }}
        .tab-pane.active {{
            display: block;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 14px;
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}

        .stat-card .label {{
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }}

        .stat-card .value {{
            font-size: 1.6rem;
            font-weight: 700;
            margin-top: 4px;
            color: var(--text-primary);
        }}

        .stat-card .sub {{
            font-size: 0.73rem;
            color: var(--text-secondary);
            margin-top: 3px;
            font-weight: 500;
        }}

        /* Filter Controls */
        .controls-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            align-items: center;
        }}

        .search-box {{
            flex: 1 1 300px;
        }}

        .search-box input {{
            width: 100%;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 9px 14px;
            color: var(--text-primary);
            font-size: 0.95rem;
            outline: none;
        }}

        .search-box input:focus {{
            border-color: var(--accent);
        }}

        .filter-select, .confidence-slider {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        select {{
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-primary);
            outline: none;
            cursor: pointer;
        }}

        /* Table */
        .table-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            overflow: hidden;
        }}

        .table-container {{
            max-height: 750px;
            overflow-y: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            text-align: left;
        }}

        th {{
            background-color: var(--bg-card);
            color: var(--text-secondary);
            padding: 12px 16px;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
            border-bottom: 1px solid var(--border-color);
        }}

        td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }}

        tr:hover td {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .badge-active {{ background-color: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }}
        .badge-freeblock {{ background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-freelist {{ background-color: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }}
        .badge-slack {{ background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-unallocated {{ background-color: rgba(236, 72, 153, 0.15); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.3); }}
        .badge-wal-insert {{ background-color: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }}
        .badge-wal-update {{ background-color: rgba(6, 182, 212, 0.15); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.3); }}
        .badge-wal-delete {{ background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-journal-insert {{ background-color: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }}
        .badge-journal-update {{ background-color: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.3); }}
        .badge-journal-delete {{ background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-index-active {{ background-color: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
        .badge-index-freeblock {{ background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-index-slack {{ background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-index-unallocated {{ background-color: rgba(236, 72, 153, 0.15); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.3); }}
        .badge-page-reserved-space {{ background-color: rgba(236, 72, 153, 0.2); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.4); }}

        /* Geolocation Badges */
        .geo-badge {{
            display: inline-flex;
            align-items: center;
            gap: 4px;
            background: rgba(34, 197, 94, 0.15);
            border: 1px solid rgba(34, 197, 94, 0.4);
            color: #4ade80;
            padding: 1px 7px;
            border-radius: 4px;
            font-size: 0.76rem;
            font-family: monospace;
            text-decoration: none;
            margin-left: 6px;
            transition: background 0.2s;
        }}
        .geo-badge:hover {{
            background: rgba(34, 197, 94, 0.28);
            text-decoration: underline;
        }}

        /* Evidence Hash Badges */
        .hash-badge {{
            display: inline-flex;
            align-items: center;
            gap: 3px;
            background: rgba(148, 163, 184, 0.12);
            border: 1px solid rgba(148, 163, 184, 0.28);
            color: #94a3b8;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-family: monospace;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .hash-badge:hover {{
            background: rgba(148, 163, 184, 0.25);
            color: #f8fafc;
        }}

        /* Foreign Key Badges */
        .fk-badge {{
            display: inline-flex;
            align-items: center;
            gap: 4px;
            background: rgba(56, 189, 248, 0.12);
            border: 1px solid rgba(56, 189, 248, 0.35);
            color: #38bdf8;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 0.76rem;
            font-family: monospace;
            margin-left: 6px;
            cursor: default;
        }}
        .fk-badge .arrow {{ color: #94a3b8; font-weight: bold; }}
        .fk-badge .target {{ font-weight: 600; color: #bae6fd; }}

        /* Storage Breakdown Card */
        .storage-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 20px;
        }}
        .storage-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            font-weight: 600;
            color: var(--text-primary);
        }}
        .storage-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 12px;
        }}
        .storage-metric {{
            background: rgba(15, 23, 42, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            padding: 10px 14px;
        }}
        .storage-metric .lbl {{
            font-size: 0.72rem;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 700;
        }}
        .storage-metric .val {{
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-top: 3px;
        }}
        .storage-metric .sub {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 1px;
        }}

        .table-name {{
            color: #e2e8f0;
            font-weight: 600;
        }}

        .columns-container {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .col-row {{
            display: flex;
            align-items: baseline;
            gap: 8px;
            font-size: 0.85rem;
            word-break: break-all;
        }}

        .col-label {{
            color: var(--text-muted);
            font-weight: 600;
            min-width: 90px;
        }}

        .col-val {{
            color: var(--text-primary);
        }}

        /* Decoded Blob Boxes */
        .decoded-box {{
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 6px;
            padding: 8px 12px;
            margin-top: 4px;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.8rem;
        }}

        .decoded-tag {{
            font-size: 0.7rem;
            font-weight: 700;
            color: var(--accent);
            text-transform: uppercase;
            margin-bottom: 4px;
        }}

        .highlight {{
            background-color: #fbbf24;
            color: #0f172a;
            padding: 1px 3px;
            border-radius: 2px;
            font-weight: 700;
        }}

        /* WAL Timeline Specific Styles */
        .timeline-container {{
            position: relative;
            padding: 20px 0 20px 40px;
        }}

        .timeline-line {{
            position: absolute;
            left: 19px;
            top: 20px;
            bottom: 20px;
            width: 2px;
            background: var(--border-color);
        }}

        .timeline-item {{
            position: relative;
            margin-bottom: 24px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px 20px;
        }}

        .timeline-item::before {{
            content: '';
            position: absolute;
            left: -28px;
            top: 20px;
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: var(--accent);
            border: 3px solid var(--bg-primary);
        }}

        .timeline-item.wal-insert::before {{ background: #22c55e; }}
        .timeline-item.wal-update::before {{ background: #06b6d4; }}
        .timeline-item.wal-delete::before {{ background: #ef4444; }}

        .timeline-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }}

        .timeline-frame {{
            font-family: monospace;
            font-weight: 700;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        .diff-grid {{
            display: flex;
            flex-direction: column;
            gap: 8px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 0.85rem;
        }}

        .diff-row {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .diff-col-name {{
            font-weight: bold;
            color: var(--accent);
            min-width: 100px;
        }}

        .diff-old {{
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            padding: 2px 6px;
            border-radius: 4px;
            text-decoration: line-through;
        }}

        .diff-new {{
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            padding: 2px 6px;
            border-radius: 4px;
        }}

        .footer {{
            margin-top: 30px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="title-group">
                <h1>🔍 {html.escape(title)}</h1>
                <p id="txt-subtitle">Forensic Database Reconstruction, Deleted Record Recovery & WAL Transaction Diff</p>
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
                <button id="langToggleBtn" onclick="toggleLanguage()" style="background: var(--bg-secondary); border: 1px solid var(--border-color); color: var(--text-primary); padding: 6px 14px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.85rem; display: flex; align-items: center; gap: 6px; transition: all 0.2s;">
                    <span id="langFlag">🇫🇷</span> <span id="langLabel">Français</span>
                </button>
            </div>
        </header>

        <!-- Navigation Tabs -->
        <div class="tabs-nav">
            <button class="tab-btn active" id="btn-tab-evidence" onclick="switchTab('evidence')">
                <span id="tab-title-evidence">📋 All Evidence</span> <span class="tab-badge" id="tab-badge-evidence">{len(serialized_records)}</span>
            </button>
            <button class="tab-btn" id="btn-tab-wal" onclick="switchTab('wal')">
                <span id="tab-title-wal">⏱️ WAL Transaction Timeline</span> <span class="tab-badge" id="tab-badge-wal">{len(wal_mutations)}</span>
            </button>
        </div>

        <!-- TAB 1: ALL EVIDENCE -->
        <div id="pane-evidence" class="tab-pane active">
            <!-- Anti-Forensics Anomaly Alerts Banner -->
            <div id="antiForensicsBanner" style="display: none; margin-bottom: 20px;"></div>

            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card" style="cursor: pointer;" onclick="document.getElementById('sourceFilter').value='all'; applyFilters();" title="Click to show all records">
                    <div class="label" id="lbl-total-records">Total Records</div>
                    <div class="value">{len(serialized_records):,}</div>
                    <div class="sub">All Evidence</div>
                </div>
                <div class="stat-card" style="cursor: pointer;" onclick="document.getElementById('sourceFilter').value='active'; applyFilters();" title="Click to filter by active records">
                    <div class="label" id="lbl-active">Active</div>
                    <div class="value" style="color: var(--color-active);">{total_active_count:,}</div>
                    <div class="sub">{active_sub}</div>
                </div>
                <div class="stat-card" style="cursor: pointer;" onclick="document.getElementById('sourceFilter').value='mutations'; applyFilters();" title="Click to filter by mutated records">
                    <div class="label" id="lbl-mutations">Mutations / Diffs</div>
                    <div class="value" style="color: #eab308;">{mutations_count:,}</div>
                    <div class="sub">Active vs Carved</div>
                </div>
                <div class="stat-card" style="cursor: pointer;" onclick="document.getElementById('sourceFilter').value='freeblock'; applyFilters();" title="Click to filter by freeblocks">
                    <div class="label" id="lbl-freeblocks">Freeblocks</div>
                    <div class="value" style="color: var(--color-freeblock);">{total_freeblock_count:,}</div>
                    <div class="sub">{fb_sub}</div>
                </div>
                <div class="stat-card" style="cursor: pointer;" onclick="document.getElementById('sourceFilter').value='freelist'; applyFilters();" title="Click to filter by freelist records">
                    <div class="label" id="lbl-freelist">Freelist Records</div>
                    <div class="value" style="color: var(--color-freelist);">{freelist_count:,}</div>
                    <div class="sub" id="sub-freelist"></div>
                </div>
                <div class="stat-card" style="cursor: pointer;" onclick="document.getElementById('sourceFilter').value='slack'; applyFilters();" title="Click to filter by slack & unallocated">
                    <div class="label" id="lbl-slack">Slack & Unallocated</div>
                    <div class="value" style="color: var(--color-slack);">{total_slack_count:,}</div>
                    <div class="sub">{slack_sub}</div>
                </div>
                <div class="stat-card" style="cursor: pointer;" onclick="document.getElementById('sourceFilter').value='page_reserved_space'; applyFilters();" title="Click to filter by page reserved space">
                    <div class="label" id="lbl-reserved">Page Reserved Space</div>
                    <div class="value" style="color: #ec4899;">{reserved_count:,}</div>
                    <div class="sub" id="sub-reserved">{reserved_sub}</div>
                </div>
                <div class="stat-card" style="cursor: pointer;" onclick="document.getElementById('sourceFilter').value='wal'; applyFilters();" title="Click to filter by WAL / Journal">
                    <div class="label" id="lbl-wal">WAL & Journal</div>
                    <div class="value" style="color: var(--color-wal);">{len(wal_mutations):,}</div>
                    <div class="sub">Transaction Logs</div>
                </div>
            </div>

            <!-- File Integrity & Hashes Card -->
            <div id="integrityCard" class="storage-card" style="display: none;">
                <div class="storage-header">
                    <span id="lbl-integrity-title">🔐 Cryptographic Chain of Custody & File Integrity Hashes</span>
                </div>
                <div id="integrityGrid" style="display: flex; flex-direction: column; gap: 6px; font-family: monospace; font-size: 0.82rem; color: var(--text-secondary);"></div>
            </div>

            <!-- WAL Shared Memory (.db-shm) Card -->
            <div id="shmCard" class="storage-card" style="display: none;">
                <div class="storage-header">
                    <span id="lbl-shm-title">⚡ WAL Shared Memory Index (.db-shm) Diagnostics</span>
                    <span id="shmSummary" style="font-size: 0.85rem; color: var(--text-secondary);"></span>
                </div>
                <div class="storage-grid" id="shmGrid"></div>
            </div>

            <!-- Storage & Slack Allocation Breakdown -->
            <div id="storageBreakdownCard" class="storage-card" style="display: none;">
                <div class="storage-header">
                    <span id="lbl-storage-title">📊 Storage Allocation & Forensic Slack Breakdown</span>
                    <span id="storageTotalPages" style="font-size: 0.85rem; color: var(--text-secondary);"></span>
                </div>
                <div class="storage-grid">
                    <div class="storage-metric">
                        <div class="lbl" id="lbl-storage-active">Active Data</div>
                        <div class="val" id="storageActiveVal" style="color: var(--color-active);">-</div>
                        <div class="sub" id="sub-storage-active">Allocated B-Tree Cells</div>
                    </div>
                    <div class="storage-metric">
                        <div class="lbl" id="lbl-storage-freeblock">Freeblocks</div>
                        <div class="val" id="storageFreeblockVal" style="color: var(--color-freeblock);">-</div>
                        <div class="sub" id="sub-storage-freeblock">Deleted Linked Blocks</div>
                    </div>
                    <div class="storage-metric">
                        <div class="lbl" id="lbl-storage-unalloc">Unallocated Space</div>
                        <div class="val" id="storageUnallocVal" style="color: var(--color-unallocated);">-</div>
                        <div class="sub" id="sub-storage-unalloc">Cell Pointer Gaps</div>
                    </div>
                    <div class="storage-metric">
                        <div class="lbl" id="lbl-storage-frag">Fragmented Free Slack</div>
                        <div class="val" id="storageFragVal" style="color: var(--color-slack);">-</div>
                        <div class="sub" id="sub-storage-frag">Page Header Offset 7</div>
                    </div>
                    <div class="storage-metric">
                        <div class="lbl" id="lbl-storage-freelist">Freelist Pages</div>
                        <div class="val" id="storageFreelistVal" style="color: var(--color-freelist);">-</div>
                        <div class="sub" id="sub-storage-freelist">Trunk & Leaf Pages</div>
                    </div>
                    <div class="storage-metric" id="storageReservedMetric">
                        <div class="lbl" id="lbl-storage-reserved">Reserved Space</div>
                        <div class="val" id="storageReservedVal" style="color: #ec4899;">-</div>
                        <div class="sub" id="sub-storage-reserved">Steganography / Anti-Forensics</div>
                    </div>
                    <div class="storage-metric">
                        <div class="lbl" id="lbl-storage-totalslack">Total Forensic Slack</div>
                        <div class="val" id="storageTotalSlackVal" style="color: #38bdf8;">-</div>
                        <div class="sub" id="sub-storage-totalslack">Recoverable / Deleted Volume</div>
                    </div>
                </div>
            </div>

            <!-- Controls -->
            <div class="controls-card">
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="Search keywords, flags, emails, tokens (instant live search)...">
                </div>

                <div class="filter-select">
                    <label for="sourceFilter" id="lbl-source-filter">Source:</label>
                    <select id="sourceFilter">
                        <option value="all">All Sources</option>
                        <option value="mutations">🔄 Mutations / Modified Rows Only (Diffs)</option>
                        <option value="active">Active Cells</option>
                        <option value="deleted">Deleted Only (Freeblock, Freelist, Slack, Journals)</option>
                        <option value="freeblock">Freeblocks</option>
                        <option value="freelist">Freelist Records</option>
                        <option value="slack">Slack Space</option>
                        <option value="unallocated">Unallocated</option>
                        <option value="page_reserved_space">🛡️ Page Reserved Space (Steganography)</option>
                        <option value="wal">WAL Transactions</option>
                        <option value="journal">Rollback Journal</option>
                    </select>
                </div>

                <div class="filter-select">
                    <label for="tableFilter" id="lbl-table-filter">Table:</label>
                    <select id="tableFilter">
                        <option value="all">All Tables</option>
                        {"".join(f'<option value="{html.escape(t)}">{html.escape(t)} ({count})</option>' for t, count in sorted(table_stats.items()))}
                    </select>
                </div>

                <div class="confidence-slider">
                    <label for="confSlider"><span id="lbl-min-conf">Min Confidence</span>: <span id="confVal">0.50</span></label>
                    <input type="range" id="confSlider" min="0.0" max="1.0" step="0.05" value="0.50">
                </div>
            </div>

            <!-- Pagination and Table Controls -->
            <div class="pagination-bar" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; font-size: 0.9rem; color: var(--text-secondary);">
                <div id="recordsCount">Showing 0 of 0 records</div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <label for="pageSizeSelect" id="lbl-rows-per-page">Rows per page:</label>
                    <select id="pageSizeSelect" style="background: var(--bg-secondary); color: var(--text-primary); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px;">
                        <option value="50">50</option>
                        <option value="100" selected>100</option>
                        <option value="250">250</option>
                        <option value="500">500</option>
                        <option value="all">All</option>
                    </select>
                    <div style="display: flex; gap: 4px;">
                        <button id="btnPrevPage" class="tab-btn" style="padding: 4px 12px; font-size: 0.85rem;" onclick="changePage(-1)">◀ Prev</button>
                        <span id="pageIndicator" style="display: flex; align-items: center; padding: 0 8px; font-weight: 600; color: var(--text-primary);">Page 1 / 1</span>
                        <button id="btnNextPage" class="tab-btn" style="padding: 4px 12px; font-size: 0.85rem;" onclick="changePage(1)">Next ▶</button>
                    </div>
                </div>
            </div>

            <!-- Table -->
            <div class="table-card">
                <div class="table-container">
                    <table id="recordsTable">
                        <thead>
                            <tr>
                                <th style="width: 70px;" id="th-page">Page</th>
                                <th style="width: 80px;" id="th-offset">Offset</th>
                                <th style="width: 110px;" id="th-source">Source</th>
                                <th style="width: 75px;" id="th-conf">Conf.</th>
                                <th style="width: 140px;" id="th-table">Table</th>
                                <th style="width: 70px;" id="th-rowid">RowID</th>
                                <th id="th-columns">Reconstructed Columns & Decoded Payloads</th>
                            </tr>
                        </thead>
                        <tbody id="tableBody">
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 2: WAL TIMELINE -->
        <div id="pane-wal" class="tab-pane">
            <div class="stat-card" style="margin-bottom: 20px; text-align: left; padding: 18px;">
                <h3 style="color: var(--color-wal); margin-bottom: 6px;" id="txt-wal-title">⏱️ Write-Ahead Log (WAL) Chronological Transaction Diff</h3>
                <p style="color: var(--text-secondary); font-size: 0.9rem;" id="txt-wal-desc">
                    Reconstructs exact transaction order, column modifications, and deleted rows prior to WAL checkpoints.
                </p>
            </div>

            <div class="timeline-container">
                <div class="timeline-line"></div>
                <div id="walTimelineList"></div>
            </div>
        </div>



        <div class="footer">
            <p>SQLite-Carver-Pro v{__version__} | Author: Dam-FOR3K</p>
        </div>
    </div>

    <script>
        const rawData = {json_payload};
        const walData = {wal_payload};
        const storageData = {storage_payload};
        const integrityData = {integrity_payload};
        const shmData = {shm_payload};

        const I18N = {{
            en: {{
                flag: "🇫🇷",
                langBtn: "Français",
                subtitle: "Forensic Database Reconstruction, Deleted Record Recovery & WAL / Journal Transaction Diff",
                tabEvidence: "📋 All Evidence",
                tabWal: "⏱️ WAL & Journal Timeline",
                totalRecords: "Total Records",
                active: "Active",
                mutations: "Mutations / Diffs",
                freeblocks: "Freeblocks",
                freelist: "Freelist Records",
                freelistPagesSub: (p) => `${{p.toLocaleString()}} ${{p === 1 ? 'page' : 'pages'}}`,
                slack: "Slack & Unallocated",
                reserved: "Page Reserved Space",
                reservedSub: (b) => b > 0 ? `${{b}} B/page` : "Steganography / Slack",
                walMutations: "WAL & Journal",

                integrityTitle: "🔐 Cryptographic Chain of Custody & File Integrity Hashes",
                
                shmTitle: "⚡ WAL Shared Memory Index (.db-shm) Diagnostics",
                shmActiveReaders: "active reader(s)",
                shmPageSize: "Page Size",
                shmPageSizeSub: "SHM Header",
                shmMaxWalFrame: "Max WAL Frame",
                shmMaxWalFrameSub: "WAL Index mxFrame",
                shmDatabasePages: "Database Pages",
                shmDatabasePagesSub: "SHM nPage",
                shmCheckpointSeq: "Checkpoint Seq",
                shmCheckpointSeqSub: "aFrame[0]",
                shmCheckpointBackfill: "Checkpoint Backfill",
                shmCheckpointBackfillSub: "aFrame[1]",

                storageTitle: "📊 Storage Allocation & Forensic Slack Breakdown",
                storageActive: "Active Data",
                storageActiveSub: "Allocated B-Tree Cells",
                storageFreeblocks: "Freeblocks",
                storageFreeblocksSub: "Deleted Linked Blocks",
                storageUnalloc: "Unallocated Space",
                storageUnallocSub: "Cell Pointer Gaps",
                storageFrag: "Fragmented Free Slack",
                storageFragSub: "Page Header Offset 7",
                storageFreelist: "Freelist Pages",
                storageFreelistSub: "Trunk & Leaf Pages",
                storageReserved: "Reserved Space",
                storageReservedSub: "Per-page Anti-Forensics / Steganography",
                storageTotalSlack: "Total Forensic Slack",
                storageTotalSlackSub: "Recoverable / Deleted Volume",

                searchPlaceholder: "Search keywords, flags, emails, tokens (instant live search)...",
                sourceLabel: "Source:",
                sourceAll: "All Sources",
                sourceMutations: "🔄 Mutations / Modified Rows Only (Diffs)",
                sourceActive: "Active Cells",
                sourceDeleted: "Deleted Only (Freeblock, Freelist, Slack, Journals)",
                sourceFreeblock: "Freeblocks",
                sourceFreelist: "Freelist Records",
                sourceSlack: "Slack Space",
                sourceUnallocated: "Unallocated",
                sourceReserved: "🛡️ Page Reserved Space (Steganography)",
                sourceWal: "WAL Transactions",
                sourceJournal: "Rollback Journal",
                tableLabel: "Table:",
                tableAll: "All Tables",
                minConf: "Min Confidence",
                rowsPerPage: "Rows per page:",
                btnPrev: "◀ Prev",
                btnNext: "Next ▶",
                thPage: "Page",
                thOffset: "Offset",
                thSource: "Source",
                thConf: "Conf.",
                thTable: "Table",
                thRowId: "RowID",
                thColumns: "Reconstructed Columns & Decoded Payloads",
                walTitle: "⏱️ Chronological Transaction Diff (WAL & Rollback Journal)",
                walDesc: "Reconstructs exact transaction order, column modifications, and deleted rows from WAL frames and Rollback Journal records.",
                noWal: "No WAL or Rollback Journal transactions recorded.",
                noRecords: "No matching records found.",
                showingRecords: (s, e, t) => `Showing ${{s}}-${{e}} of ${{t.toLocaleString()}} records`,
                showingZero: "Showing 0 records",
                pageOf: (c, t) => `Page ${{c}} / ${{t}}`,
                afAlertTitle: "Anti-Forensics & Tampering Anomalies Detected",
            }},
            fr: {{
                flag: "🇬🇧",
                langBtn: "English",
                subtitle: "Reconstruction Forensique, Carving de Cellules Supprimées & Diff WAL / Journal",
                tabEvidence: "📋 Toutes les Preuves",
                tabWal: "⏱️ Timeline WAL & Journal",
                totalRecords: "Total Enregistrements",
                active: "Actifs",
                mutations: "Mutations / Diffs",
                freeblocks: "Freeblocks",
                freelist: "Enregistrements Freelist",
                freelistPagesSub: (p) => `${{p.toLocaleString()}} ${{p === 1 || p === 0 ? 'page' : 'pages'}}`,
                slack: "Slack & Non-Alloué",
                reserved: "Espace Réservé",
                reservedSub: (b) => b > 0 ? `${{b}} octets/page` : "Stéganographie / Slack",
                walMutations: "WAL & Journal",

                integrityTitle: "🔐 Chaîne de Garde Cryptographique & Intégrité des Fichiers",

                shmTitle: "⚡ Diagnostic de la Mémoire Partagée WAL (.db-shm)",
                shmActiveReaders: "lecteur(s) actif(s)",
                shmPageSize: "Taille de Page",
                shmPageSizeSub: "En-tête SHM",
                shmMaxWalFrame: "Frame WAL Max",
                shmMaxWalFrameSub: "Index WAL mxFrame",
                shmDatabasePages: "Pages de Base",
                shmDatabasePagesSub: "SHM nPage",
                shmCheckpointSeq: "Séquence Checkpoint",
                shmCheckpointSeqSub: "aFrame[0]",
                shmCheckpointBackfill: "Remplissage Checkpoint",
                shmCheckpointBackfillSub: "aFrame[1]",

                storageTitle: "📊 Répartition du Stockage & Slack Forensique",
                storageActive: "Données Actives",
                storageActiveSub: "Cellules B-Tree Allouées",
                storageFreeblocks: "Freeblocks",
                storageFreeblocksSub: "Blocs Chaînés Supprimés",
                storageUnalloc: "Espace Non-Alloué",
                storageUnallocSub: "Intervalles de Pointeurs",
                storageFrag: "Slack Fragmenté",
                storageFragSub: "En-tête de Page Offset 7",
                storageFreelist: "Pages Freelist",
                storageFreelistSub: "Pages Troncs & Feuilles",
                storageReserved: "Espace Réservé",
                storageReservedSub: "Stéganographie / Anti-Forensics",
                storageTotalSlack: "Total Slack Forensique",
                storageTotalSlackSub: "Volume Récupérable / Supprimé",

                searchPlaceholder: "Rechercher mots-clés, tokens, emails, flags (recherche instantanée)...",
                sourceLabel: "Source :",
                sourceAll: "Toutes les sources",
                sourceMutations: "🔄 Mutations / Lignes Modifiées (Diffs)",
                sourceActive: "Cellules Actives",
                sourceDeleted: "Supprimés uniquement (Freeblock, Freelist, Slack, Journaux)",
                sourceFreeblock: "Freeblocks",
                sourceFreelist: "Enregistrements Freelist",
                sourceSlack: "Slack Space",
                sourceUnallocated: "Espace Non-Alloué",
                sourceReserved: "🛡️ Espace Réservé (Stéganographie)",
                sourceWal: "Transactions WAL",
                sourceJournal: "Journal Rollback",
                tableLabel: "Table :",
                tableAll: "Toutes les tables",
                minConf: "Confiance Min",
                rowsPerPage: "Lignes par page :",
                btnPrev: "◀ Préc",
                btnNext: "Suiv ▶",
                thPage: "Page",
                thOffset: "Offset",
                thSource: "Source",
                thConf: "Conf.",
                thTable: "Table",
                thRowId: "RowID",
                thColumns: "Colonnes Reconstruites & Données Décodées",
                walTitle: "⏱️ Chronologie des Transactions (WAL & Rollback Journal)",
                walDesc: "Reconstitue l'historique des transactions, colonnes modifiées et lignes supprimées depuis les trames WAL et journaux rollback.",
                noWal: "Aucune transaction WAL ou Rollback Journal enregistrée.",
                noRecords: "Aucun enregistrement correspondant trouvé.",
                showingRecords: (s, e, t) => `Affichage ${{s}}-${{e}} sur ${{t.toLocaleString()}} enregistrements`,
                showingZero: "Affichage 0 enregistrement",
                pageOf: (c, t) => `Page ${{c}} sur ${{t}}`,
                afAlertTitle: "Anomalies Anti-Forensics & Altérations Détectées",
            }}
        }};

        let currentLang = '{active_lang}';

        function toggleLanguage() {{
            currentLang = currentLang === 'en' ? 'fr' : 'en';
            applyLanguage();
        }}

        function applyLanguage() {{
            const lang = I18N[currentLang];
            document.getElementById('langFlag').textContent = lang.flag;
            document.getElementById('langLabel').textContent = lang.langBtn;
            document.getElementById('txt-subtitle').textContent = lang.subtitle;
            document.getElementById('tab-title-evidence').textContent = lang.tabEvidence;
            document.getElementById('tab-title-wal').textContent = lang.tabWal;
            
            document.getElementById('lbl-total-records').textContent = lang.totalRecords;
            document.getElementById('lbl-active').textContent = lang.active;
            const lblMut = document.getElementById('lbl-mutations'); if (lblMut) lblMut.textContent = lang.mutations;
            document.getElementById('lbl-freeblocks').textContent = lang.freeblocks;
            document.getElementById('lbl-freelist').textContent = lang.freelist;
            const subFl = document.getElementById('sub-freelist');
            if (subFl) {{
                const flCount = (typeof storageData !== 'undefined' && storageData && storageData.freelist_pages_count !== undefined) ? storageData.freelist_pages_count : null;
                subFl.textContent = (flCount !== null) ? lang.freelistPagesSub(flCount) : '';
            }}
            document.getElementById('lbl-slack').textContent = lang.slack;
            const lblRes = document.getElementById('lbl-reserved');
            if (lblRes) lblRes.textContent = lang.reserved;
            const subRes = document.getElementById('sub-reserved');
            if (subRes) {{
                const resB = (typeof storageData !== 'undefined' && storageData && storageData.reserved_space_per_page !== undefined) ? storageData.reserved_space_per_page : 0;
                subRes.textContent = lang.reservedSub(resB);
            }}
            document.getElementById('lbl-wal').textContent = lang.walMutations;

            // Integrity Card
            const lblIntegrity = document.getElementById('lbl-integrity-title');
            if (lblIntegrity) lblIntegrity.textContent = lang.integrityTitle;

            // SHM Card
            const lblShm = document.getElementById('lbl-shm-title');
            if (lblShm) lblShm.textContent = lang.shmTitle;

            // Storage Breakdown Card
            const lblStorage = document.getElementById('lbl-storage-title');
            if (lblStorage) lblStorage.textContent = lang.storageTitle;
            if (document.getElementById('lbl-storage-active')) document.getElementById('lbl-storage-active').textContent = lang.storageActive;
            if (document.getElementById('sub-storage-active')) document.getElementById('sub-storage-active').textContent = lang.storageActiveSub;
            if (document.getElementById('lbl-storage-freeblock')) document.getElementById('lbl-storage-freeblock').textContent = lang.storageFreeblocks;
            if (document.getElementById('sub-storage-freeblock')) document.getElementById('sub-storage-freeblock').textContent = lang.storageFreeblocksSub;
            if (document.getElementById('lbl-storage-unalloc')) document.getElementById('lbl-storage-unalloc').textContent = lang.storageUnalloc;
            if (document.getElementById('sub-storage-unalloc')) document.getElementById('sub-storage-unalloc').textContent = lang.storageUnallocSub;
            if (document.getElementById('lbl-storage-frag')) document.getElementById('lbl-storage-frag').textContent = lang.storageFrag;
            if (document.getElementById('sub-storage-frag')) document.getElementById('sub-storage-frag').textContent = lang.storageFragSub;
            if (document.getElementById('lbl-storage-freelist')) document.getElementById('lbl-storage-freelist').textContent = lang.storageFreelist;
            if (document.getElementById('sub-storage-freelist')) document.getElementById('sub-storage-freelist').textContent = lang.storageFreelistSub;
            if (document.getElementById('lbl-storage-reserved')) document.getElementById('lbl-storage-reserved').textContent = lang.storageReserved;
            if (document.getElementById('sub-storage-reserved')) document.getElementById('sub-storage-reserved').textContent = lang.storageReservedSub;
            if (document.getElementById('lbl-storage-totalslack')) document.getElementById('lbl-storage-totalslack').textContent = lang.storageTotalSlack;
            if (document.getElementById('sub-storage-totalslack')) document.getElementById('sub-storage-totalslack').textContent = lang.storageTotalSlackSub;
            
            document.getElementById('searchInput').placeholder = lang.searchPlaceholder;
            document.getElementById('lbl-source-filter').textContent = lang.sourceLabel;
            document.getElementById('lbl-table-filter').textContent = lang.tableLabel;
            document.getElementById('lbl-min-conf').textContent = lang.minConf;
            document.getElementById('lbl-rows-per-page').textContent = lang.rowsPerPage;

            // Source Filter Options
            const optAll = document.querySelector('#sourceFilter option[value="all"]'); if (optAll) optAll.textContent = lang.sourceAll;
            const optMut = document.querySelector('#sourceFilter option[value="mutations"]'); if (optMut) optMut.textContent = lang.sourceMutations;
            const optAct = document.querySelector('#sourceFilter option[value="active"]'); if (optAct) optAct.textContent = lang.sourceActive;
            const optDel = document.querySelector('#sourceFilter option[value="deleted"]'); if (optDel) optDel.textContent = lang.sourceDeleted;
            const optFb = document.querySelector('#sourceFilter option[value="freeblock"]'); if (optFb) optFb.textContent = lang.sourceFreeblock;
            const optFl = document.querySelector('#sourceFilter option[value="freelist"]'); if (optFl) optFl.textContent = lang.sourceFreelist;
            const optSl = document.querySelector('#sourceFilter option[value="slack"]'); if (optSl) optSl.textContent = lang.sourceSlack;
            const optUn = document.querySelector('#sourceFilter option[value="unallocated"]'); if (optUn) optUn.textContent = lang.sourceUnallocated;
            const optRes = document.querySelector('#sourceFilter option[value="page_reserved_space"]'); if (optRes) optRes.textContent = lang.sourceReserved;
            const optWal = document.querySelector('#sourceFilter option[value="wal"]'); if (optWal) optWal.textContent = lang.sourceWal;
            const optJ = document.querySelector('#sourceFilter option[value="journal"]'); if (optJ) optJ.textContent = lang.sourceJournal;

            const optTblAll = document.querySelector('#tableFilter option[value="all"]'); if (optTblAll) optTblAll.textContent = lang.tableAll;

            // Pagination Buttons
            const btnPrev = document.getElementById('btnPrevPage'); if (btnPrev) btnPrev.textContent = lang.btnPrev;
            const btnNext = document.getElementById('btnNextPage'); if (btnNext) btnNext.textContent = lang.btnNext;
            
            document.getElementById('th-page').textContent = lang.thPage;
            document.getElementById('th-offset').textContent = lang.thOffset;
            document.getElementById('th-source').textContent = lang.thSource;
            document.getElementById('th-conf').textContent = lang.thConf;
            document.getElementById('th-table').textContent = lang.thTable;
            document.getElementById('th-rowid').textContent = lang.thRowId;
            document.getElementById('th-columns').textContent = lang.thColumns;
            
            document.getElementById('txt-wal-title').textContent = lang.walTitle;
            document.getElementById('txt-wal-desc').textContent = lang.walDesc;

            if (integrityData && Object.keys(integrityData).length > 0) {{
                const card = document.getElementById('integrityCard');
                const grid = document.getElementById('integrityGrid');
                let hasEntries = false;
                grid.innerHTML = '';
                for (const [k, v] of Object.entries(integrityData)) {{
                    if (v && v.sha256) {{
                        hasEntries = true;
                        grid.innerHTML += `<div style="display: flex; flex-wrap: wrap; justify-content: space-between; padding: 4px 8px; background: rgba(15,23,42,0.4); border-radius: 4px;">
                            <span><strong>${{escapeHtml(v.filename || k)}}</strong> (${{v.size_bytes ? v.size_bytes.toLocaleString() : 0}} B):</span>
                            <span>SHA-256: <code style="color:#4ade80;">${{v.sha256}}</code> | MD5: <code style="color:#94a3b8;">${{v.md5}}</code></span>
                        </div>`;
                    }}
                }}
                if (hasEntries) card.style.display = 'block';
            }}

            if (shmData && shmData.has_shm) {{
                const scard = document.getElementById('shmCard');
                const sgrid = document.getElementById('shmGrid');
                scard.style.display = 'block';
                document.getElementById('shmSummary').textContent = `${{shmData.active_readers_count}} ${{lang.shmActiveReaders}}`;
                sgrid.innerHTML = `
                    <div class="storage-metric"><div class="lbl">${{lang.shmPageSize}}</div><div class="val" style="color:var(--accent);">${{shmData.page_size}} B</div><div class="sub">${{lang.shmPageSizeSub}}</div></div>
                    <div class="storage-metric"><div class="lbl">${{lang.shmMaxWalFrame}}</div><div class="val" style="color:var(--color-wal);">${{shmData.max_wal_frame.toLocaleString()}}</div><div class="sub">${{lang.shmMaxWalFrameSub}}</div></div>
                    <div class="storage-metric"><div class="lbl">${{lang.shmDatabasePages}}</div><div class="val" style="color:var(--color-active);">${{shmData.database_pages.toLocaleString()}}</div><div class="sub">${{lang.shmDatabasePagesSub}}</div></div>
                    <div class="storage-metric"><div class="lbl">${{lang.shmCheckpointSeq}}</div><div class="val" style="color:var(--color-slack);">${{shmData.checkpoint_sequence}}</div><div class="sub">${{lang.shmCheckpointSeqSub}}</div></div>
                    <div class="storage-metric"><div class="lbl">${{lang.shmCheckpointBackfill}}</div><div class="val" style="color:var(--color-freelist);">${{shmData.checkpoint_backfill}}</div><div class="sub">${{lang.shmCheckpointBackfillSub}}</div></div>
                `;
            }}

            if (storageData && storageData.total_pages) {{
                document.getElementById('storageBreakdownCard').style.display = 'block';
                const fmtB = (b) => {{
                    if (!b || b === 0) return '0 B';
                    const k = 1024;
                    const sizes = ['B', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(b) / Math.log(k));
                    return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                }};
                document.getElementById('storageTotalPages').textContent = `${{storageData.total_pages.toLocaleString()}} pages (${{fmtB(storageData.total_bytes)}})`;
                document.getElementById('storageActiveVal').textContent = fmtB(storageData.active_bytes);
                document.getElementById('storageFreeblockVal').textContent = fmtB(storageData.freeblock_bytes);
                document.getElementById('storageUnallocVal').textContent = fmtB(storageData.unallocated_bytes);
                document.getElementById('storageFragVal').textContent = fmtB(storageData.fragmented_free_bytes);
                document.getElementById('storageFreelistVal').textContent = `${{storageData.freelist_pages_count}} pgs (${{fmtB(storageData.freelist_bytes)}})`;
                const resMetric = document.getElementById('storageReservedMetric');
                if (resMetric) {{
                    const resBytes = storageData.reserved_space_bytes || 0;
                    const resPerPg = storageData.reserved_space_per_page || 0;
                    const resValEl = document.getElementById('storageReservedVal');
                    if (resValEl) {{
                        if (resBytes > 0) {{
                            resValEl.textContent = `${{resPerPg}} B/pg (${{fmtB(resBytes)}})`;
                            resValEl.style.color = '#ec4899';
                        }} else {{
                            resValEl.textContent = '0 B';
                            resValEl.style.color = 'var(--text-secondary)';
                        }}
                    }}
                }}
                document.getElementById('storageTotalSlackVal').textContent = fmtB(storageData.total_slack_bytes);
            }}

            renderPage();
            renderWalTimeline();
        }}

        // Pre-index lowercase search strings for ultra-fast filtering
        for (let i = 0; i < rawData.length; i++) {{
            rawData[i]._searchIndex = JSON.stringify(rawData[i]).toLowerCase();
        }}

        let currentPage = 1;
        let pageSize = 100;
        let currentFilteredData = rawData;
        let searchTimeout = null;

        // Tab Switching
        function switchTab(tabId) {{
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
            
            if (tabId === 'evidence') {{
                const b = document.getElementById('btn-tab-evidence'); if (b) b.classList.add('active');
                document.getElementById('pane-evidence').classList.add('active');
                applyFilters();
            }} else if (tabId === 'wal') {{
                const b = document.getElementById('btn-tab-wal'); if (b) b.classList.add('active');
                document.getElementById('pane-wal').classList.add('active');
                renderWalTimeline();
            }}
        }}

        // Evidence Table Controls
        const searchInput = document.getElementById('searchInput');
        const sourceFilter = document.getElementById('sourceFilter');
        const tableFilter = document.getElementById('tableFilter');
        const confSlider = document.getElementById('confSlider');
        const confVal = document.getElementById('confVal');
        const pageSizeSelect = document.getElementById('pageSizeSelect');
        const tableBody = document.getElementById('tableBody');
        const recordsCount = document.getElementById('recordsCount');
        const pageIndicator = document.getElementById('pageIndicator');
        const btnPrevPage = document.getElementById('btnPrevPage');
        const btnNextPage = document.getElementById('btnNextPage');

        confSlider.addEventListener('input', () => {{
            confVal.textContent = parseFloat(confSlider.value).toFixed(2);
            currentPage = 1;
            applyFilters();
        }});

        searchInput.addEventListener('input', () => {{
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {{
                currentPage = 1;
                applyFilters();
            }}, 120);
        }});

        sourceFilter.addEventListener('change', () => {{
            currentPage = 1;
            applyFilters();
        }});

        tableFilter.addEventListener('change', () => {{
            currentPage = 1;
            applyFilters();
        }});

        pageSizeSelect.addEventListener('change', () => {{
            const val = pageSizeSelect.value;
            pageSize = val === 'all' ? rawData.length : parseInt(val, 10);
            currentPage = 1;
            renderPage();
        }});

        function changePage(delta) {{
            const totalPages = Math.max(1, Math.ceil(currentFilteredData.length / pageSize));
            const newPage = currentPage + delta;
            if (newPage >= 1 && newPage <= totalPages) {{
                currentPage = newPage;
                renderPage();
            }}
        }}

        function highlightText(text, query) {{
            if (!query || typeof text !== 'string') return escapeHtml(String(text));
            const escapedText = escapeHtml(text);
            const escapedQuery = escapeHtml(query);
            const regex = new RegExp(`(${{escapedQuery.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&')}})`, 'gi');
            return escapedText.replace(regex, '<span class="highlight">$1</span>');
        }}

        function escapeHtml(str) {{
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }}

        function renderValue(val, query) {{
            if (val === null || val === undefined) return '<span style="color: var(--text-muted);">NULL</span>';
            
            if (typeof val === 'object' && val._blob_format) {{
                let decodedStr = '';
                if (typeof val._decoded === 'object') {{
                    decodedStr = JSON.stringify(val._decoded, null, 2);
                }} else {{
                    decodedStr = String(val._decoded);
                }}
                return `
                    <div class="decoded-box">
                        <div class="decoded-tag">📦 [${{val._blob_format}}]</div>
                        <pre style="margin: 0; white-space: pre-wrap; word-break: break-all;">${{highlightText(decodedStr, query)}}</pre>
                    </div>
                `;
            }}

            if (typeof val === 'object') {{
                return `<pre style="margin: 0; white-space: pre-wrap;">${{highlightText(JSON.stringify(val, null, 2), query)}}</pre>`;
            }}

            return highlightText(String(val), query);
        }}

        function applyFilters() {{
            const query = searchInput.value.trim().toLowerCase();
            const src = sourceFilter.value;
            const tbl = tableFilter.value;
            const minConf = parseFloat(confSlider.value);

            currentFilteredData = rawData.filter(item => {{
                if (item.confidence !== undefined && item.confidence < minConf) return false;
                
                const itemSrc = (item.source || (item.mutation_type ? `wal_${{item.mutation_type.toLowerCase()}}` : '')).toLowerCase();
                const isActive = itemSrc.includes('active');
                if (src === 'mutations' && !item.is_mutation) return false;
                if (src === 'active' && !isActive) return false;
                if (src === 'deleted' && isActive) return false;
                if (src === 'freeblock' && !itemSrc.includes('freeblock')) return false;
                if (src === 'freelist' && !itemSrc.includes('freelist')) return false;
                if (src === 'slack' && (!itemSrc.includes('slack') && !itemSrc.includes('unallocated'))) return false;
                if (src === 'unallocated' && !itemSrc.includes('unallocated')) return false;
                if (src === 'page_reserved_space' && !itemSrc.includes('reserved_space')) return false;
                if (src === 'wal' && !itemSrc.includes('wal')) return false;
                if (src === 'journal' && !itemSrc.includes('journal')) return false;

                const itemTable = (item.matched_table || item.table_name || '').toLowerCase();
                if (tbl !== 'all' && itemTable !== tbl.toLowerCase()) return false;

                if (query) {{
                    return item._searchIndex && item._searchIndex.includes(query);
                }}

                return true;
            }});

            renderPage();
        }}

        function renderPage() {{
            const lang = I18N[currentLang];
            const query = searchInput.value.trim().toLowerCase();
            const total = currentFilteredData.length;
            const totalPages = Math.max(1, Math.ceil(total / pageSize));
            if (currentPage > totalPages) currentPage = totalPages;

            const startIdx = (currentPage - 1) * pageSize;
            const endIdx = Math.min(startIdx + pageSize, total);
            const pageRecords = currentFilteredData.slice(startIdx, endIdx);

            recordsCount.textContent = total > 0 
                ? lang.showingRecords(startIdx + 1, endIdx, total)
                : lang.showingZero;

            pageIndicator.textContent = lang.pageOf(currentPage, totalPages);
            btnPrevPage.disabled = (currentPage <= 1);
            btnNextPage.disabled = (currentPage >= totalPages);

            let rowsHtml = '';
            for (let i = 0; i < pageRecords.length; i++) {{
                const item = pageRecords[i];
                const pageId = item.page_id !== undefined ? item.page_id : '-';
                const offset = item.offset_in_page !== undefined ? '0x' + item.offset_in_page.toString(16) : '-';
                const source = item.source || (item.mutation_type ? `${{item.journal_source || 'wal'}}_${{item.mutation_type.toLowerCase()}}` : 'unknown');
                const conf = item.confidence !== undefined ? item.confidence.toFixed(2) : '1.00';
                const table = item.matched_table || item.table_name || '?';
                const rowid = item.rowid !== undefined && item.rowid !== null ? item.rowid : '?';

                let badgeClass = 'badge-active';
                if (source.includes('index_active')) badgeClass = 'badge-index-active';
                else if (source.includes('index_freeblock')) badgeClass = 'badge-index-freeblock';
                else if (source.includes('index_slack')) badgeClass = 'badge-index-slack';
                else if (source.includes('index_unallocated')) badgeClass = 'badge-index-unallocated';
                else if (source.includes('freeblock')) badgeClass = 'badge-freeblock';
                else if (source.includes('freelist')) badgeClass = 'badge-freelist';
                else if (source.includes('slack')) badgeClass = 'badge-slack';
                else if (source.includes('unallocated')) badgeClass = 'badge-unallocated';
                else if (source.includes('reserved_space')) badgeClass = 'badge-page-reserved-space';
                else if (source.includes('journal_insert')) badgeClass = 'badge-journal-insert';
                else if (source.includes('journal_update')) badgeClass = 'badge-journal-update';
                else if (source.includes('journal_delete')) badgeClass = 'badge-journal-delete';
                else if (source.includes('wal_insert')) badgeClass = 'badge-wal-insert';
                else if (source.includes('wal_update')) badgeClass = 'badge-wal-update';
                else if (source.includes('wal_delete')) badgeClass = 'badge-wal-delete';

                let colsHtml = '<div class="columns-container">';
                if (item.columns) {{
                    for (const [k, v] of Object.entries(item.columns)) {{
                        let diffBadge = '';
                        if (item.mutation_diff && item.mutation_diff[k]) {{
                            const dVal = item.mutation_diff[k];
                            diffBadge = ` <span title="Current active row had '${{escapeHtml(String(dVal.active))}}'" style="display:inline-block; font-size:0.75rem; background:rgba(234,179,8,0.2); color:#eab308; border:1px solid rgba(234,179,8,0.4); border-radius:3px; padding:0 4px; margin-left:4px; font-weight:600;">🔄 Active: ${{renderValue(dVal.active, query)}}</span>`;
                        }}
                        let tsBadge = '';
                        if (item._timestamps && item._timestamps[k]) {{
                            const ts = item._timestamps[k];
                            tsBadge = ` <span title="${{escapeHtml(ts.description)}}" style="display:inline-block; font-size:0.75rem; background:rgba(56,189,248,0.15); color:#38bdf8; border:1px solid rgba(56,189,248,0.3); border-radius:3px; padding:0 4px; margin-left:4px; font-family: monospace;">📅 ${{escapeHtml(ts.iso_utc)}}</span>`;
                        }}
                        let fkBadge = '';
                        if (item._foreign_keys && item._foreign_keys[k]) {{
                            const fk = item._foreign_keys[k];
                            fkBadge = ` <span class="fk-badge" title="Resolved Foreign Key: ${{escapeHtml(fk.target_table)}}.${{escapeHtml(fk.target_column)}} = ${{fk.target_id}}"><span class="arrow">➔</span> <span class="target">${{escapeHtml(fk.target_table)}}:</span> <strong>${{escapeHtml(fk.display_value)}}</strong></span>`;
                        }}
                        colsHtml += `
                            <div class="col-row">
                                <span class="col-label">${{escapeHtml(k)}}:</span>
                                <span class="col-val">${{renderValue(v, query)}}${{diffBadge}}${{fkBadge}}${{tsBadge}}</span>
                            </div>
                        `;
                    }}
                }} else if (item.column_diffs) {{
                    for (const diff of item.column_diffs) {{
                        colsHtml += `
                            <div class="col-row">
                                <span class="col-label">${{escapeHtml(diff.column)}}:</span>
                                <span class="col-val"><span style="color: #ef4444;">${{renderValue(diff.old, query)}}</span> ➔ <span style="color: #22c55e;">${{renderValue(diff.new, query)}}</span></span>
                            </div>
                        `;
                    }}
                }} else if (item.raw_values) {{
                    item.raw_values.forEach((v, idx) => {{
                        colsHtml += `
                            <div class="col-row">
                                <span class="col-label">c${{idx}}:</span>
                                <span class="col-val">${{renderValue(v, query)}}</span>
                            </div>
                        `;
                    }});
                }}
                colsHtml += '</div>';

                let extraBadges = '';
                if (item.is_mutation) {{
                    extraBadges += ` <span class="badge" style="background: rgba(234,179,8,0.2); color: #eab308; border: 1px solid rgba(234,179,8,0.4); font-weight: bold;">🔄 HISTORICAL MUTATION (DIFF)</span>`;
                }}
                if (item._geo) {{
                    const altStr = (item._geo.altitude !== null && item._geo.altitude !== undefined) ? ` (${{item._geo.altitude}}m)` : '';
                    extraBadges += ` <a href="${{escapeHtml(item._geo.url)}}" target="_blank" rel="noopener noreferrer" class="geo-badge" title="Open GPS location in OpenStreetMap">📍 ${{item._geo.latitude.toFixed(5)}}, ${{item._geo.longitude.toFixed(5)}}${{altStr}}</a>`;
                }}
                if (item._evidence_hash) {{
                    extraBadges += ` <span class="hash-badge" title="Record SHA-256: ${{item._evidence_hash}}">🔐 ${{item._evidence_hash.substring(0, 8)}}</span>`;
                }}

                rowsHtml += `
                    <tr>
                        <td style="color: var(--text-muted);">${{pageId}}</td>
                        <td style="font-family: monospace; color: var(--text-muted);">${{offset}}</td>
                        <td><span class="badge ${{badgeClass}}">${{escapeHtml(source)}}</span></td>
                        <td style="font-weight: 600;">${{conf}}</td>
                        <td><span class="table-name">${{escapeHtml(table)}}</span></td>
                        <td style="color: var(--accent);">${{rowid}}</td>
                        <td>${{colsHtml}}${{extraBadges ? `<div style="margin-top: 6px;">${{extraBadges}}</div>` : ''}}</td>
                    </tr>
                `;
            }}

            if (pageRecords.length === 0) {{
                rowsHtml = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">${{lang.noRecords}}</td></tr>`;
            }}

            tableBody.innerHTML = rowsHtml;
        }}

        // WAL Timeline Rendering
        function renderWalTimeline() {{
            const lang = I18N[currentLang];
            const listContainer = document.getElementById('walTimelineList');
            if (!walData || walData.length === 0) {{
                listContainer.innerHTML = `<div class="stat-card" style="text-align: center; color: var(--text-muted); padding: 30px;">${{lang.noWal}}</div>`;
                return;
            }}

            let timelineHtml = '';
            for (const mut of walData) {{
                const type = mut.mutation_type;
                const typeClass = `wal-${{type.toLowerCase()}}`;
                const isCommitBadge = mut.is_commit ? '<span class="badge" style="background: rgba(56, 189, 248, 0.2); color: #38bdf8;">COMMIT</span>' : '';
                const walOnlyBadge = mut.is_wal_only_table ? '<span class="badge" style="background: rgba(236, 72, 153, 0.2); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.4);">★ WAL-ONLY TABLE</span>' : '';
                let diffStateBadge = '';
                if (mut.diff_state === 'wal_only') {{
                    diffStateBadge = '<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24;">∅ WAL ONLY</span>';
                }} else if (mut.diff_state === 'diff_from_db') {{
                    diffStateBadge = '<span class="badge" style="background: rgba(168, 85, 247, 0.2); color: #c084fc;">≠ MODIFIED</span>';
                }}
                
                let diffContentHtml = '';
                if (type === 'UPDATE' && mut.column_diffs && mut.column_diffs.length > 0) {{
                    diffContentHtml = '<div class="diff-grid">';
                    for (const d of mut.column_diffs) {{
                        diffContentHtml += `
                            <div class="diff-row">
                                <span class="diff-col-name">${{escapeHtml(d.column)}}:</span>
                                <span class="diff-old">${{escapeHtml(JSON.stringify(d.old))}}</span>
                                <span style="color: var(--text-muted);">➔</span>
                                <span class="diff-new">${{escapeHtml(JSON.stringify(d.new))}}</span>
                            </div>
                        `;
                    }}
                    diffContentHtml += '</div>';
                }} else if (type === 'INSERT' && mut.new_values) {{
                    diffContentHtml = `<div class="diff-grid"><div class="diff-row"><span style="color: #4ade80;">+ Row inserted:</span> ${{escapeHtml(JSON.stringify(mut.new_values))}}</div></div>`;
                }} else if (type === 'DELETE' && mut.old_values) {{
                    diffContentHtml = `<div class="diff-grid"><div class="diff-row"><span style="color: #f87171;">- Row deleted:</span> ${{escapeHtml(JSON.stringify(mut.old_values))}}</div></div>`;
                }}

                const isJournal = mut.journal_source === 'rollback_journal';
                const srcLabel = isJournal ? 'Rollback Journal' : 'WAL';
                const srcBadge = isJournal 
                    ? '<span class="badge" style="background: rgba(14, 165, 233, 0.2); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.4);">ROLLBACK JOURNAL</span>' 
                    : '<span class="badge" style="background: rgba(6, 182, 212, 0.2); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.4);">WAL</span>';

                timelineHtml += `
                    <div class="timeline-item ${{typeClass}}">
                        <div class="timeline-header">
                            <span class="timeline-frame">${{srcLabel}} Frame #${{mut.frame_index}} (Page ${{mut.page_id}})</span>
                            ${{srcBadge}}
                            <span class="badge badge-${{typeClass}}">${{type}}</span>
                            ${{isCommitBadge}}
                            ${{walOnlyBadge}}
                            ${{diffStateBadge}}
                            <span style="color: var(--text-secondary); font-size: 0.9rem;">Table: <strong style="color: #f8fafc;">${{escapeHtml(mut.table_name || 'Unknown')}}</strong></span>
                            <span style="color: var(--text-muted); font-size: 0.85rem; margin-left: auto;">RowID: <strong style="color: var(--accent);">${{mut.rowid !== null ? mut.rowid : '?'}}</strong></span>
                        </div>
                        ${{diffContentHtml}}
                    </div>
                `;
            }}

            listContainer.innerHTML = timelineHtml;
        }}

        // ==========================================
        // ANTI-FORENSICS & TAMPERING ALERT BANNER
        // ==========================================
        function renderAntiForensicsBanner() {{
            if (!integrityData || !integrityData.anomalies || integrityData.anomalies.length === 0) return;
            const banner = document.getElementById('antiForensicsBanner');
            if (!banner) return;

            banner.style.display = 'block';
            let alertItems = integrityData.anomalies.map(a => `
                <div style="margin-top: 6px; padding: 10px 14px; background: rgba(0,0,0,0.25); border-radius: 6px; border-left: 3px solid ${{a.severity === 'HIGH' ? '#ef4444' : '#f59e0b'}};">
                    <strong style="color: ${{a.severity === 'HIGH' ? '#f87171' : '#fbbf24'}};">[${{a.severity}}] ${{escapeHtml(a.title)}}</strong>
                    <div style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 3px;">${{escapeHtml(a.details)}}</div>
                </div>
            `).join('');

            banner.innerHTML = `
                <div style="background: rgba(239, 68, 68, 0.12); border: 1px solid #ef4444; border-radius: 8px; padding: 14px 18px;">
                    <div style="display: flex; align-items: center; gap: 8px; color: #ef4444; font-weight: 700; font-size: 1.05rem;">
                        <span>⚠️</span> <span>${{I18N[currentLang].afAlertTitle}}</span> (${{integrityData.anomalies.length}})
                    </div>
                    ${{alertItems}}
                </div>
            `;
        }}

        // Initial render
        applyLanguage();
        applyFilters();
        renderAntiForensicsBanner();
    </script>
</body>
</html>
"""
    path.write_text(html_content, encoding="utf-8")

