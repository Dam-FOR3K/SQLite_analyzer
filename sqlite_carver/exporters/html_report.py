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

from sqlite_carver.core.carver import CarvedRecord
from sqlite_carver.core.wal_diff import RowMutation
from sqlite_carver.exporters.export import mutation_to_dict, record_to_dict


def generate_html_report(
    records: List[Union[CarvedRecord, RowMutation]],
    output_path: str | Path,
    title: str = "SQLite Forensic Investigation Report",
) -> None:
    """Generates a standalone, interactive HTML forensic dashboard with WAL diff timeline."""
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
            d["_record_kind"] = "wal"
            src = f"wal_{d['mutation_type'].lower()}"
            tbl = d["table_name"] or "Unknown / Unmatched"
            wal_mutations.append(d)
        else:
            d = {"raw": str(r)}
            src = "unknown"
            tbl = "Unknown"

        source_stats[src] = source_stats.get(src, 0) + 1
        table_stats[tbl] = table_stats.get(tbl, 0) + 1
        serialized_records.append(d)

    json_payload = json.dumps(serialized_records, ensure_ascii=False).replace("</", r"\u003c/")
    wal_payload = json.dumps(wal_mutations, ensure_ascii=False).replace("</", r"\u003c/")

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
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 14px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 14px;
            text-align: center;
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
            <button class="tab-btn active" onclick="switchTab('evidence')">
                <span id="tab-title-evidence">📋 All Evidence</span> <span class="tab-badge" id="tab-badge-evidence">{len(serialized_records)}</span>
            </button>
            <button class="tab-btn" onclick="switchTab('wal')">
                <span id="tab-title-wal">⏱️ WAL Transaction Timeline</span> <span class="tab-badge" id="tab-badge-wal">{len(wal_mutations)}</span>
            </button>
        </div>

        <!-- TAB 1: ALL EVIDENCE -->
        <div id="pane-evidence" class="tab-pane active">
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label" id="lbl-total-records">Total Records</div>
                    <div class="value">{len(serialized_records)}</div>
                </div>
                <div class="stat-card">
                    <div class="label" id="lbl-active">Active</div>
                    <div class="value" style="color: var(--color-active);">{source_stats.get('active', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="label" id="lbl-freeblocks">Freeblocks</div>
                    <div class="value" style="color: var(--color-freeblock);">{source_stats.get('freeblock', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="label" id="lbl-freelist">Freelist Pages</div>
                    <div class="value" style="color: var(--color-freelist);">{source_stats.get('freelist', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="label" id="lbl-slack">Slack & Unallocated</div>
                    <div class="value" style="color: var(--color-slack);">{source_stats.get('slack', 0) + source_stats.get('unallocated', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="label" id="lbl-wal">WAL Mutations</div>
                    <div class="value" style="color: var(--color-wal);">{len(wal_mutations)}</div>
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
                        <option value="active">Active Cells</option>
                        <option value="deleted">Deleted Only (Freeblock, Freelist, Slack, WAL)</option>
                        <option value="freeblock">Freeblocks</option>
                        <option value="freelist">Freelist Pages</option>
                        <option value="slack">Slack Space</option>
                        <option value="unallocated">Unallocated</option>
                        <option value="wal">WAL Transactions</option>
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
            <p>SQLite-Carver-Pro v1.2.0 | Author: Dam-FOR3K</p>
        </div>
    </div>

    <script>
        const rawData = {json_payload};
        const walData = {wal_payload};

        const I18N = {{
            en: {{
                flag: "🇫🇷",
                langBtn: "Français",
                subtitle: "Forensic Database Reconstruction, Deleted Record Recovery & WAL Transaction Diff",
                tabEvidence: "📋 All Evidence",
                tabWal: "⏱️ WAL Transaction Timeline",
                totalRecords: "Total Records",
                active: "Active",
                freeblocks: "Freeblocks",
                freelist: "Freelist Pages",
                slack: "Slack & Unallocated",
                walMutations: "WAL Mutations",
                searchPlaceholder: "Search keywords, flags, emails, tokens (instant live search)...",
                sourceLabel: "Source:",
                sourceAll: "All Sources",
                sourceActive: "Active Cells",
                sourceDeleted: "Deleted Only (Freeblock, Freelist, Slack, WAL)",
                sourceFreeblock: "Freeblocks",
                sourceFreelist: "Freelist Pages",
                sourceSlack: "Slack Space",
                sourceUnallocated: "Unallocated",
                sourceWal: "WAL Transactions",
                tableLabel: "Table:",
                tableAll: "All Tables",
                minConf: "Min Confidence",
                rowsPerPage: "Rows per page:",
                thPage: "Page",
                thOffset: "Offset",
                thSource: "Source",
                thConf: "Conf.",
                thTable: "Table",
                thRowId: "RowID",
                thColumns: "Reconstructed Columns & Decoded Payloads",
                walTitle: "⏱️ Write-Ahead Log (WAL) Chronological Transaction Diff",
                walDesc: "Reconstructs exact transaction order, column modifications, and deleted rows prior to WAL checkpoints.",
                noWal: "No WAL transactions recorded or no companion WAL file was present.",
                noRecords: "No matching records found.",
                showingRecords: (s, e, t) => `Showing ${{s}}-${{e}} of ${{t.toLocaleString()}} records`,
                showingZero: "Showing 0 records",
                pageOf: (c, t) => `Page ${{c}} / ${{t}}`,
            }},
            fr: {{
                flag: "🇬🇧",
                langBtn: "English",
                subtitle: "Reconstruction Forensique, Carving de Cellules Supprimées & Diff WAL",
                tabEvidence: "📋 Toutes les Preuves",
                tabWal: "⏱️ Timeline des Transactions WAL",
                totalRecords: "Total Enregistrements",
                active: "Actifs",
                freeblocks: "Freeblocks",
                freelist: "Pages Freelist",
                slack: "Slack & Non-Alloué",
                walMutations: "Mutations WAL",
                searchPlaceholder: "Rechercher mots-clés, tokens, emails, flags (recherche instantanée)...",
                sourceLabel: "Source :",
                sourceAll: "Toutes les sources",
                sourceActive: "Cellules Actives",
                sourceDeleted: "Supprimés uniquement (Freeblock, Freelist, Slack, WAL)",
                sourceFreeblock: "Freeblocks",
                sourceFreelist: "Pages Freelist",
                sourceSlack: "Slack Space",
                sourceUnallocated: "Espace Non-Alloué",
                sourceWal: "Transactions WAL",
                tableLabel: "Table :",
                tableAll: "Toutes les tables",
                minConf: "Confiance Min",
                rowsPerPage: "Lignes par page :",
                thPage: "Page",
                thOffset: "Offset",
                thSource: "Source",
                thConf: "Conf.",
                thTable: "Table",
                thRowId: "RowID",
                thColumns: "Colonnes Reconstituées & Payloads Décodés",
                walTitle: "⏱️ Journal Write-Ahead Log (WAL) — Diff Chronologique des Transactions",
                walDesc: "Reconstitue l'ordre exact des transactions, les modifications de colonnes et les lignes supprimées avant checkpoint.",
                noWal: "Aucune transaction WAL enregistrée ou aucun fichier compagnon .db-wal présent.",
                noRecords: "Aucun enregistrement correspondant trouvé.",
                showingRecords: (s, e, t) => `Affichage ${{s}}-${{e}} sur ${{t.toLocaleString()}} enregistrements`,
                showingZero: "Affichage 0 enregistrement",
                pageOf: (c, t) => `Page ${{c}} sur ${{t}}`,
            }}
        }};

        let currentLang = 'en';

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
            document.getElementById('lbl-freeblocks').textContent = lang.freeblocks;
            document.getElementById('lbl-freelist').textContent = lang.freelist;
            document.getElementById('lbl-slack').textContent = lang.slack;
            document.getElementById('lbl-wal').textContent = lang.walMutations;
            
            document.getElementById('searchInput').placeholder = lang.searchPlaceholder;
            document.getElementById('lbl-source-filter').textContent = lang.sourceLabel;
            document.getElementById('lbl-table-filter').textContent = lang.tableLabel;
            document.getElementById('lbl-min-conf').textContent = lang.minConf;
            document.getElementById('lbl-rows-per-page').textContent = lang.rowsPerPage;
            
            document.getElementById('th-page').textContent = lang.thPage;
            document.getElementById('th-offset').textContent = lang.thOffset;
            document.getElementById('th-source').textContent = lang.thSource;
            document.getElementById('th-conf').textContent = lang.thConf;
            document.getElementById('th-table').textContent = lang.thTable;
            document.getElementById('th-rowid').textContent = lang.thRowId;
            document.getElementById('th-columns').textContent = lang.thColumns;
            
            document.getElementById('txt-wal-title').textContent = lang.walTitle;
            document.getElementById('txt-wal-desc').textContent = lang.walDesc;

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
                document.querySelectorAll('.tab-btn')[0].classList.add('active');
                document.getElementById('pane-evidence').classList.add('active');
                applyFilters();
            }} else {{
                document.querySelectorAll('.tab-btn')[1].classList.add('active');
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
                if (src === 'active' && itemSrc !== 'active') return false;
                if (src === 'deleted' && itemSrc === 'active') return false;
                if (src === 'freeblock' && !itemSrc.includes('freeblock')) return false;
                if (src === 'freelist' && !itemSrc.includes('freelist')) return false;
                if (src === 'slack' && !itemSrc.includes('slack')) return false;
                if (src === 'unallocated' && !itemSrc.includes('unallocated')) return false;
                if (src === 'wal' && !itemSrc.includes('wal')) return false;

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
                const source = item.source || (item.mutation_type ? `wal_${{item.mutation_type.toLowerCase()}}` : 'unknown');
                const conf = item.confidence !== undefined ? item.confidence.toFixed(2) : '1.00';
                const table = item.matched_table || item.table_name || '?';
                const rowid = item.rowid !== undefined && item.rowid !== null ? item.rowid : '?';

                let badgeClass = 'badge-active';
                if (source.includes('freeblock')) badgeClass = 'badge-freeblock';
                else if (source.includes('freelist')) badgeClass = 'badge-freelist';
                else if (source.includes('slack')) badgeClass = 'badge-slack';
                else if (source.includes('unallocated')) badgeClass = 'badge-unallocated';
                else if (source.includes('wal_insert')) badgeClass = 'badge-wal-insert';
                else if (source.includes('wal_update')) badgeClass = 'badge-wal-update';
                else if (source.includes('wal_delete')) badgeClass = 'badge-wal-delete';

                let colsHtml = '<div class="columns-container">';
                if (item.columns) {{
                    for (const [k, v] of Object.entries(item.columns)) {{
                        colsHtml += `
                            <div class="col-row">
                                <span class="col-label">${{escapeHtml(k)}}:</span>
                                <span class="col-val">${{renderValue(v, query)}}</span>
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

                rowsHtml += `
                    <tr>
                        <td style="color: var(--text-muted);">${{pageId}}</td>
                        <td style="font-family: monospace; color: var(--text-muted);">${{offset}}</td>
                        <td><span class="badge ${{badgeClass}}">${{escapeHtml(source)}}</span></td>
                        <td style="font-weight: 600;">${{conf}}</td>
                        <td><span class="table-name">${{escapeHtml(table)}}</span></td>
                        <td style="color: var(--accent);">${{rowid}}</td>
                        <td>${{colsHtml}}</td>
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

                timelineHtml += `
                    <div class="timeline-item ${{typeClass}}">
                        <div class="timeline-header">
                            <span class="timeline-frame">Frame #${{mut.frame_index}} (Page ${{mut.page_id}})</span>
                            <span class="badge badge-${{typeClass}}">${{type}}</span>
                            ${{isCommitBadge}}
                            <span style="color: var(--text-secondary); font-size: 0.9rem;">Table: <strong style="color: #f8fafc;">${{escapeHtml(mut.table_name || 'Unknown')}}</strong></span>
                            <span style="color: var(--text-muted); font-size: 0.85rem; margin-left: auto;">RowID: <strong style="color: var(--accent);">${{mut.rowid !== null ? mut.rowid : '?'}}</strong></span>
                        </div>
                        ${{diffContentHtml}}
                    </div>
                `;
            }}

            listContainer.innerHTML = timelineHtml;
        }}

        // Initial render
        applyFilters();
    </script>
</body>
</html>
"""
    path.write_text(html_content, encoding="utf-8")

