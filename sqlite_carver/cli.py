"""
Rich Command-Line Interface for sqlite-carver-pro.

Provides colorized terminal outputs, tables, hex viewers, and exporters.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from sqlite_carver import __version__
from sqlite_carver.core.carver import CarvedRecord, SQLiteCarver, TableSchema
from sqlite_carver.core.parser import DatabaseParser, PageType
from sqlite_carver.core.wal_diff import MutationType, RowMutation, WalDiffEngine
from sqlite_carver.decoders.blobs import inspect_blob
from sqlite_carver.exporters.export import dispatch_export, export_csv, export_html, export_json, export_jsonl, export_parquet, record_to_dict
from sqlite_carver.i18n import get_language, set_language, t

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(highlight=False, legacy_windows=False)


def sanitize_display(text: Any) -> str:
    s = str(text)
    return "".join(c if c.isprintable() or c in "\r\n\t " else "?" for c in s)


def render_banner() -> None:
    banner = f"""[bold cyan]╔════════════════════════════════════════════════════════════════╗
║             SQLite-Carver-Pro v{__version__:<31}║
║  {t('banner_title'):<62}║
╚════════════════════════════════════════════════════════════════╝[/bold cyan]"""
    console.print(banner)


def cmd_info(args: argparse.Namespace) -> None:
    """Displays structural forensic metadata about a SQLite database."""
    set_language(getattr(args, "lang", "en"))
    db_path = Path(args.db_path)
    if not db_path.exists():
        console.print(f"[bold red]Error:[/] {t('file_not_found', path=db_path)}")
        sys.exit(1)

    raw_data = db_path.read_bytes()
    parser = DatabaseParser(raw_data)
    hdr = parser.header

    # Header Panel
    hdr_table = Table(box=box.SIMPLE, show_header=False)
    hdr_table.add_column("Property", style="bold cyan", width=25)
    hdr_table.add_column("Value", style="white")

    hdr_table.add_row(t("prop_page_size"), f"{hdr.page_size} bytes")
    hdr_table.add_row(t("prop_page_count"), f"{hdr.page_count} pages ({len(raw_data):,} bytes)")
    hdr_table.add_row(t("prop_format_version"), f"Read: {hdr.file_format_read}, Write: {hdr.file_format_write} ({'WAL Mode' if hdr.file_format_write == 2 else 'Rollback Journal'})")
    hdr_table.add_row(t("prop_text_encoding"), f"{hdr.text_encoding.name} ({hdr.text_encoding.value})")
    hdr_table.add_row(t("prop_freelist_pages"), f"{hdr.freelist_count} (Trunk Root Page: {hdr.freelist_trunk_page})")
    hdr_table.add_row(t("prop_schema_version"), f"{hdr.schema_cookie} / user_version: {hdr.user_version}")
    hdr_table.add_row(t("prop_app_id"), f"0x{hdr.application_id:08x}")

    console.print(Panel(hdr_table, title=f"[bold green]{t('header_analysis_title')}[/bold green]", box=box.ROUNDED))

    # Discover Freelist
    freelist_pages = parser.get_all_freelist_pages()
    if freelist_pages:
        console.print(f"[bold yellow]{t('freelist_found', count=len(freelist_pages))}[/] {freelist_pages}")
    else:
        console.print(f"[dim]{t('freelist_none')}[/dim]")

    # Discover Tables & Schemas
    carver = SQLiteCarver(raw_data)
    schemas = carver.discover_schemas()
    if schemas:
        table_summary = Table(title=t("tables_discovered"), box=box.ROUNDED)
        table_summary.add_column(t("th_table_name"), style="bold magenta")
        table_summary.add_column(t("th_root_page"), justify="right", style="cyan")
        table_summary.add_column(t("th_columns"), style="white")
        table_summary.add_column(t("th_sql_def"), style="dim")

        for name, s in schemas.items():
            cols_repr = ", ".join(f"{col}: {s.column_types[i]}" for i, col in enumerate(s.columns))
            table_summary.add_row(name, str(s.root_page), cols_repr, s.sql)
        console.print(table_summary)
    else:
        console.print(f"[yellow]{t('no_tables_warning')}[/yellow]")


def cmd_carve(args: argparse.Namespace) -> None:
    """Carves deleted records, slack space, freeblocks, and unallocated margins."""
    set_language(getattr(args, "lang", "en"))
    db_path = Path(args.db_path)
    if not db_path.exists():
        console.print(f"[bold red]Error:[/] {t('file_not_found', path=db_path)}")
        sys.exit(1)

    raw_data = db_path.read_bytes()
    carver = SQLiteCarver(raw_data)

    include_active = not args.deleted_only
    records = carver.carve_all(include_active=include_active)

    # Filter records
    filtered: List[CarvedRecord] = []
    for r in records:
        if args.table and (not r.matched_table or args.table.lower() != r.matched_table.lower()):
            continue
        if args.source and r.source.lower() != args.source.lower():
            continue
        if r.confidence < args.min_confidence:
            continue
        filtered.append(r)

    # Check companion WAL journal
    wal_mutations: List[RowMutation] = []
    wal_path = Path(str(db_path) + "-wal")
    if not wal_path.exists() and db_path.suffix == ".db":
        alt_wal = db_path.with_suffix(".wal")
        if alt_wal.exists():
            wal_path = alt_wal

    if wal_path.exists():
        try:
            wal_engine = WalDiffEngine(raw_data, wal_path.read_bytes())
            wal_mutations = wal_engine.compute_timeline_diff()
        except Exception as e:
            console.print(t("wal_warning", name=wal_path.name, err=e))

    # Summary
    source_counts = {}
    for r in filtered:
        source_counts[r.source] = source_counts.get(r.source, 0) + 1
    for m in wal_mutations:
        m_src = f"wal_{m.mutation_type.value.lower()}"
        source_counts[m_src] = source_counts.get(m_src, 0) + 1

    total_items_count = len(filtered) + len(wal_mutations)
    summary_panel = Panel(
        f"[bold]{t('total_evidence')}:[/] {total_items_count} | " + " | ".join(f"[cyan]{k}:[/] {v}" for k, v in source_counts.items()),
        title=f"[bold green]{t('carve_summary_title')}[/bold green]",
        box=box.ROUNDED,
    )
    console.print(summary_panel)

    all_evidence = list(filtered) + list(wal_mutations)

    if args.export:
        try:
            res = dispatch_export(all_evidence, args.export, title=f"Carved Evidence Report - {db_path.name}")
            console.print(f"[bold green]{t('export_success', count=res['written'], fmt=res['format'], path=res['path'])}[/]")
            if res.get("skipped_wal", 0) > 0:
                console.print(f"[yellow]{t('wal_omitted_note', count=res['skipped_wal'], fmt=res['format'])}[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Export Error:[/] {e}")
            sys.exit(1)
        return

    # Print Table
    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column(t("th_page"), style="dim", justify="right", width=6)
    table.add_column(t("th_offset"), style="dim", justify="right", width=8)
    table.add_column(t("th_source"), style="bold yellow", width=12)
    table.add_column(t("th_conf"), justify="right", width=6)
    table.add_column(t("th_table"), style="magenta", width=14)
    table.add_column(t("th_rowid"), justify="right", width=6)
    table.add_column(t("th_values"), style="white")

    # Limit terminal display to avoid overwhelming stdout
    limit = args.limit or 50
    for r in filtered[:limit]:
        conf_color = "green" if r.confidence >= 0.85 else ("yellow" if r.confidence >= 0.65 else "red")
        
        # Format values
        val_strs = []
        for i, val in enumerate(r.values):
            col_name = r.column_names[i] if i < len(r.column_names) else f"c{i}"
            if isinstance(val, bytes):
                blob_dec = inspect_blob(val)
                if blob_dec.detected_format != "raw_hex":
                    val_repr = f"[{blob_dec.detected_format}: {str(blob_dec.data)[:30]}...]"
                else:
                    val_repr = f"<blob {len(val)}B: {val[:8].hex()}...>"
            else:
                val_repr = str(val)
                if len(val_repr) > 40:
                    val_repr = val_repr[:37] + "..."
            val_strs.append(f"[dim]{col_name}:[/dim] {sanitize_display(val_repr)}")

        table.add_row(
            str(r.page_id),
            hex(r.offset_in_page),
            r.source,
            f"[{conf_color}]{r.confidence:.2f}[/{conf_color}]",
            r.matched_table or "[dim]?[/dim]",
            str(r.rowid) if r.rowid is not None else "[dim]?[/dim]",
            "\n".join(val_strs),
        )

    console.print(table)
    if len(filtered) > limit:
        console.print(f"[dim]{t('more_records', count=len(filtered) - limit)}[/dim]")


def cmd_wal_diff(args: argparse.Namespace) -> None:
    """Analyzes WAL files and computes row transaction timelines."""
    set_language(getattr(args, "lang", "en"))
    db_path = Path(args.db_path)
    wal_path = Path(args.wal_path) if args.wal_path else db_path.with_name(db_path.name + "-wal")

    if not db_path.exists():
        console.print(f"[bold red]Error:[/] {t('file_not_found', path=db_path)}")
        sys.exit(1)
    if not wal_path.exists():
        console.print(f"[bold red]Error:[/] {t('wal_not_found', path=wal_path)}")
        sys.exit(1)

    db_data = db_path.read_bytes()
    wal_data = wal_path.read_bytes()

    engine = WalDiffEngine(db_data, wal_data)

    if not engine.wal_header:
        console.print(f"[bold red]Error:[/] {t('invalid_wal_header', path=wal_path)}")
        sys.exit(1)

    wh = engine.wal_header
    console.print(f"[bold cyan]{t('wal_header_info', version=wh.format_version, size=wh.page_size, seq=wh.checkpoint_seq, frames=len(engine.frames))}[/bold cyan]")

    mutations = engine.compute_timeline_diff()

    # Apply table filter if specified
    if getattr(args, "table", None):
        mutations = [m for m in mutations if (m.table_name or "").lower() == args.table.lower()]

    if args.export:
        try:
            res = dispatch_export(mutations, args.export, title=f"WAL Timeline Report - {wal_path.name}")
            console.print(f"[bold green]{t('export_success', count=res['written'], fmt=res['format'], path=res['path'])}[/]")
        except Exception as e:
            console.print(f"[bold red]Export Error:[/] {e}")
            sys.exit(1)
        return

    table = Table(title=f"[bold green]{t('wal_timeline_title')}[/bold green]", box=box.ROUNDED, show_lines=True)
    table.add_column(t("th_frame"), style="dim", justify="right", width=6)
    table.add_column(t("th_page"), style="dim", justify="right", width=6)
    table.add_column(t("th_mutation"), style="bold", width=10)
    table.add_column(t("th_table"), style="magenta", width=14)
    table.add_column(t("th_rowid"), justify="right", width=6)
    table.add_column(t("th_diff_content"), style="white")

    for m in mutations:
        if m.mutation_type == MutationType.INSERT:
            color = "green"
            content = ", ".join(f"{str(v)[:30]}" for v in (m.new_values or []))
        elif m.mutation_type == MutationType.UPDATE:
            color = "yellow"
            diff_strs = [f"[bold]{d.column_name}[/bold]: [red]{d.old_value}[/red] -> [green]{d.new_value}[/green]" for d in m.column_diffs]
            content = "\n".join(diff_strs)
        else:
            color = "red"
            content = f"Deleted: {', '.join(str(v)[:30] for v in (m.old_values or []))}"

        table.add_row(
            str(m.frame_index) + (" (C)" if m.is_commit else ""),
            str(m.page_id),
            f"[{color}]{m.mutation_type.value}[/{color}]",
            m.table_name or "?",
            str(m.rowid) if m.rowid is not None else "?",
            content,
        )

    console.print(table)


def cmd_decode_blob(args: argparse.Namespace) -> None:
    """Inspects and decodes raw binary BLOB payloads."""
    set_language(getattr(args, "lang", "en"))
    if args.hex:
        try:
            data = bytes.fromhex(args.hex.strip())
        except ValueError as e:
            console.print(f"[bold red]Error:[/] {t('hex_error', err=e)}")
            sys.exit(1)
    elif args.file:
        data = Path(args.file).read_bytes()
    else:
        console.print(f"[bold red]Error:[/] {t('blob_param_error')}")
        sys.exit(1)

    result = inspect_blob(data)
    panel_title = f"[bold green]{t('blob_panel_title', fmt=result.detected_format, conf=result.confidence)}[/bold green]"
    
    meta_strs = []
    for k, v in result.metadata.items():
        meta_strs.append(f"[bold dim]{k}:[/bold dim] [yellow]{v}[/yellow]")
    meta_line = " | ".join(meta_strs) if meta_strs else "[dim]No extra metadata[/dim]"

    content = f"[bold cyan]{t('blob_metadata_title')}:[/] {meta_line}\n\n" + (
        json.dumps(result.data, indent=2, ensure_ascii=False) if isinstance(result.data, (dict, list)) else str(result.data)
    )
    console.print(Panel(content, title=panel_title, box=box.ROUNDED))


def cmd_search(args: argparse.Namespace) -> None:
    """Recursively searches for keywords or hex patterns across active/deleted records, blobs, and WAL."""
    from sqlite_carver.core.search import ForensicSearchEngine

    set_language(getattr(args, "lang", "en"))
    db_path = Path(args.db_path)
    if not db_path.exists():
        console.print(f"[bold red]Error:[/] {t('file_not_found', path=db_path)}")
        sys.exit(1)

    db_data = db_path.read_bytes()
    wal_path = Path(args.wal_path) if args.wal_path else db_path.with_name(db_path.name + "-wal")
    include_wal_flag = getattr(args, "include_wal", True)
    wal_data = wal_path.read_bytes() if (include_wal_flag and wal_path.exists()) else None

    engine = ForensicSearchEngine(db_data, wal_data=wal_data)
    matches = engine.search(
        query=args.query,
        is_hex=args.hex,
        include_active=not args.deleted_only,
        deleted_only=args.deleted_only,
        table_filter=args.table,
        min_confidence=args.min_confidence,
        include_wal=include_wal_flag,
    )

    query_repr = f"hex:0x{args.query}" if args.hex else f"'{args.query}'"
    scope_str = t("search_scope_deleted") if args.deleted_only else t("search_scope_active")
    if include_wal_flag and wal_data:
        scope_str += " + WAL"

    console.print(Panel(
        f"[bold]{t('search_query')}:[/] [yellow]{query_repr}[/yellow] | [bold]{t('search_matches')}:[/] [green]{len(matches)}[/green] | [bold]{t('search_scope')}:[/] {scope_str}",
        title=f"[bold green]{t('search_summary_title')}[/bold green]",
        box=box.ROUNDED,
    ))

    if not matches:
        console.print(f"[dim]{t('search_none')}[/dim]")
        return

    if args.export:
        export_records = [m.record for m in matches]
        try:
            res = dispatch_export(export_records, args.export, title=f"Forensic Search Matches - {args.query}")
            console.print(f"[bold green]{t('export_success', count=res['written'], fmt=res['format'], path=res['path'])}[/]")
            if res.get("skipped_wal", 0) > 0:
                console.print(f"[yellow]{t('wal_matches_omitted', count=res['skipped_wal'], fmt=res['format'])}[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Export Error:[/] {e}")
            sys.exit(1)
        return

    # Render Table
    table = Table(title=f"{t('search_matches')} for {query_repr}", box=box.ROUNDED, show_lines=True)
    table.add_column(t("th_page"), style="dim", justify="right", width=6)
    table.add_column(t("th_offset"), style="dim", justify="right", width=8)
    table.add_column(t("th_source"), style="bold", width=12)
    table.add_column(t("th_conf"), justify="right", width=6)
    table.add_column(t("th_table"), style="magenta", width=14)
    table.add_column(t("th_rowid"), justify="right", width=6)
    table.add_column(t("th_container"), style="cyan", width=10)
    table.add_column(t("th_matched_snippet"), style="white")

    limit = args.limit or 50
    for m in matches[:limit]:
        if m.record_source == "active":
            src_styled = "[green]active[/green]"
        elif m.record_source in ("freeblock", "slack", "unallocated", "freelist"):
            src_styled = f"[red]{m.record_source}[/red]"
        else:
            src_styled = f"[cyan]{m.record_source}[/cyan]"

        table.add_row(
            str(m.page_id),
            hex(m.offset_in_page),
            src_styled,
            f"{m.confidence:.2f}",
            m.table_name or "[dim]?[/dim]",
            str(m.rowid) if m.rowid is not None else "[dim]?[/dim]",
            m.container_format,
            f"[bold yellow]{m.matched_column}:[/bold yellow] {sanitize_display(m.matched_value_snippet)}",
        )

    console.print(table)
    if len(matches) > limit:
        console.print(f"[dim]{t('more_records', count=len(matches) - limit)}[/dim]")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sqlite-carver",
        description="SQLite-Carver-Pro: Forensic Parser, Slack Carver, Freelist & WAL Diff Engine",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--lang", "-l", choices=["en", "fr"], default="en", help="Language interface (en: English, fr: Français)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # info
    p_info = subparsers.add_parser("info", help="Inspect database header, freelists, and schema")
    p_info.add_argument("db_path", help="Path to SQLite database file")
    p_info.add_argument("--lang", "-l", choices=["en", "fr"], default="en", help="Language interface")
    p_info.set_defaults(func=cmd_info)

    # carve
    p_carve = subparsers.add_parser("carve", help="Carve active and deleted records from database")
    p_carve.add_argument("db_path", help="Path to SQLite database file")
    p_carve.add_argument("--deleted-only", action="store_true", help="Only show carved deleted records (freeblock/slack/unallocated)")
    p_carve.add_argument("--table", help="Filter by table name")
    p_carve.add_argument("--source", help="Filter by source (active, freeblock, slack, unallocated, freelist)")
    p_carve.add_argument("--min-confidence", type=float, default=0.5, help="Minimum confidence threshold (0.0 - 1.0)")
    p_carve.add_argument("--limit", type=int, default=50, help="Limit number of rows displayed in console")
    p_carve.add_argument("--export", help="Export to path (.html, .json, .jsonl, .csv, .parquet)")
    p_carve.add_argument("--lang", "-l", choices=["en", "fr"], default="en", help="Language interface")
    p_carve.set_defaults(func=cmd_carve)

    # search
    p_search = subparsers.add_parser("search", help="Deep forensic search across active/deleted records, blobs, and WAL")
    p_search.add_argument("db_path", help="Path to SQLite database file")
    p_search.add_argument("query", help="Text keyword or hex string to search for")
    p_search.add_argument("--hex", action="store_true", help="Search query as hex byte sequence (e.g. deadbeef)")
    p_search.add_argument("--deleted-only", action="store_true", help="Only search carved deleted records (freeblocks/slack)")
    p_search.add_argument("--table", help="Filter search to specific table name")
    p_search.add_argument("--include-wal", action=argparse.BooleanOptionalAction, default=True, help="Include WAL journal file in search if present (default: True, use --no-include-wal to disable)")
    p_search.add_argument("--wal-path", help="Explicit path to WAL file")
    p_search.add_argument("--min-confidence", type=float, default=0.5, help="Minimum confidence threshold")
    p_search.add_argument("--limit", type=int, default=50, help="Limit output rows")
    p_search.add_argument("--export", help="Export matches to path (.html, .json, .jsonl, .csv, .parquet)")
    p_search.add_argument("--lang", "-l", choices=["en", "fr"], default="en", help="Language interface")
    p_search.set_defaults(func=cmd_search)

    # wal-diff
    p_wal = subparsers.add_parser("wal-diff", help="Analyze WAL transaction diffs and timeline")
    p_wal.add_argument("db_path", help="Path to base SQLite database file")
    p_wal.add_argument("wal_path", nargs="?", help="Path to WAL file (defaults to <db_path>-wal)")
    p_wal.add_argument("--table", help="Filter WAL mutations to a specific table")
    p_wal.add_argument("--export", help="Export timeline mutations to (.html, .json, .jsonl)")
    p_wal.add_argument("--lang", "-l", choices=["en", "fr"], default="en", help="Language interface")
    p_wal.set_defaults(func=cmd_wal_diff)

    # decode-blob
    p_blob = subparsers.add_parser("decode-blob", help="Decode embedded binary structures (bplist, protobuf, zlib)")
    p_blob.add_argument("--hex", help="Hex string of binary data")
    p_blob.add_argument("--file", help="Path to raw binary file")
    p_blob.add_argument("--lang", "-l", choices=["en", "fr"], default="en", help="Language interface")
    p_blob.set_defaults(func=cmd_decode_blob)

    if len(sys.argv) == 1:
        render_banner()
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    set_language(getattr(args, "lang", "en"))
    args.func(args)



if __name__ == "__main__":
    main()
