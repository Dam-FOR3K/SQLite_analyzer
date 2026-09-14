"""
Rich Command-Line Interface for sqlite-carver-pro.

Provides colorized terminal outputs, tables, hex viewers, and exporters.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Any, List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from sqlite_carver import __version__
from sqlite_carver.core.carver import CarvedRecord, SQLiteCarver, TableSchema
from sqlite_carver.core.correlator import EntityCorrelator
from sqlite_carver.core.encryption import analyze_database_encryption
from sqlite_carver.core.integrity import check_anti_forensics_anomalies, hash_file
from sqlite_carver.core.parser import DatabaseParser, ForensicBuffer, PageType, open_forensic_buffer
from sqlite_carver.core.shm import ShmAnalyzer
from sqlite_carver.core.wal_diff import JournalDiffEngine, MutationType, RowMutation, WalDiffEngine
from sqlite_carver.decoders.blobs import dump_blob_to_file, inspect_blob
from sqlite_carver.decoders.geolocation import extract_coordinates
from sqlite_carver.decoders.timestamps import decode_timestamp
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

    fb = ForensicBuffer(db_path)
    raw_data = fb.buffer

    # Encryption / SQLCipher & Shannon Entropy Analysis
    enc_info = analyze_database_encryption(raw_data)
    if enc_info.is_encrypted:
        enc_table = Table(box=box.SIMPLE, show_header=False)
        enc_table.add_column("Property", style="bold red", width=25)
        enc_table.add_column("Value", style="white")
        enc_table.add_row("Encryption Status", f"[bold red]{enc_info.confidence_label} ({enc_info.confidence:.0%})[/]")
        enc_table.add_row("Format / Scheme", f"[bold yellow]{enc_info.scheme}[/]")
        enc_table.add_row("Shannon Entropy", f"[bold magenta]{enc_info.entropy:.4f} / 8.0000[/]")
        if enc_info.salt_hex:
            enc_table.add_row("Detected Salt (16B)", f"[dim cyan]{enc_info.salt_hex}[/]")
        for reason in enc_info.reasons:
            enc_table.add_row("Diagnostic", f"[dim]{reason}[/]")
        console.print(Panel(enc_table, title="[bold red]⚠️ Cryptographic Protection / Encrypted Database Detected[/bold red]", box=box.ROUNDED, border_style="red"))

    parser = DatabaseParser(raw_data)
    hdr = parser.header

    # Forensic File Integrity Hashes
    h_db = hash_file(db_path)
    hash_table = Table(box=box.SIMPLE, show_header=False)
    hash_table.add_column("File / Target", style="bold cyan", width=25)
    hash_table.add_column("Hashes", style="white")
    hash_table.add_row(
        f"{db_path.name} ({h_db['size_bytes']:,} B)",
        f"SHA-256: [green]{h_db['sha256']}[/green]\nMD5: [dim]{h_db['md5']}[/dim]",
    )

    wal_path = Path(str(db_path) + "-wal")
    if not wal_path.exists() and db_path.suffix == ".db":
        alt_w = db_path.with_suffix(".wal")
        if alt_w.exists():
            wal_path = alt_w
    if wal_path.exists():
        h_wal = hash_file(wal_path)
        hash_table.add_row(
            f"{wal_path.name} ({h_wal['size_bytes']:,} B)",
            f"SHA-256: [cyan]{h_wal['sha256']}[/cyan]\nMD5: [dim]{h_wal['md5']}[/dim]",
        )

    j_path = Path(str(db_path) + "-journal")
    if not j_path.exists() and db_path.suffix == ".db":
        alt_j = db_path.with_name(db_path.name + ".journal")
        if alt_j.exists():
            j_path = alt_j
    if j_path.exists():
        h_j = hash_file(j_path)
        hash_table.add_row(
            f"{j_path.name} ({h_j['size_bytes']:,} B)",
            f"SHA-256: [yellow]{h_j['sha256']}[/yellow]\nMD5: [dim]{h_j['md5']}[/dim]",
        )

    shm_path = Path(str(db_path) + "-shm")
    if not shm_path.exists() and db_path.suffix == ".db":
        alt_s = db_path.with_suffix(".shm")
        if alt_s.exists():
            shm_path = alt_s
    if shm_path.exists():
        h_s = hash_file(shm_path)
        hash_table.add_row(
            f"{shm_path.name} ({h_s['size_bytes']:,} B)",
            f"SHA-256: [magenta]{h_s['sha256']}[/magenta]\nMD5: [dim]{h_s['md5']}[/dim]",
        )

    console.print(Panel(hash_table, title="[bold green]Cryptographic Chain of Custody & File Hashes[/bold green]", box=box.ROUNDED))

    if not hdr:
        err_detail = "Database is encrypted (SQLCipher / AES-256). Structural B-tree headers cannot be parsed without decryption key." if enc_info.is_encrypted else "File may be corrupt, truncated, or not a standard SQLite database."
        console.print(f"[bold red]Cannot parse SQLite header:[/] {err_detail}")
        fb.close()
        return

    # Header Panel
    hdr_table = Table(box=box.SIMPLE, show_header=False)
    hdr_table.add_column("Property", style="bold cyan", width=25)
    hdr_table.add_column("Value", style="white")

    hdr_table.add_row(t("prop_page_size"), f"{hdr.page_size} bytes")
    hdr_table.add_row(t("prop_page_count"), f"{parser.page_count} pages ({len(raw_data):,} bytes)")
    hdr_table.add_row(t("prop_format_version"), f"Read: {hdr.read_version}, Write: {hdr.write_version} ({'WAL Mode' if hdr.write_version == 2 else 'Rollback Journal'})")
    hdr_table.add_row(t("prop_text_encoding"), f"{hdr.encoding.upper()}")
    hdr_table.add_row(t("prop_freelist_pages"), f"{hdr.total_freelist_pages} (Trunk Root Page: {hdr.first_freelist_trunk_page})")
    if hdr.reserved_space > 0:
        total_res = hdr.reserved_space * parser.page_count
        hdr_table.add_row(
            t("prop_reserved_space"),
            f"[bold magenta]{hdr.reserved_space} B/page[/bold magenta] ({total_res:,} bytes total) [bold red]⚠️ Steganography / Anti-Forensics Area[/bold red]",
        )
    hdr_table.add_row(t("prop_schema_version"), f"{hdr.schema_cookie} / user_version: {hdr.user_version}")
    hdr_table.add_row(t("prop_app_id"), f"0x{hdr.application_id:08x}")

    console.print(Panel(hdr_table, title=f"[bold green]{t('header_analysis_title')}[/bold green]", box=box.ROUNDED))

    # Storage & Slack Space Breakdown
    storage = parser.compute_storage_breakdown()
    storage_table = Table(box=box.SIMPLE, show_header=False)
    storage_table.add_column("Property", style="bold cyan", width=28)
    storage_table.add_column("Size", style="white")
    storage_table.add_row("Active Payloads", f"{storage.active_bytes:,} bytes")
    storage_table.add_row("Freeblocks (Deleted)", f"{storage.freeblock_bytes:,} bytes")
    storage_table.add_row("Unallocated Space", f"{storage.unallocated_bytes:,} bytes")
    storage_table.add_row("Fragmented Slack (Offset 7)", f"{storage.fragmented_free_bytes:,} bytes")
    storage_table.add_row("Freelist Pages", f"{storage.freelist_pages_count} pages ({storage.freelist_bytes:,} bytes)")
    if storage.reserved_space_bytes > 0:
        storage_table.add_row("Page Reserved Space", f"[bold magenta]{storage.reserved_space_bytes:,} bytes[/bold magenta]")
    storage_table.add_row("Total Recoverable Slack", f"[bold green]{storage.to_dict()['total_slack_bytes']:,} bytes[/bold green]")
    console.print(Panel(storage_table, title="[bold green]Storage & Forensic Slack Allocation[/bold green]", box=box.ROUNDED))

    # Discover Freelist
    freelist_pages = parser.get_all_freelist_pages()
    if freelist_pages:
        console.print(f"[bold yellow]{t('freelist_found', count=len(freelist_pages))}[/] {freelist_pages}")
    else:
        console.print(f"[dim]{t('freelist_none')}[/dim]")

    # Discover Tables & Schemas
    carver = SQLiteCarver(raw_data)
    schemas = carver.schemas
    if schemas:
        table_summary = Table(title=t("tables_discovered"), box=box.ROUNDED)
        table_summary.add_column(t("th_table_name"), style="bold magenta")
        table_summary.add_column(t("th_root_page"), justify="right", style="cyan")
        table_summary.add_column(t("th_columns"), style="white")
        table_summary.add_column(t("th_sql_def"), style="dim")

        for name, s in schemas.items():
            cols_repr = ", ".join(f"{c.name}: {c.affinity}" for c in s.columns)
            table_summary.add_row(name, str(s.root_page), cols_repr, s.sql or "")
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

    fb = ForensicBuffer(db_path)
    raw_data = fb.buffer

    # Encryption / SQLCipher & Shannon Entropy Analysis
    enc_info = analyze_database_encryption(raw_data)
    if enc_info.is_encrypted:
        enc_table = Table(box=box.SIMPLE, show_header=False)
        enc_table.add_column("Property", style="bold red", width=25)
        enc_table.add_column("Value", style="white")
        enc_table.add_row("Encryption Status", f"[bold red]{enc_info.confidence_label} ({enc_info.confidence:.0%})[/]")
        enc_table.add_row("Format / Scheme", f"[bold yellow]{enc_info.scheme}[/]")
        enc_table.add_row("Shannon Entropy", f"[bold magenta]{enc_info.entropy:.4f} / 8.0000[/]")
        if enc_info.salt_hex:
            enc_table.add_row("Detected Salt (16B)", f"[dim cyan]{enc_info.salt_hex}[/]")
        for reason in enc_info.reasons:
            enc_table.add_row("Diagnostic", f"[dim]{reason}[/]")
        console.print(Panel(enc_table, title="[bold red]⚠️ Cryptographic Protection / Encrypted Database Detected[/bold red]", box=box.ROUNDED, border_style="red"))

    carver = SQLiteCarver(raw_data)

    include_active = not args.deleted_only
    records = carver.carve_all(include_active=include_active)

    # Filter records
    mutations_only = getattr(args, "mutations_only", False)
    filtered: List[CarvedRecord] = []
    for r in records:
        if mutations_only and not getattr(r, "is_mutation", False):
            continue
        if args.table and (not r.matched_table or args.table.lower() != r.matched_table.lower()):
            continue
        source_filter = getattr(args, "source", None)
        if source_filter and r.source.lower() != source_filter.lower():
            continue
        if r.confidence < args.min_confidence:
            continue
        filtered.append(r)

    # Correlate foreign keys and entities across tables
    correlator = EntityCorrelator(carver.schemas)
    correlator.correlate_records(filtered)

    # Check companion WAL journal
    wal_mutations: List[RowMutation] = []
    wal_path = Path(str(db_path) + "-wal")
    if not wal_path.exists() and db_path.suffix == ".db":
        alt_wal = db_path.with_suffix(".wal")
        if alt_wal.exists():
            wal_path = alt_wal

    if wal_path.exists():
        wal_bytes = wal_path.read_bytes()
        if len(wal_bytes) == 0 or wal_bytes[:4] == b"\x00\x00\x00\x00":
            # Normal checkpointed / reset WAL (no active pending transactions)
            pass
        elif len(wal_bytes) < 32:
            console.print(f"[dim]{t('wal_empty_or_reset', name=wal_path.name)}[/dim]")
        else:
            try:
                wal_engine = WalDiffEngine(raw_data, wal_bytes, user_schemas=list(carver.schemas.values()))
                if not wal_engine.wal_header:
                    magic_val = struct.unpack(">I", wal_bytes[:4])[0] if len(wal_bytes) >= 4 else 0
                    console.print(f"[yellow]{t('wal_invalid_magic', name=wal_path.name, size=len(wal_bytes), magic=magic_val)}[/yellow]")
                else:
                    wal_mutations.extend(wal_engine.compute_timeline_diff())
            except Exception as e:
                err_msg = str(e).strip() or e.__class__.__name__
                console.print(t("wal_warning", name=wal_path.name, err=err_msg))

    # Check companion Rollback Journal (.db-journal / -journal)
    journal_path = Path(str(db_path) + "-journal")
    if not journal_path.exists() and db_path.suffix == ".db":
        alt_j = db_path.with_name(db_path.name + ".journal")
        if alt_j.exists():
            journal_path = alt_j
        else:
            alt_j2 = db_path.with_suffix(".journal")
            if alt_j2.exists():
                journal_path = alt_j2

    if journal_path.exists():
        j_bytes = journal_path.read_bytes()
        if len(j_bytes) == 0 or j_bytes[:4] == b"\x00\x00\x00\x00":
            pass
        elif len(j_bytes) < 28:
            console.print(f"[dim]{t('wal_empty_or_reset', name=journal_path.name)}[/dim]")
        else:
            try:
                j_engine = JournalDiffEngine(raw_data, j_bytes, user_schemas=list(carver.schemas.values()))
                if j_engine.journal_header:
                    wal_mutations.extend(j_engine.compute_timeline_diff())
            except Exception as e:
                err_msg = str(e).strip() or e.__class__.__name__
                console.print(t("wal_warning", name=journal_path.name, err=err_msg))

    # Check companion SHM (.db-shm)
    shm_path = Path(str(db_path) + "-shm")
    if not shm_path.exists() and db_path.suffix == ".db":
        alt_s = db_path.with_suffix(".shm")
        if alt_s.exists():
            shm_path = alt_s
    shm_dict = None
    if shm_path.exists():
        try:
            s_bytes = shm_path.read_bytes()
            if len(s_bytes) >= 48:
                shm_analyzer = ShmAnalyzer(s_bytes)
                if shm_analyzer.header:
                    shm_dict = shm_analyzer.to_dict()
        except Exception:
            pass

    # Build forensic integrity hashes
    integrity_dict = {
        "database": hash_file(db_path),
    }
    if wal_path.exists():
        integrity_dict["wal"] = hash_file(wal_path)
    if journal_path.exists():
        integrity_dict["journal"] = hash_file(journal_path)
    if shm_path.exists():
        integrity_dict["shm"] = hash_file(shm_path)

    # Check anti-forensics anomalies
    anomalies = check_anti_forensics_anomalies(carver.parser, file_size=len(raw_data))
    if anomalies:
        integrity_dict["anomalies"] = anomalies
        for a in anomalies:
            color = "bold red" if a.get("severity") == "HIGH" else "bold yellow"
            console.print(f"[{color}]⚠️  {a['title']}[/]")
            console.print(f"   [dim]{a['details']}[/dim]")

    # Summary
    mutations_count = sum(1 for r in filtered if getattr(r, "is_mutation", False))
    source_counts = {}
    for r in filtered:
        source_counts[r.source] = source_counts.get(r.source, 0) + 1
    for m in wal_mutations:
        m_src = f"{getattr(m, 'journal_source', 'wal')}_{m.mutation_type.value.lower()}"
        source_counts[m_src] = source_counts.get(m_src, 0) + 1

    total_items_count = len(filtered) + len(wal_mutations)
    summary_parts = [f"[bold]{t('total_evidence')}:[/] {total_items_count}"]
    if mutations_count > 0:
        summary_parts.append(f"[bold yellow]mutations_diff:[/] {mutations_count}")
    summary_parts.extend(f"[cyan]{k}:[/] {v}" for k, v in source_counts.items())
    summary_panel = Panel(
        " | ".join(summary_parts),
        title=f"[bold green]{t('carve_summary_title')}[/bold green]",
        box=box.ROUNDED,
    )
    console.print(summary_panel)

    all_evidence = list(filtered) + list(wal_mutations)
    storage_dict = carver.parser.compute_storage_breakdown().to_dict()

    if args.export:
        try:
            res = dispatch_export(
                all_evidence,
                args.export,
                title=f"Carved Evidence Report - {db_path.name}",
                schemas=carver.schemas,
                storage_breakdown=storage_dict,
                integrity_info=integrity_dict,
                shm_info=shm_dict,
                lang=getattr(args, "lang", None),
            )
            console.print(f"[bold green]{t('export_success', count=res['written'], fmt=res['format'], path=res['path'])}[/]")
            if res.get("skipped_wal", 0) > 0:
                console.print(f"[yellow]{t('wal_omitted_note', count=res['skipped_wal'], fmt=res['format'])}[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Export Error:[/] {e}")
            fb.close()
            sys.exit(1)
        fb.close()
        return

    if getattr(args, "dump_blobs", None):
        dump_dir = Path(args.dump_blobs)
        dump_dir.mkdir(parents=True, exist_ok=True)
        dumped_count = 0
        for r in filtered:
            for i, val in enumerate(r.values):
                if isinstance(val, bytes) and len(val) > 0:
                    col_name = r.column_names[i] if i < len(r.column_names) else f"c{i}"
                    blob_fname = f"page_{r.page_id}_row_{r.rowid if r.rowid is not None else 'x'}_{r.matched_table or 'tbl'}_{col_name}"
                    dump_blob_to_file(val, dump_dir / blob_fname)
                    dumped_count += 1
        console.print(f"[bold green]Successfully dumped {dumped_count} BLOB file(s) to {dump_dir}[/bold green]")

    # Print Table
    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column(t("th_page"), style="dim", justify="right", width=6)
    table.add_column(t("th_offset"), style="dim", justify="right", width=8)
    table.add_column(t("th_source"), style="bold yellow", width=14)
    table.add_column(t("th_conf"), justify="right", width=6)
    table.add_column(t("th_table"), style="magenta", width=14)
    table.add_column(t("th_rowid"), justify="right", width=6)
    table.add_column(t("th_values"), style="white")

    # Limit terminal display to avoid overwhelming stdout
    limit = args.limit or 50
    for r in filtered[:limit]:
        conf_color = "green" if r.confidence >= 0.85 else ("yellow" if r.confidence >= 0.65 else "red")
        
        # Format values with intelligent timestamp and blob file identification
        val_strs = []
        for i, val in enumerate(r.values):
            col_name = r.column_names[i] if i < len(r.column_names) else f"c{i}"
            if isinstance(val, bytes):
                blob_dec = inspect_blob(val)
                if blob_dec.is_file:
                    val_repr = f"[{blob_dec.detected_format.upper()} {len(val)}B ({blob_dec.suggested_extension})]"
                elif blob_dec.detected_format != "raw_hex":
                    val_repr = f"[{blob_dec.detected_format}: {str(blob_dec.data)[:30]}...]"
                else:
                    val_repr = f"<blob {len(val)}B: {val[:8].hex()}...>"
            else:
                ts = decode_timestamp(val, col_name) if isinstance(val, (int, float)) and not isinstance(val, bool) else None
                if ts:
                    val_repr = f"{val} 📅 [cyan]{ts.iso_utc}[/cyan]"
                else:
                    val_repr = str(val)
                    if len(val_repr) > 40:
                        val_repr = val_repr[:37] + "..."
            if getattr(r, "foreign_keys", None) and col_name in r.foreign_keys:
                fk = r.foreign_keys[col_name]
                val_repr += f" ➔ [cyan]{fk['target_table']}:[/cyan] [bold]{fk['display_value']}[/bold]"
            if getattr(r, "is_mutation", False) and getattr(r, "mutation_diff", None) and col_name in r.mutation_diff:
                active_val = r.mutation_diff[col_name].get("active")
                val_repr += f" 🔄 [yellow](active: {active_val})[/yellow]"
            val_strs.append(f"[dim]{col_name}:[/dim] {sanitize_display(val_repr)}")

        src_disp = r.source
        if getattr(r, "is_mutation", False):
            src_disp = f"{r.source} [bold yellow]MUT[/bold yellow]"

        table.add_row(
            str(r.page_id),
            hex(r.offset_in_page),
            src_disp,
            f"[{conf_color}]{r.confidence:.2f}[/{conf_color}]",
            r.matched_table or "[dim]?[/dim]",
            str(r.rowid) if r.rowid is not None else "[dim]?[/dim]",
            "\n".join(val_strs),
        )

    console.print(table)
    if len(filtered) > limit:
        console.print(f"[dim]{t('more_records', count=len(filtered) - limit)}[/dim]")
    fb.close()



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

    fb = ForensicBuffer(db_path)
    db_data = fb.buffer
    wal_data = wal_path.read_bytes()

    engine = WalDiffEngine(db_data, wal_data)

    if not engine.wal_header:
        if len(wal_data) < 32 or wal_data[:4] == b"\x00\x00\x00\x00":
            console.print(f"[yellow]{t('wal_empty_or_reset', name=wal_path.name)}[/yellow]")
            return
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
            res = dispatch_export(
                mutations,
                args.export,
                title=f"WAL Timeline Report - {wal_path.name}",
                lang=getattr(args, "lang", None),
            )
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

    fb = ForensicBuffer(db_path)
    db_data = fb.buffer
    wal_path = Path(args.wal_path) if args.wal_path else db_path.with_name(db_path.name + "-wal")
    if not wal_path.exists() and db_path.suffix == ".db":
        alt_wal = db_path.with_suffix(".wal")
        if alt_wal.exists():
            wal_path = alt_wal
    include_wal_flag = getattr(args, "include_wal", True)
    wal_data = None
    if include_wal_flag and wal_path.exists():
        wb = wal_path.read_bytes()
        if len(wb) >= 32 and wb[:4] != b"\x00\x00\x00\x00":
            wal_data = wb

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
            res = dispatch_export(
                export_records,
                args.export,
                title=f"Forensic Search Matches - {args.query}",
                schemas=engine.carver.schemas,
                lang=getattr(args, "lang", None),
            )
            console.print(f"[bold green]{t('export_success', count=res['written'], fmt=res['format'], path=res['path'])}[/]")
            if res.get("skipped_wal", 0) > 0:
                console.print(f"[yellow]{t('wal_matches_omitted', count=res['skipped_wal'], fmt=res['format'])}[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Export Error:[/] {e}")
            sys.exit(1)
        return

    if getattr(args, "dump_blobs", None):
        dump_dir = Path(args.dump_blobs)
        dump_dir.mkdir(parents=True, exist_ok=True)
        dumped_count = 0
        for m in matches:
            r = m.record
            for i, val in enumerate(r.values):
                if isinstance(val, bytes) and len(val) > 0:
                    col_name = r.column_names[i] if i < len(r.column_names) else f"c{i}"
                    blob_fname = f"match_p{m.page_id}_r{m.rowid if m.rowid is not None else 'x'}_{m.table_name or 'tbl'}_{col_name}"
                    dump_blob_to_file(val, dump_dir / blob_fname)
                    dumped_count += 1
        console.print(f"[bold green]Successfully dumped {dumped_count} matched BLOB file(s) to {dump_dir}[/bold green]")

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
        elif m.record_source in ("page_reserved_space", "reserved_space"):
            src_styled = "[bold magenta]reserved_space[/bold magenta]"
        elif m.record_source in ("freeblock", "slack", "unallocated", "freelist", "index_freeblock", "index_slack", "index_unallocated"):
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


def cmd_carve_raw(args: argparse.Namespace) -> None:
    """Raw Page Hunter: carves SQLite records from arbitrary memory dumps or raw disk images."""
    import re
    set_language(getattr(args, "lang", "en"))
    image_path = Path(args.image_path)
    if not image_path.exists():
        console.print(f"[bold red]Error:[/] {t('file_not_found', path=image_path)}")
        sys.exit(1)

    fb = ForensicBuffer(image_path)
    raw_data = fb.buffer
    page_size = args.page_size

    user_schemas = []
    if getattr(args, "schema", None):
        schema_path = Path(args.schema)
        if schema_path.exists():
            sql_text = schema_path.read_text(encoding="utf-8")
            for m in re.finditer(r"CREATE\s+TABLE\s+([`\"\[]?(\w+)[`\"\]]?)\s*\((.*?)\);", sql_text, re.DOTALL | re.IGNORECASE):
                t_name = m.group(2)
                user_schemas.append(TableSchema.from_sql(t_name, 0, m.group(0)))

    workers = getattr(args, "workers", 1)
    if workers > 1:
        console.print(f"[cyan]Scanning {image_path.name} ({len(raw_data):,} bytes) with candidate page size {page_size}B across {workers} parallel worker threads...[/cyan]")
    else:
        console.print(f"[cyan]Scanning {image_path.name} ({len(raw_data):,} bytes) with candidate page size {page_size}B...[/cyan]")

    records = SQLiteCarver.carve_raw_pages(
        raw_data,
        page_size=page_size,
        user_schemas=user_schemas,
        include_active=True,
        workers=workers,
    )

    filtered = [r for r in records if r.confidence >= args.min_confidence]
    console.print(f"[bold green]Raw Page Hunter carved {len(filtered)} records from candidate SQLite pages![/bold green]")

    if args.export:
        try:
            res = dispatch_export(
                filtered,
                args.export,
                title=f"Raw Carved Evidence Report - {image_path.name}",
                integrity_info={"raw_image": hash_file(image_path)},
                lang=getattr(args, "lang", None),
            )
            console.print(f"[bold green]{t('export_success', count=res['written'], fmt=res['format'], path=res['path'])}[/]")
        except Exception as e:
            console.print(f"[bold red]Export Error:[/] {e}")
            sys.exit(1)
        return

    # Print Table
    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Block", style="dim", justify="right", width=6)
    table.add_column("Offset", style="dim", justify="right", width=8)
    table.add_column("Source", style="bold yellow", width=14)
    table.add_column("Conf", justify="right", width=6)
    table.add_column("Table", style="magenta", width=14)
    table.add_column("RowID", justify="right", width=6)
    table.add_column("Values", style="white")

    limit = args.limit or 50
    for r in filtered[:limit]:
        conf_color = "green" if r.confidence >= 0.85 else "yellow"
        val_strs = []
        for i, val in enumerate(r.values):
            col_name = r.column_names[i] if i < len(r.column_names) else f"c{i}"
            val_strs.append(f"[dim]{col_name}:[/dim] {sanitize_display(str(val))}")
        table.add_row(
            str(r.page_id),
            hex(r.offset_in_page),
            r.source,
            f"[{conf_color}]{r.confidence:.2f}[/{conf_color}]",
            r.matched_table or "[dim]?[/dim]",
            str(r.rowid) if r.rowid is not None else "[dim]?[/dim]",
            ", ".join(val_strs),
        )

    console.print(table)
    if len(filtered) > limit:
        console.print(f"[dim]{t('more_records', count=len(filtered) - limit)}[/dim]")


def main() -> None:
    examples = """
Exemples d'utilisation concrets / Concrete usage examples:
  1. Inspecter la structure et les tables d'une base :
     sqlite-carver info ma_base.db

  2. Carving complet (actifs + supprimés dans le slack/freeblocks) :
     sqlite-carver carve ma_base.db

  3. Isoler UNIQUEMENT les enregistrements supprimés :
     sqlite-carver carve ma_base.db --deleted-only

  4. Générer le rapport interactif HTML (avec recherche, timeline WAL, horodatages) :
     sqlite-carver carve ma_base.db --export rapport.html

  5. Extraire automatiquement les fichiers intégrés dans les BLOBs (PNG, JPEG, PDF...) :
     sqlite-carver carve ma_base.db --dump-blobs ./fichiers_extraits

  6. Exporter la base reconstituée avec ses colonnes d'origine dans SQLite :
     sqlite-carver carve ma_base.db --export preuve_reconstituee.sqlite

  7. Recherche récursive d'un mot-clé (texte, WAL, BLOBs bplist/protobuf) :
     sqlite-carver search ma_base.db "mon_mot_cle"

  8. Historique différentiel des transactions WAL avant/après :
     sqlite-carver wal-diff ma_base.db ma_base.db-wal --export timeline.html

  9. Chasseur de pages brutes (Raw Page Hunter sur dump RAM ou image disque sans en-tête) :
     sqlite-carver carve-raw dump_memoire.raw --page-size 4096 --export brut.sqlite
"""

    parser = argparse.ArgumentParser(
        prog="sqlite-carver",
        description="SQLite-Carver-Pro: Forensic Parser, Slack Carver, Freelist & WAL Diff Engine",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
    p_carve.add_argument("--mutations-only", "--diff-only", action="store_true", help="Only show carved records that represent historical mutations/updates of active records")
    p_carve.add_argument("--table", help="Filter by table name")
    p_carve.add_argument("--source", help="Filter by source (active, freeblock, slack, unallocated, freelist)")
    p_carve.add_argument("--min-confidence", type=float, default=0.5, help="Minimum confidence threshold (0.0 - 1.0)")
    p_carve.add_argument("--limit", type=int, default=50, help="Limit number of rows displayed in console")
    p_carve.add_argument("--export", help="Export to path (.html, .json, .jsonl, .csv, .parquet, .sqlite, .db)")
    p_carve.add_argument("--dump-blobs", help="Directory path to dump all extracted/carved BLOB files with auto-detected extensions")
    p_carve.add_argument("--lang", "-l", choices=["en", "fr"], default="en", help="Language interface")
    p_carve.set_defaults(func=cmd_carve)

    # carve-raw (Raw Page Hunter)
    p_raw = subparsers.add_parser("carve-raw", help="Carve records from unallocated disk images, RAM dumps, or raw binary streams without SQLite header")
    p_raw.add_argument("image_path", help="Path to raw binary file, memory dump, or unallocated disk image")
    p_raw.add_argument("--page-size", type=int, default=4096, choices=[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536], help="Candidate page size to scan (default: 4096)")
    p_raw.add_argument("--schema", help="Path to SQL file with table schemas to guide recovery")
    p_raw.add_argument("--workers", "-w", type=int, default=1, help="Number of concurrent worker threads for parallel scanning (default: 1)")
    p_raw.add_argument("--min-confidence", type=float, default=0.5, help="Minimum confidence threshold (0.0 - 1.0)")
    p_raw.add_argument("--limit", type=int, default=50, help="Limit number of rows displayed in console")
    p_raw.add_argument("--export", help="Export to path (.html, .json, .jsonl, .csv, .parquet, .sqlite, .db)")
    p_raw.add_argument("--lang", "-l", choices=["en", "fr"], default="en", help="Language interface")
    p_raw.set_defaults(func=cmd_carve_raw)

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
    p_search.add_argument("--export", help="Export matches to path (.html, .json, .jsonl, .csv, .parquet, .sqlite, .db)")
    p_search.add_argument("--dump-blobs", help="Directory path to dump matched BLOB files with auto-detected extensions")
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
