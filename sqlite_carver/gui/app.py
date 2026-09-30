"""
Modern Desktop GUI for SQLite Carver Pro.

Built with CustomTkinter for a sleek, modern, dark-mode forensic dashboard.
Features:
- High-DPI dark mode interface with forensic metric cards.
- Background multi-threaded carving engine (non-blocking UI).
- Real-time instant search & multi-criteria filtering across all carved columns.
- Built-in Forensic Hex & ASCII Inspector modal with clipboard copy & raw bin export.
- On-the-fly SQLCipher decryption credential input.
- One-click HTML, CSV, JSON, and reconstructed SQLite export.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any, Dict, List, Optional
import webbrowser

# Ensure parent directory is in sys.path when executed directly
if __package__ is None or __package__ == "":
    _parent = str(Path(__file__).resolve().parent.parent.parent)
    if _parent not in sys.path:
        sys.path.insert(0, _parent)

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from sqlite_carver import __version__
from sqlite_carver.core.carver import CarvedRecord, SQLiteCarver
from sqlite_carver.core.correlator import EntityCorrelator
from sqlite_carver.core.encryption import analyze_database_encryption, try_decrypt_database
from sqlite_carver.core.parser import DatabaseParser
from sqlite_carver.core.wal_diff import RowMutation, WalDiffEngine
from sqlite_carver.exporters.export import dispatch_export, record_to_dict, mutation_to_dict
from sqlite_carver.i18n import get_language, set_language, t


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class HexInspectorModal(ctk.CTkToplevel):
    """Forensic Hex and ASCII byte inspector dialog."""

    def __init__(self, parent: Any, record: Any, title_text: str = "Forensic Hex & ASCII Inspector"):
        super().__init__(parent)
        self.title(title_text)
        self.geometry("860x580")
        self.minsize(700, 450)
        self.transient(parent)
        self.grab_set()

        self.record = record
        self.raw_bytes = bytes(getattr(record, "raw_payload", b"") or b"")
        self.configure(fg_color="#0f172a")

        # Header Frame
        header = ctk.CTkFrame(self, fg_color="#1e293b", corner_radius=8)
        header.pack(fill="x", padx=16, pady=(16, 8))

        title_lbl = ctk.CTkLabel(
            header,
            text=f"🔍 {title_text}",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color="#38bdf8",
        )
        title_lbl.pack(side="left", padx=14, pady=10)

        # Meta bar
        page_id = getattr(record, "page_id", "-")
        offset = f"0x{getattr(record, 'offset_in_page', 0):04x}"
        tbl = getattr(record, "matched_table", None) or getattr(record, "table_name", "Unknown")
        rowid = getattr(record, "rowid", "-")
        source = getattr(record, "source", "unknown")
        size_bytes = len(self.raw_bytes)

        meta_frame = ctk.CTkFrame(self, fg_color="#0b1120", corner_radius=6)
        meta_frame.pack(fill="x", padx=16, pady=4)

        meta_text = (
            f"Page: {page_id}  |  Offset: {offset}  |  Table: {tbl}  |  "
            f"RowID: {rowid}  |  Source: {source}  |  Size: {size_bytes:,} bytes"
        )
        ctk.CTkLabel(
            meta_frame,
            text=meta_text,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#94a3b8",
        ).pack(side="left", padx=12, pady=6)

        # Action Toolbar
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=16, pady=6)

        btn_copy_hex = ctk.CTkButton(
            toolbar,
            text="📋 Copy Hex",
            width=110,
            height=28,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#1e293b",
            hover_color="#334155",
            command=self._copy_hex,
        )
        btn_copy_hex.pack(side="left", padx=(0, 8))

        btn_copy_ascii = ctk.CTkButton(
            toolbar,
            text="📝 Copy ASCII",
            width=110,
            height=28,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#1e293b",
            hover_color="#334155",
            command=self._copy_ascii,
        )
        btn_copy_ascii.pack(side="left", padx=8)

        btn_save_bin = ctk.CTkButton(
            toolbar,
            text="💾 Save .bin",
            width=110,
            height=28,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#1e293b",
            hover_color="#334155",
            command=self._save_bin,
        )
        btn_save_bin.pack(side="left", padx=8)

        btn_close = ctk.CTkButton(
            toolbar,
            text="Close",
            width=80,
            height=28,
            fg_color="#334155",
            hover_color="#475569",
            command=self.destroy,
        )
        btn_close.pack(side="right")

        # Text container (Monospace hex view)
        self.text_box = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#020617",
            text_color="#e2e8f0",
            border_width=1,
            border_color="#334155",
            corner_radius=8,
        )
        self.text_box.pack(fill="both", expand=True, padx=16, pady=(4, 16))

        self._render_hex()

    def _render_hex(self) -> None:
        if not self.raw_bytes:
            self.text_box.insert("1.0", "No raw byte payload available for this record.")
            return

        lines = []
        data = self.raw_bytes
        length = len(data)

        for i in range(0, length, 16):
            chunk = data[i : i + 16]
            offset_str = f"{i:08x}"
            hex_tokens = [f"{b:02x}" for b in chunk]
            if len(hex_tokens) < 16:
                hex_tokens.extend(["  "] * (16 - len(hex_tokens)))

            hex_str = " ".join(hex_tokens[:8]) + "  " + " ".join(hex_tokens[8:])
            ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset_str}  {hex_str}  |{ascii_chars}|")

        self.text_box.insert("1.0", "\n".join(lines))
        self.text_box.configure(state="disabled")

    def _copy_hex(self) -> None:
        hex_val = self.raw_bytes.hex()
        self.clipboard_clear()
        self.clipboard_append(hex_val)
        messagebox.showinfo("Copied", f"Copied {len(hex_val)} hex characters to clipboard.")

    def _copy_ascii(self) -> None:
        ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in self.raw_bytes)
        self.clipboard_clear()
        self.clipboard_append(ascii_text)
        messagebox.showinfo("Copied", "Copied ASCII representation to clipboard.")

    def _save_bin(self) -> None:
        p = getattr(self.record, "page_id", 0)
        off = getattr(self.record, "offset_in_page", 0)
        default_name = f"payload_p{p}_off0x{off:04x}.bin"
        target = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".bin",
            initialfile=default_name,
            filetypes=[("Binary file", "*.bin"), ("All files", "*.*")],
        )
        if target:
            Path(target).write_bytes(self.raw_bytes)
            messagebox.showinfo("Saved", f"Raw payload written to {target}")


class SQLiteCarverApp(ctk.CTk):
    """Main Application Window for SQLite Carver Pro."""

    def __init__(self, initial_db: Optional[str] = None, initial_key: Optional[str] = None, lang: str = "en"):
        super().__init__()
        self.title(f"SQLite Carver Pro v{__version__} - Forensic Investigation Suite")
        self.geometry("1340x860")
        self.minsize(1080, 700)

        self.active_lang = lang
        set_language(lang)

        self.db_path: Optional[Path] = Path(initial_db) if initial_db else None
        self.raw_data: Optional[bytes] = None
        self.carver: Optional[SQLiteCarver] = None
        self.all_evidence: List[Any] = []
        self.filtered_evidence: List[Any] = []
        self.search_job: Optional[str] = None
        self.is_carving = False

        self._build_ui()

        if initial_key:
            self.key_entry.delete(0, "end")
            self.key_entry.insert(0, initial_key)

        if self.db_path and self.db_path.exists():
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, str(self.db_path))
            self._start_carving()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ----------------------------------------------------
        # 1. HEADER SECTION
        # ----------------------------------------------------
        header = ctk.CTkFrame(self, fg_color="#0f172a", height=60, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        logo_label = ctk.CTkLabel(
            header,
            text="🔍 SQLite Carver Pro",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color="#38bdf8",
        )
        logo_label.grid(row=0, column=0, padx=(18, 10), pady=12, sticky="w")

        badge = ctk.CTkLabel(
            header,
            text=f"v{__version__} PRO",
            font=ctk.CTkFont(size=10, weight="bold"),
            fg_color="#0369a1",
            text_color="#f0f9ff",
            corner_radius=6,
            padx=6,
            pady=2,
        )
        badge.grid(row=0, column=1, sticky="w")

        author_label = ctk.CTkLabel(
            header,
            text="Dam-FOR3K | Forensic Grade",
            font=ctk.CTkFont(size=12),
            text_color="#64748b",
        )
        author_label.grid(row=0, column=2, padx=(10, 16), sticky="e")

        self.btn_lang = ctk.CTkButton(
            header,
            text="🇫🇷 Français" if self.active_lang == "en" else "🇬🇧 English",
            width=100,
            height=28,
            fg_color="#1e293b",
            hover_color="#334155",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._toggle_language,
        )
        self.btn_lang.grid(row=0, column=3, padx=(0, 18), sticky="e")

        # ----------------------------------------------------
        # 2. TOP CONTROL CARD (File, Key, Options, Actions)
        # ----------------------------------------------------
        ctrl_card = ctk.CTkFrame(self, fg_color="#1e293b", corner_radius=10)
        ctrl_card.grid(row=1, column=0, sticky="ew", padx=16, pady=12)
        ctrl_card.grid_columnconfigure(1, weight=1)

        # File row
        lbl_file = ctk.CTkLabel(ctrl_card, text="Database File:", font=ctk.CTkFont(weight="bold"))
        lbl_file.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="w")

        self.file_entry = ctk.CTkEntry(
            ctrl_card,
            placeholder_text="Select SQLite Database, WAL, or raw disk image...",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.file_entry.grid(row=0, column=1, padx=8, pady=(12, 6), sticky="ew")

        btn_browse = ctk.CTkButton(
            ctrl_card,
            text="📂 Browse...",
            width=100,
            font=ctk.CTkFont(weight="bold"),
            command=self._browse_file,
        )
        btn_browse.grid(row=0, column=2, padx=(4, 14), pady=(12, 6))

        # Credentials & Toggles row
        lbl_key = ctk.CTkLabel(ctrl_card, text="Decryption Key (SQLCipher / SEE):", font=ctk.CTkFont(weight="bold"))
        lbl_key.grid(row=1, column=0, padx=14, pady=6, sticky="w")

        key_box = ctk.CTkFrame(ctrl_card, fg_color="transparent")
        key_box.grid(row=1, column=1, columnspan=2, padx=(8, 14), pady=6, sticky="ew")
        key_box.grid_columnconfigure(0, weight=1)

        self.key_entry = ctk.CTkEntry(
            key_box,
            placeholder_text="Passphrase or raw hex AES key for SQLCipher & SEE (AES-OFB)...",
            show="•",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.key_entry.grid(row=0, column=0, sticky="ew")

        self.btn_show_key = ctk.CTkButton(
            key_box,
            text="👁",
            width=36,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_show_key,
        )
        self.btn_show_key.grid(row=0, column=1, padx=(6, 0))

        # Options Checkboxes & Launch Button
        opt_box = ctk.CTkFrame(ctrl_card, fg_color="transparent")
        opt_box.grid(row=2, column=0, columnspan=3, padx=14, pady=(8, 12), sticky="ew")
        opt_box.grid_columnconfigure(6, weight=1)

        self.chk_active = ctk.CTkCheckBox(opt_box, text="Active Cells", font=ctk.CTkFont(size=12))
        self.chk_active.select()
        self.chk_active.grid(row=0, column=0, padx=(0, 12))

        self.chk_freeblocks = ctk.CTkCheckBox(opt_box, text="Freeblocks", font=ctk.CTkFont(size=12))
        self.chk_freeblocks.select()
        self.chk_freeblocks.grid(row=0, column=1, padx=12)

        self.chk_slack = ctk.CTkCheckBox(opt_box, text="Slack & Unallocated", font=ctk.CTkFont(size=12))
        self.chk_slack.select()
        self.chk_slack.grid(row=0, column=2, padx=12)

        self.chk_wal = ctk.CTkCheckBox(opt_box, text="WAL / Journal Diffs", font=ctk.CTkFont(size=12))
        self.chk_wal.select()
        self.chk_wal.grid(row=0, column=3, padx=12)

        self.chk_resurrect = ctk.CTkCheckBox(opt_box, text="Cross-Index Recovery", font=ctk.CTkFont(size=12))
        self.chk_resurrect.select()
        self.chk_resurrect.grid(row=0, column=4, padx=12)

        self.btn_carve = ctk.CTkButton(
            opt_box,
            text="🚀 Start Deep Carving",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=34,
            command=self._start_carving,
        )
        self.btn_carve.grid(row=0, column=7, padx=(10, 0))

        # ----------------------------------------------------
        # 3. METRIC CARDS BANNER (6 Stats)
        # ----------------------------------------------------
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))
        for col in range(6):
            stats_frame.grid_columnconfigure(col, weight=1)

        self.card_total = self._create_stat_card(stats_frame, 0, "Total Evidence", "0", "All Provenances", "#38bdf8")
        self.card_active = self._create_stat_card(stats_frame, 1, "Active Cells", "0", "Allocated Records", "#22c55e")
        self.card_fb = self._create_stat_card(stats_frame, 2, "Freeblocks", "0", "Deleted Linked Blocks", "#f59e0b")
        self.card_slack = self._create_stat_card(stats_frame, 3, "Slack & Margins", "0", "Cell Slack / Gaps", "#ec4899")
        self.card_resurrect = self._create_stat_card(stats_frame, 4, "Resurrected", "0", "Recovered from Index", "#a855f7")
        self.card_wal = self._create_stat_card(stats_frame, 5, "WAL Mutations", "0", "Transactions & Diffs", "#06b6d4")

        # ----------------------------------------------------
        # 4. SEARCH & FILTER CONTROLS BAR
        # ----------------------------------------------------
        search_card = ctk.CTkFrame(self, fg_color="#1e293b", corner_radius=8)
        search_card.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 8))
        search_card.grid_columnconfigure(0, weight=1)

        search_box = ctk.CTkFrame(search_card, fg_color="transparent")
        search_box.pack(fill="x", padx=12, pady=8)
        search_box.grid_columnconfigure(0, weight=1)

        self.search_entry = ctk.CTkEntry(
            search_box,
            placeholder_text="🔎 Instant search across all columns, keywords, emails, rowids, payload bytes...",
            font=ctk.CTkFont(size=12),
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", lambda e: self._on_search_change())

        self.table_filter = ctk.CTkComboBox(
            search_box,
            values=["All Tables"],
            width=150,
            command=lambda v: self._apply_filters(),
        )
        self.table_filter.grid(row=0, column=1, padx=6)

        self.source_filter = ctk.CTkComboBox(
            search_box,
            values=["All Sources", "Active", "Freeblocks", "Slack", "Unallocated", "Resurrected", "WAL / Journal"],
            width=150,
            command=lambda v: self._apply_filters(),
        )
        self.source_filter.grid(row=0, column=2, padx=6)

        # Export Buttons Group
        self.btn_export_html = ctk.CTkButton(
            search_box,
            text="🌐 HTML Report",
            width=110,
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(weight="bold"),
            command=self._export_html,
        )
        self.btn_export_html.grid(row=0, column=3, padx=(8, 4))

        self.btn_export_more = ctk.CTkButton(
            search_box,
            text="💾 Export...",
            width=90,
            fg_color="#475569",
            hover_color="#334155",
            font=ctk.CTkFont(weight="bold"),
            command=self._export_dialog,
        )
        self.btn_export_more.grid(row=0, column=4, padx=(4, 0))

        # ----------------------------------------------------
        # 5. EVIDENCE DATA TABLE (Treeview)
        # ----------------------------------------------------
        table_card = ctk.CTkFrame(self, fg_color="#1e293b", corner_radius=10)
        table_card.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0, 8))
        self.grid_rowconfigure(4, weight=1)

        # Style TTK Treeview for custom dark styling
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#0f172a",
            foreground="#f8fafc",
            fieldbackground="#0f172a",
            rowheight=26,
            font=("Segoe UI", 10),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#1e293b",
            foreground="#38bdf8",
            font=("Segoe UI", 10, "bold"),
            borderwidth=1,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#0284c7")],
            foreground=[("selected", "#ffffff")],
        )

        columns = ("page", "offset", "source", "conf", "table", "rowid", "columns_data")
        self.tree = ttk.Treeview(table_card, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("page", text="Page", command=lambda: self._sort_column("page", False))
        self.tree.heading("offset", text="Offset", command=lambda: self._sort_column("offset", False))
        self.tree.heading("source", text="Source", command=lambda: self._sort_column("source", False))
        self.tree.heading("conf", text="Conf.", command=lambda: self._sort_column("conf", False))
        self.tree.heading("table", text="Table", command=lambda: self._sort_column("table", False))
        self.tree.heading("rowid", text="RowID", command=lambda: self._sort_column("rowid", False))
        self.tree.heading("columns_data", text="Extracted Payload & Decoded Columns")

        self.tree.column("page", width=65, anchor="center")
        self.tree.column("offset", width=80, anchor="center")
        self.tree.column("source", width=110, anchor="center")
        self.tree.column("conf", width=60, anchor="center")
        self.tree.column("table", width=140, anchor="w")
        self.tree.column("rowid", width=70, anchor="center")
        self.tree.column("columns_data", width=700, anchor="w")

        # Scrollbars
        vsb = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_card, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(2, 0), pady=(2, 0))
        vsb.grid(row=0, column=1, sticky="ns", pady=(2, 0))
        hsb.grid(row=1, column=0, sticky="ew", padx=(2, 0))
        table_card.grid_rowconfigure(0, weight=1)
        table_card.grid_columnconfigure(0, weight=1)

        # Row styling tags
        self.tree.tag_configure("active", foreground="#4ade80")
        self.tree.tag_configure("freeblock", foreground="#fbbf24")
        self.tree.tag_configure("slack", foreground="#f472b6")
        self.tree.tag_configure("resurrected", foreground="#c084fc")
        self.tree.tag_configure("wal", foreground="#38bdf8")

        self.tree.bind("<Double-1>", self._on_row_double_click)
        self.tree.bind("<Return>", self._on_row_double_click)

        # Context Menu (Right-Click)
        self.context_menu = tk.Menu(self, tearoff=0, bg="#1e293b", fg="#f8fafc", activebackground="#0284c7")
        self.context_menu.add_command(label="🔍 Inspect Raw Bytes (Hex / ASCII)", command=self._inspect_selected_hex)
        self.context_menu.add_command(label="📋 Copy Row JSON", command=self._copy_selected_json)
        self.context_menu.add_command(label="📋 Copy Columns Text", command=self._copy_selected_text)
        self.tree.bind("<Button-3>", self._show_context_menu)

        # ----------------------------------------------------
        # 6. BOTTOM STATUS & PROGRESS BAR
        # ----------------------------------------------------
        status_card = ctk.CTkFrame(self, fg_color="#0f172a", height=36, corner_radius=0)
        status_card.grid(row=5, column=0, sticky="ew")
        status_card.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            status_card,
            text="Ready. Select a SQLite database file and click 'Start Deep Carving'.",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
        )
        self.status_label.grid(row=0, column=0, padx=16, pady=4, sticky="w")

        self.progress_bar = ctk.CTkProgressBar(status_card, width=200, height=10)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=0, column=1, padx=16, pady=4, sticky="e")

    def _create_stat_card(
        self,
        parent: Any,
        col: int,
        title: str,
        val: str,
        subtext: str,
        color: str,
    ) -> Dict[str, Any]:
        card = ctk.CTkFrame(parent, fg_color="#1e293b", corner_radius=8)
        card.grid(row=0, column=col, padx=4, pady=2, sticky="ew")

        lbl_t = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11, weight="bold"), text_color="#94a3b8")
        lbl_t.pack(pady=(8, 0))

        lbl_v = ctk.CTkLabel(card, text=val, font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"), text_color=color)
        lbl_v.pack(pady=2)

        lbl_s = ctk.CTkLabel(card, text=subtext, font=ctk.CTkFont(size=10), text_color="#64748b")
        lbl_s.pack(pady=(0, 8))

        return {"frame": card, "val": lbl_v, "sub": lbl_s}

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Select SQLite Database or Raw Binary Dump",
            filetypes=[
                ("SQLite Databases", "*.sqlite *.db *.sqlite3 *.db3 *.fossil"),
                ("WAL Files", "*.db-wal *.wal"),
                ("Rollback Journals", "*.db-journal *.journal"),
                ("All Files", "*.*"),
            ],
        )
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)
            self.db_path = Path(path)

    def _toggle_show_key(self) -> None:
        if self.key_entry.cget("show") == "":
            self.key_entry.configure(show="•")
            self.btn_show_key.configure(text="👁")
        else:
            self.key_entry.configure(show="")
            self.btn_show_key.configure(text="🔒")

    def _toggle_language(self) -> None:
        self.active_lang = "fr" if self.active_lang == "en" else "en"
        set_language(self.active_lang)
        self.btn_lang.configure(text="🇫🇷 Français" if self.active_lang == "en" else "🇬🇧 English")

    def _start_carving(self) -> None:
        target = self.file_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please select a database file first.")
            return

        target_path = Path(target)
        if not target_path.exists():
            messagebox.showerror("File Not Found", f"Specified file does not exist:\n{target_path}")
            return

        self.db_path = target_path
        self.is_carving = True
        self.btn_carve.configure(state="disabled", text="⏳ Carving...")
        self.progress_bar.start()
        self.status_label.configure(text=f"Loading {target_path.name}...")

        # Run in worker thread to prevent UI freezing
        thread = threading.Thread(target=self._carve_worker, daemon=True)
        thread.start()

    def _carve_worker(self) -> None:
        start_time = time.time()
        try:
            target_path = self.db_path
            raw_bytes = target_path.read_bytes()
            password = self.key_entry.get().strip() or None

            # Detect if user opened a WAL file directly
            is_direct_wal = target_path.name.lower().endswith(("-wal", ".wal"))
            companion_db = None
            if is_direct_wal:
                candidates = []
                if target_path.name.endswith("-wal"):
                    candidates.append(target_path.with_name(target_path.name[:-4]))
                if target_path.suffix == ".wal":
                    candidates.append(target_path.with_suffix(".db"))
                    candidates.append(target_path.with_suffix(".sqlite"))
                    candidates.append(target_path.with_suffix(""))
                for cand in candidates:
                    if cand and cand.exists() and cand.is_file():
                        companion_db = cand
                        break

            wal_bytes = None
            if is_direct_wal:
                if companion_db:
                    wal_bytes = raw_bytes
                    raw_bytes = companion_db.read_bytes()
                else:
                    wal_bytes = raw_bytes
                    # Standalone WAL without companion DB
                    raw_bytes = b"SQLite format 3\x00" + b"\x00" * 4080

            # Check encryption
            dec_meta = None
            enc_analysis = analyze_database_encryption(raw_bytes)
            if enc_analysis.is_encrypted:
                if password:
                    self.status_label.configure(text=f"Decrypting {enc_analysis.scheme} in-memory...")
                    raw_bytes, dec_meta = try_decrypt_database(raw_bytes, password)
                else:
                    self.after(
                        0,
                        lambda: messagebox.showwarning(
                            "Encrypted Database",
                            f"Detected encrypted database: {enc_analysis.scheme}\n"
                            f"Entropy: {enc_analysis.entropy:.4f} / 8.0\n\n"
                            "Please enter the passphrase or raw AES key above.",
                        ),
                    )

            self.raw_data = raw_bytes
            self.carver = SQLiteCarver(raw_bytes)

            include_active = bool(self.chk_active.get())
            records = self.carver.carve_all(include_active=include_active)

            # Correlate FK entities
            correlator = EntityCorrelator(self.carver.schemas)
            correlator.correlate_records(records)

            # Companion WAL
            wal_mutations = []
            wal_records = []
            if self.chk_wal.get():
                if not wal_bytes:
                    for cand in [
                        Path(str(target_path) + "-wal"),
                        target_path.with_suffix(".wal"),
                        target_path.with_name(target_path.name + ".wal"),
                        target_path.with_name(target_path.stem + "-wal"),
                        target_path.with_name(target_path.stem + ".wal"),
                    ]:
                        if cand.exists() and cand.is_file():
                            wal_bytes = cand.read_bytes()
                            break

                if wal_bytes and len(wal_bytes) >= 32:
                    try:
                        wal_engine = WalDiffEngine(
                            raw_bytes,
                            wal_bytes,
                            user_schemas=list(self.carver.schemas.values()),
                            encryption_meta=dec_meta,
                        )
                        wal_mutations = wal_engine.compute_timeline_diff()
                        if wal_engine.slack_frames:
                            wal_records = wal_engine.carve_wal_slack_records()
                    except Exception as ex:
                        print(f"[WAL Warning] Error in WAL diff engine: {ex}")

            all_items = list(records) + list(wal_records) + list(wal_mutations)
            elapsed = time.time() - start_time

            # Update UI on main thread
            self.after(0, lambda: self._on_carving_complete(all_items, elapsed))

        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda: self._on_carving_error(err_msg))

    def _on_carving_complete(self, all_items: List[Any], elapsed: float) -> None:
        self.is_carving = False
        self.progress_bar.stop()
        self.progress_bar.set(1.0)
        self.btn_carve.configure(state="normal", text="🚀 Start Deep Carving")

        self.all_evidence = all_items

        # Populate tables dropdown
        table_names = sorted(list(self.carver.schemas.keys())) if self.carver else []
        self.table_filter.configure(values=["All Tables"] + table_names)
        self.table_filter.set("All Tables")

        # Update stats
        active_count = sum(1 for r in all_items if getattr(r, "source", "") == "active")
        fb_count = sum(1 for r in all_items if "freeblock" in getattr(r, "source", ""))
        slack_count = sum(1 for r in all_items if "slack" in getattr(r, "source", ""))
        unalloc_count = sum(1 for r in all_items if "unalloc" in getattr(r, "source", ""))
        resurrect_count = sum(1 for r in all_items if "resurrected" in getattr(r, "source", ""))
        wal_count = sum(1 for r in all_items if isinstance(r, RowMutation) or getattr(r, "is_mutation", False) or "wal" in getattr(r, "source", ""))

        self.card_total["val"].configure(text=f"{len(all_items):,}")
        self.card_active["val"].configure(text=f"{active_count:,}")
        self.card_fb["val"].configure(text=f"{fb_count:,}")
        self.card_slack["val"].configure(text=f"{slack_count:,}")
        self.card_slack["sub"].configure(text=f"Cell Slack ({slack_count}) | Unalloc ({unalloc_count})")
        self.card_resurrect["val"].configure(text=f"{resurrect_count:,}")
        self.card_wal["val"].configure(text=f"{wal_count:,}")

        self.status_label.configure(
            text=f"Carving complete: {len(all_items):,} evidence records recovered in {elapsed:.2f}s."
        )

        self._apply_filters()

    def _on_carving_error(self, err_msg: str) -> None:
        self.is_carving = False
        self.progress_bar.stop()
        self.progress_bar.set(0)
        self.btn_carve.configure(state="normal", text="🚀 Start Deep Carving")
        self.status_label.configure(text=f"Error: {err_msg}")
        messagebox.showerror("Carving Error", f"Failed to carve database:\n{err_msg}")

    def _on_search_change(self) -> None:
        if self.search_job:
            self.after_cancel(self.search_job)
        self.search_job = self.after(150, self._apply_filters)

    def _apply_filters(self) -> None:
        query = self.search_entry.get().strip().lower()
        sel_tbl = self.table_filter.get()
        sel_src = self.source_filter.get()

        filtered = []
        for item in self.all_evidence:
            # Source filter
            src = getattr(item, "source", "") or ("wal" if isinstance(item, RowMutation) else "unknown")
            if sel_src == "Active" and "active" not in src:
                continue
            if sel_src == "Freeblocks" and "freeblock" not in src:
                continue
            if sel_src == "Slack" and "slack" not in src:
                continue
            if sel_src == "Unallocated" and "unalloc" not in src:
                continue
            if sel_src == "Resurrected" and "resurrected" not in src:
                continue
            if sel_src == "WAL / Journal" and not (isinstance(item, RowMutation) or "wal" in src or "journal" in src):
                continue

            # Table filter
            tbl = getattr(item, "matched_table", None) or getattr(item, "table_name", "")
            if sel_tbl != "All Tables" and (not tbl or tbl.lower() != sel_tbl.lower()):
                continue

            # Text query
            if query:
                item_str = f"{tbl} {src} {getattr(item, 'rowid', '')} {getattr(item, 'values', '')}".lower()
                if query not in item_str:
                    continue

            filtered.append(item)

        self.filtered_evidence = filtered
        self._populate_tree(filtered)

    def _populate_tree(self, items: List[Any]) -> None:
        for row in self.tree.get_children():
            self.tree.delete(row)

        limit = 500  # render top 500 in UI for ultra responsive scrolling
        for i, item in enumerate(items[:limit]):
            p = getattr(item, "page_id", "-")
            off = f"0x{getattr(item, 'offset_in_page', 0):04x}" if hasattr(item, "offset_in_page") else "-"
            src = getattr(item, "source", "") or ("wal_mutation" if isinstance(item, RowMutation) else "unknown")
            conf = f"{getattr(item, 'confidence', 1.0):.2f}"
            tbl = getattr(item, "matched_table", None) or getattr(item, "table_name", "-") or "-"
            rowid = getattr(item, "rowid", "-")

            tag = "active"
            if "freeblock" in src:
                tag = "freeblock"
            elif "slack" in src or "unallocated" in src:
                tag = "slack"
            elif "resurrected" in src:
                tag = "resurrected"
            elif isinstance(item, RowMutation) or "wal" in src or "journal" in src:
                tag = "wal"

            cols_preview = ""
            if hasattr(item, "column_names") and hasattr(item, "values"):
                pairs = []
                for cn, cv in zip(item.column_names, item.values):
                    pairs.append(f"{cn}: {cv}")
                cols_preview = " | ".join(pairs)
            elif isinstance(item, RowMutation):
                if item.column_diffs:
                    diffs = [f"{d.column_name}: {d.old_value} -> {d.new_value}" for d in item.column_diffs]
                    cols_preview = f"[{item.mutation_type.value}] " + " | ".join(diffs)
                elif item.new_values:
                    cols_preview = f"[{item.mutation_type.value}] " + ", ".join(str(v) for v in item.new_values)
                elif item.old_values:
                    cols_preview = f"[{item.mutation_type.value}] " + ", ".join(str(v) for v in item.old_values)
                else:
                    cols_preview = f"[{item.mutation_type.value}] {item.details}"

            self.tree.insert(
                "",
                "end",
                iid=str(i),
                values=(p, off, src, conf, tbl, rowid, cols_preview),
                tags=(tag,),
            )

    def _on_row_double_click(self, event: Any) -> None:
        self._inspect_selected_hex()

    def _show_context_menu(self, event: Any) -> None:
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _get_selected_record(self) -> Optional[Any]:
        sel = self.tree.selection()
        if not sel:
            return None
        idx = int(sel[0])
        if 0 <= idx < len(self.filtered_evidence):
            return self.filtered_evidence[idx]
        return None

    def _inspect_selected_hex(self) -> None:
        rec = self._get_selected_record()
        if not rec:
            messagebox.showinfo("Select Record", "Please select a record from the table first.")
            return

        HexInspectorModal(self, rec)

    def _copy_selected_json(self) -> None:
        rec = self._get_selected_record()
        if not rec:
            return
        if isinstance(rec, CarvedRecord):
            d = record_to_dict(rec)
        elif isinstance(rec, RowMutation):
            d = mutation_to_dict(rec)
        else:
            d = {"raw": str(rec)}

        txt = json.dumps(d, ensure_ascii=False, indent=2)
        self.clipboard_clear()
        self.clipboard_append(txt)
        messagebox.showinfo("Copied", "Record JSON copied to clipboard.")

    def _copy_selected_text(self) -> None:
        rec = self._get_selected_record()
        if not rec:
            return
        sel = self.tree.selection()
        values = self.tree.item(sel[0], "values")
        txt = " | ".join(str(v) for v in values)
        self.clipboard_clear()
        self.clipboard_append(txt)
        messagebox.showinfo("Copied", "Record text copied to clipboard.")

    def _sort_column(self, col: str, reverse: bool) -> None:
        # Sort evidence by selected column
        def sort_key(item: Any) -> Any:
            val = getattr(item, col, None)
            if val is None and col == "table":
                val = getattr(item, "table_name", "")
            return val if val is not None else ""

        self.filtered_evidence.sort(key=sort_key, reverse=reverse)
        self._populate_tree(self.filtered_evidence)
        self.tree.heading(col, command=lambda: self._sort_column(col, not reverse))

    def _export_html(self) -> None:
        if not self.all_evidence:
            messagebox.showwarning("No Data", "Please carve a database before exporting.")
            return

        out = filedialog.asksaveasfilename(
            parent=self,
            title="Export Interactive HTML Forensic Report",
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html")],
            initialfile=f"forensic_report_{self.db_path.stem if self.db_path else 'database'}.html",
        )
        if not out:
            return

        try:
            schemas_dict = self.carver.schemas if self.carver else None
            storage_dict = self.carver.parser.compute_storage_breakdown().to_dict() if (self.carver and self.carver.parser) else None
            dispatch_export(
                self.all_evidence,
                out,
                title=f"Forensic Report - {self.db_path.name if self.db_path else 'Database'}",
                schemas=schemas_dict,
                storage_breakdown=storage_dict,
                lang=self.active_lang,
            )
            res = messagebox.askyesno(
                "Export Successful",
                f"HTML forensic report generated successfully:\n{out}\n\nOpen in web browser now?",
            )
            if res:
                webbrowser.open(Path(out).resolve().as_uri())
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to generate HTML report:\n{e}")

    def _export_dialog(self) -> None:
        if not self.all_evidence:
            messagebox.showwarning("No Data", "Please carve a database before exporting.")
            return

        out = filedialog.asksaveasfilename(
            parent=self,
            title="Export Forensic Evidence",
            filetypes=[
                ("CSV Spreadsheet", "*.csv"),
                ("JSON Data", "*.json"),
                ("JSON Lines", "*.jsonl"),
                ("Reconstructed SQLite DB", "*.sqlite"),
                ("Apache Parquet", "*.parquet"),
            ],
            initialfile=f"carved_evidence_{self.db_path.stem if self.db_path else 'database'}",
        )
        if not out:
            return

        try:
            schemas_dict = self.carver.schemas if self.carver else None
            res = dispatch_export(
                self.all_evidence,
                out,
                schemas=schemas_dict,
                lang=self.active_lang,
            )
            messagebox.showinfo("Export Successful", f"Successfully exported {res['written']:,} records to:\n{out}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export evidence:\n{e}")


def launch_gui(initial_db: Optional[str] = None, initial_key: Optional[str] = None, lang: str = "en") -> None:
    """Entry point to launch the SQLite Carver Pro desktop GUI application."""
    app = SQLiteCarverApp(initial_db=initial_db, initial_key=initial_key, lang=lang)
    app.mainloop()
