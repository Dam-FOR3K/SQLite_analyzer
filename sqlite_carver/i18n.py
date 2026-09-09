"""
Internationalization (i18n) Module for SQLite-Carver-Pro.
Supports English (en) and French (fr).
"""

from typing import Dict

# Default application language
DEFAULT_LANG = "en"

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        "banner_title": "Forensic Parser, Slack Carver, Freelist & WAL Diff Engine",
        "header_analysis_title": "SQLite Database Header Analysis",
        "prop_page_size": "Page Size",
        "prop_page_count": "Page Count",
        "prop_format_version": "File Format Version",
        "prop_text_encoding": "Text Encoding",
        "prop_freelist_pages": "Freelist Pages",
        "prop_schema_version": "Schema Cookie / Version",
        "prop_app_id": "Application ID",
        "freelist_found": "Found {count} Freelist Page(s):",
        "freelist_none": "No freelist pages found in database trunk.",
        "tables_discovered": "Discovered Schema Tables",
        "th_table_name": "Table Name",
        "th_root_page": "Root Page",
        "th_columns": "Columns",
        "th_sql_def": "SQL Definition",
        "no_tables_warning": "Warning: No active sqlite_schema entries found (database may be raw or heavily damaged).",
        "carve_summary_title": "Carving & Evidence Summary",
        "total_evidence": "Total Evidence Records",
        "wal_warning": "⚠️ Warning: Companion WAL file found ({name}) but could not be parsed: {err}",
        "export_success": "Successfully exported {count} records ({fmt}) to: {path}",
        "wal_omitted_note": "Note: {count} WAL transaction mutations omitted from flat {fmt} export. Use .html or .json to include full WAL timeline diffs.",
        "wal_matches_omitted": "Note: {count} WAL transaction matches omitted from flat {fmt} export. Use .html or .json to export WAL diffs.",
        "search_summary_title": "🔍 Forensic Search Summary",
        "search_query": "Search Query",
        "search_matches": "Matches Found",
        "search_scope": "Scope",
        "search_scope_deleted": "Deleted Only",
        "search_scope_active": "Active + Carved",
        "search_none": "No matching occurrences found in database records, slack, freeblocks, or embedded BLOBs.",
        "wal_header_info": "WAL File Header: Version {version}, Page Size {size}B, Checkpoint Seq {seq}, Frames: {frames}",
        "wal_timeline_title": "WAL Transaction Timeline & Row Mutations",
        "th_frame": "Frame",
        "th_page": "Page",
        "th_mutation": "Mutation",
        "th_table": "Table",
        "th_rowid": "RowID",
        "th_diff_content": "Diff / Content",
        "th_offset": "Offset",
        "th_source": "Source",
        "th_conf": "Conf.",
        "th_values": "Values",
        "th_container": "Container",
        "th_matched_snippet": "Matched Snippet",
        "blob_panel_title": "Decoded Payload: [cyan]{fmt}[/cyan] (Confidence: {conf:.2f})",
        "blob_metadata_title": "Structure Metadata",
        "more_records": "... and {count} more records (use --limit 0 or --export to view all)",
        "file_not_found": "Database file not found: {path}",
        "wal_not_found": "WAL file not found: {path}",
        "invalid_wal_header": "Invalid WAL file header: {path}",
        "hex_error": "Invalid hex string: {err}",
        "blob_param_error": "Must specify either --hex or --file",
    },
    "fr": {
        "banner_title": "Moteur Forensique, Carving de Slack, Freelist & Diff WAL",
        "header_analysis_title": "Analyse de l'En-tête de Base SQLite",
        "prop_page_size": "Taille de Page",
        "prop_page_count": "Nombre de Pages",
        "prop_format_version": "Version du Format de Fichier",
        "prop_text_encoding": "Encodage du Texte",
        "prop_freelist_pages": "Pages de Freelist",
        "prop_schema_version": "Cookie de Schéma / Version",
        "prop_app_id": "Application ID",
        "freelist_found": "Trouvé {count} Page(s) de Freelist :",
        "freelist_none": "Aucune page de freelist trouvée dans le tronc.",
        "tables_discovered": "Tables de Schéma Découvertes",
        "th_table_name": "Nom de Table",
        "th_root_page": "Page Racine",
        "th_columns": "Colonnes",
        "th_sql_def": "Définition SQL",
        "no_tables_warning": "Avertissement : Aucune table active trouvée dans sqlite_schema (base brute ou corrompue).",
        "carve_summary_title": "Synthèse du Carving & Preuves Numériques",
        "total_evidence": "Total des Preuves",
        "wal_warning": "⚠️ Avertissement : Fichier WAL compagnon trouvé ({name}) mais illisible : {err}",
        "export_success": "Export réussi de {count} enregistrements ({fmt}) vers : {path}",
        "wal_omitted_note": "Note : {count} mutations WAL écartées du format plat {fmt}. Utilisez .html ou .json pour inclure la timeline WAL.",
        "wal_matches_omitted": "Note : {count} correspondances WAL écartées de l'export {fmt}. Utilisez .html ou .json pour inclure le WAL.",
        "search_summary_title": "🔍 Synthèse de Recherche Forensique",
        "search_query": "Requête de Recherche",
        "search_matches": "Résultats Trouvés",
        "search_scope": "Périmètre",
        "search_scope_deleted": "Supprimés Uniquement",
        "search_scope_active": "Actifs + Carvés",
        "search_none": "Aucune correspondance trouvée dans les cellules, le slack, les freeblocks ou les BLOBs.",
        "wal_header_info": "En-tête Journal WAL : Version {version}, Taille Page {size}B, Checkpoint Seq {seq}, Trames : {frames}",
        "wal_timeline_title": "Timeline des Transactions WAL & Mutations de Lignes",
        "th_frame": "Trame",
        "th_page": "Page",
        "th_mutation": "Mutation",
        "th_table": "Table",
        "th_rowid": "RowID",
        "th_diff_content": "Diff / Données",
        "th_offset": "Offset",
        "th_source": "Source",
        "th_conf": "Conf.",
        "th_values": "Valeurs",
        "th_container": "Conteneur",
        "th_matched_snippet": "Extrait Correspondant",
        "blob_panel_title": "Payload Décodé : [cyan]{fmt}[/cyan] (Confiance : {conf:.2f})",
        "blob_metadata_title": "Métadonnées de Structure",
        "more_records": "... et {count} enregistrements supplémentaires (utilisez --limit 0 ou --export pour tout voir)",
        "file_not_found": "Fichier de base de données introuvable : {path}",
        "wal_not_found": "Fichier journal WAL introuvable : {path}",
        "invalid_wal_header": "En-tête de fichier WAL invalide : {path}",
        "hex_error": "Chaîne hexadécimale invalide : {err}",
        "blob_param_error": "Vous devez spécifier soit --hex soit --file",
    },
}

_current_lang = "en"

def set_language(lang: str) -> None:
    global _current_lang
    if lang and lang.lower() in ("fr", "french", "francais"):
        _current_lang = "fr"
    else:
        _current_lang = "en"

def get_language() -> str:
    return _current_lang

def t(key: str, **kwargs) -> str:
    """Translates a message key according to current language."""
    msg = TRANSLATIONS.get(_current_lang, TRANSLATIONS["en"]).get(key)
    if msg is None:
        msg = TRANSLATIONS["en"].get(key, key)
    if kwargs:
        return msg.format(**kwargs)
    return msg
