"""
sqlite_carver.core.integrity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Cryptographic verification and chain-of-custody evidence integrity engine.
Computes deterministic record-level SHA-256 hashes and file integrity digests.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def hash_bytes(data: bytes | memoryview) -> Dict[str, str]:
    """Computes SHA-256 and MD5 digests of a byte buffer."""
    buf = bytes(data)
    return {
        "sha256": hashlib.sha256(buf).hexdigest(),
        "md5": hashlib.md5(buf).hexdigest(),
    }


def hash_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Computes streaming SHA-256 and MD5 hashes of a file on disk."""
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return {}

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0

    with open(p, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)

    return {
        "filename": p.name,
        "size_bytes": size,
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }


def compute_record_evidence_hash(
    page_id: int,
    offset_in_page: int,
    source: str,
    matched_table: Optional[str],
    rowid: Optional[int],
    values: List[Any],
) -> str:
    """
    Computes a deterministic cryptographic SHA-256 hash for a carved evidence record.
    Used for digital forensics chain of custody and immutability verification.
    """
    # Normalize values for deterministic hashing
    normalized_vals = []
    for v in values:
        if isinstance(v, bytes):
            normalized_vals.append(f"blob:{v.hex()}")
        elif isinstance(v, float):
            normalized_vals.append(f"float:{v:.6f}")
        else:
            normalized_vals.append(str(v))

    record_repr = {
        "page_id": page_id,
        "offset": offset_in_page,
        "source": source,
        "table": matched_table or "",
        "rowid": rowid,
        "values": normalized_vals,
    }
    encoded = json.dumps(record_repr, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def check_anti_forensics_anomalies(
    parser: Any,
    actual_file_size: Optional[int] = None,
    file_size: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Detects anti-forensics, tampering, or corruption indicators in SQLite database files:
    1. Header change counter vs version-valid-for discrepancy.
    2. Header declared database size vs physical file size discrepancy (EOF slack / hidden tail data / truncation).
    3. Freelist trunk/leaf page count vs declared total_freelist_pages discrepancy.
    """
    anomalies: List[Dict[str, Any]] = []
    if not parser or not parser.header:
        return anomalies

    hdr = parser.header
    f_size = file_size if file_size is not None else (actual_file_size if actual_file_size is not None else parser.size)

    # 1. Change counter vs version_valid_for
    # In rollback journal mode (write_version == 1), file_change_counter and version_valid_for
    # must match on clean shutdown. A mismatch indicates an interrupted write, uncommitted rollback,
    # forced power loss, or manual binary hex editing.
    if hdr.write_version == 1 and hdr.file_change_counter != hdr.version_valid_for:
        anomalies.append({
            "code": "CHANGE_COUNTER_MISMATCH",
            "severity": "HIGH",
            "title": "Change Counter Mismatch (Interrupted Transaction or Hex Edit)",
            "details": (
                f"file_change_counter ({hdr.file_change_counter}) != "
                f"version_valid_for ({hdr.version_valid_for}). "
                "Indicates an uncommitted write, forced power loss, or manual tampering."
            ),
        })

    # 2. In-header page count vs physical file size (EOF Slack / Truncation)
    if hdr.in_header_db_size_pages > 0 and hdr.page_size > 0:
        logical_bytes = hdr.in_header_db_size_pages * hdr.page_size
        if f_size > logical_bytes:
            slack_len = f_size - logical_bytes
            anomalies.append({
                "code": "EOF_SLACK_DETECTED",
                "severity": "HIGH" if slack_len > 4096 else "MEDIUM",
                "title": f"EOF Slack Space Detected ({slack_len:,} bytes past DB end)",
                "details": (
                    f"Physical file size ({f_size:,} bytes) exceeds logical header size "
                    f"({logical_bytes:,} bytes, {hdr.in_header_db_size_pages} pages). "
                    f"{slack_len:,} trailing bytes may conceal anti-forensic payloads or deleted pages."
                ),
                "slack_bytes": slack_len,
                "logical_size": logical_bytes,
                "actual_size": f_size,
            })
        elif f_size < logical_bytes:
            missing_len = logical_bytes - f_size
            anomalies.append({
                "code": "PHYSICALLY_TRUNCATED_DATABASE",
                "severity": "HIGH",
                "title": f"Physically Truncated Database ({missing_len:,} bytes missing)",
                "details": (
                    f"Physical file size ({f_size:,} bytes) is less than logical header size "
                    f"({logical_bytes:,} bytes, {hdr.in_header_db_size_pages} pages). "
                    "Database file has been truncated."
                ),
                "missing_bytes": missing_len,
            })

    # 3. Freelist count consistency
    try:
        actual_freelist_pages = parser.parse_freelist_pages()
        if len(actual_freelist_pages) != hdr.total_freelist_pages:
            anomalies.append({
                "code": "FREELIST_COUNT_MISMATCH",
                "severity": "MEDIUM",
                "title": "Freelist Page Count Discrepancy",
                "details": (
                    f"Header declares {hdr.total_freelist_pages} freelist pages, "
                    f"but traversed trunk/leaf chains yielded {len(actual_freelist_pages)} pages."
                ),
            })
    except Exception:
        pass

    # 4. Reserved bytes per page (Anti-Forensics / Steganography / Custom Payload Area)
    if hdr.reserved_space > 0:
        total_res = hdr.reserved_space * parser.page_count
        anomalies.append({
            "code": "PAGE_RESERVED_SPACE_DETECTED",
            "severity": "HIGH",
            "title": f"Page Reserved Space Active ({hdr.reserved_space} B/page, {total_res:,} B total)",
            "details": (
                f"SQLite header byte 20 specifies {hdr.reserved_space} reserved bytes at the end of every page "
                f"({total_res:,} bytes total across {parser.page_count} pages). "
                "SQLite B-tree logic ignores this trailing space; it is frequently utilized for "
                "steganography, hidden anti-forensic payloads, or custom cryptographic extensions."
            ),
            "reserved_space_per_page": hdr.reserved_space,
            "total_reserved_bytes": total_res,
        })

    # 5. Auto-Vacuum & Pointermap status (Cellebrite Slide 7)
    if getattr(hdr, "has_pointermap", False):
        if hdr.vacuum_mode == "FULL":
            anomalies.append({
                "code": "AUTO_VACUUM_FULL_ACTIVE",
                "severity": "LOW",
                "title": f"Full Auto-Vacuum Active (Pointermap pages present, Root: {hdr.largest_root_btree_page})",
                "details": (
                    f"Auto-vacuum is set to FULL (largest root b-tree page: {hdr.largest_root_btree_page}). "
                    "Deleted pages are automatically relocated and truncated at commit time, "
                    "preventing forensic record recovery from trailing EOF slack."
                ),
                "vacuum_mode": "FULL",
                "largest_root_btree_page": hdr.largest_root_btree_page,
            })
        elif hdr.vacuum_mode == "INCREMENTAL":
            anomalies.append({
                "code": "AUTO_VACUUM_INCREMENTAL_ACTIVE",
                "severity": "LOW",
                "title": f"Incremental Vacuum Active (Pointermap pages present, Root: {hdr.largest_root_btree_page})",
                "details": (
                    f"Incremental vacuum is enabled (flag: {hdr.incremental_vacuum_flag}, "
                    f"largest root b-tree page: {hdr.largest_root_btree_page}). "
                    "Pointermap pages are active, but unallocated pages persist until PRAGMA incremental_vacuum is invoked."
                ),
                "vacuum_mode": "INCREMENTAL",
                "largest_root_btree_page": hdr.largest_root_btree_page,
            })

    # 6. Anti-Forensic PRAGMA secure_delete Detection (Cellebrite Slide 9)
    # When secure_delete is active, SQLite overwrites deleted cell payload in freeblocks with 0x00.
    try:
        total_fb_bytes = 0
        total_zero_bytes = 0
        for pid in range(1, parser.page_count + 1):
            fbs = parser.get_freeblocks(pid)
            for fb in fbs:
                if len(fb.raw_bytes) > 4:
                    payload = fb.raw_bytes[4:]
                    total_fb_bytes += len(payload)
                    total_zero_bytes += payload.count(b"\x00")

        if total_fb_bytes >= 16:
            zero_ratio = total_zero_bytes / total_fb_bytes
            if zero_ratio >= 0.90:
                anomalies.append({
                    "code": "PRAGMA_SECURE_DELETE_DETECTED",
                    "severity": "HIGH",
                    "title": f"Anti-Forensics: PRAGMA secure_delete Detected ({zero_ratio:.1%} Wiped Zeros)",
                    "details": (
                        f"Freeblock areas across database pages contain {zero_ratio:.1%} zero bytes "
                        f"({total_zero_bytes}/{total_fb_bytes} bytes are 0x00). "
                        "PRAGMA secure_delete was enabled on this database, which actively wipes deleted "
                        "cell payloads with zeros and suppresses forensic cell carving."
                    ),
                    "zero_ratio": zero_ratio,
                    "total_freeblock_bytes": total_fb_bytes,
                    "zero_bytes": total_zero_bytes,
                })
    except Exception:
        pass

    return anomalies


