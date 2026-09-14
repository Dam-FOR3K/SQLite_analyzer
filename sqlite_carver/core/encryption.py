"""
SQLite Encryption & Shannon Entropy Forensic Detector.

Analyzes raw file byte distribution, entropy metrics, and cryptographic
signatures to identify SQLCipher, SQLite Encryption Extension (SEE),
and encrypted mobile databases (e.g. WeChat EnMicroMsg.db, encrypted backups).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class EncryptionAnalysis:
    """Forensic assessment of database cryptographic protection and entropy."""
    is_encrypted: bool
    confidence: float
    confidence_label: str
    scheme: str
    entropy: float
    header_entropy: float
    salt_hex: str
    reasons: List[str] = field(default_factory=list)
    has_sqlite_magic: bool = False
    warning: str = ""

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        if item == "signature":
            return self.scheme
        if item == "average_entropy":
            return self.entropy
        if item == "details":
            return "; ".join(self.reasons)
        raise KeyError(item)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


def calculate_shannon_entropy(data: Union[bytes, memoryview]) -> float:
    """
    Calculates the Shannon entropy of a byte sequence.
    Returns a value between 0.0 (zero randomness / all identical bytes)
    and 8.0 (maximum randomness / ideal encryption).
    """
    length = len(data)
    if length == 0:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def analyze_database_encryption(
    raw_data: Union[bytes, memoryview],
    page_size_hint: int = 4096,
) -> EncryptionAnalysis:
    """
    Evaluates database data for encryption indicators:
    - Shannon entropy across header, body, and tail
    - Presence or absence of 'SQLite format 3\x00'
    - SQLCipher salt heuristic (16 random bytes at offset 0)
    - Uniform byte distribution
    """
    data_len = len(raw_data)
    if data_len < 16:
        return EncryptionAnalysis(
            is_encrypted=False,
            confidence=0.0,
            confidence_label="NONE",
            scheme="EMPTY_OR_CORRUPT",
            entropy=0.0,
            header_entropy=0.0,
            salt_hex="",
            reasons=["File too small to evaluate"],
        )

    has_sqlite_magic = (bytes(raw_data[:16]) == b"SQLite format 3\x00")
    header_chunk = raw_data[:min(data_len, 4096)]
    header_entropy = calculate_shannon_entropy(header_chunk)

    # Sample middle and tail blocks if file is large enough
    sample_entropies = [header_entropy]
    if data_len >= 8192:
        mid_offset = data_len // 2
        mid_chunk = raw_data[mid_offset : mid_offset + min(4096, data_len - mid_offset)]
        sample_entropies.append(calculate_shannon_entropy(mid_chunk))
    if data_len >= 12288:
        tail_chunk = raw_data[-4096:]
        sample_entropies.append(calculate_shannon_entropy(tail_chunk))

    avg_entropy = round(sum(sample_entropies) / len(sample_entropies), 4)
    salt_candidate = bytes(raw_data[:16])

    # SQLCipher / Full Database Encryption Heuristics:
    # 1. No plaintext SQLite magic header
    # 2. High Shannon entropy (typically >= 7.80, often 7.95+)
    # 3. First 16 bytes contain a non-null, high-entropy salt
    salt_entropy = calculate_shannon_entropy(salt_candidate)
    
    is_encrypted = False
    confidence = 0.0
    confidence_label = "NONE"
    sig_name = "STANDARD_SQLITE" if has_sqlite_magic else "UNKNOWN_BINARY"
    reasons: List[str] = []
    warning = ""

    if not has_sqlite_magic and avg_entropy >= 7.80 and salt_entropy >= 3.0:
        is_encrypted = True
        confidence = 0.95 if avg_entropy >= 7.92 else 0.85
        confidence_label = "HIGH"
        sig_name = "SQLCipher / AES-256 Encrypted SQLite"
        reasons = [
            f"Missing SQLite magic header at offset 0",
            f"High Shannon entropy: {avg_entropy:.4f} / 8.0000",
            f"Candidate 16-byte cryptographic salt: {salt_candidate.hex()}",
        ]
        warning = (
            f"High entropy ({avg_entropy}/8.0) and missing SQLite magic header indicate "
            f"a fully encrypted database (SQLCipher, SEE, or encrypted mobile container). "
            f"B-Tree structures cannot be carved without the master key or passphrase."
        )
    elif has_sqlite_magic and avg_entropy >= 7.60:
        confidence = 0.40
        confidence_label = "LOW"
        sig_name = "Partial / Column-Level Encrypted SQLite"
        reasons = [
            f"Standard SQLite header detected, but overall entropy is elevated ({avg_entropy:.4f} / 8.0000)",
            f"Database may contain application-level encrypted BLOBs or ciphered fields",
        ]
        warning = (
            f"Standard SQLite header detected, but overall entropy is high ({avg_entropy}/8.0). "
            f"Database may contain application-level encrypted columns."
        )
    elif has_sqlite_magic:
        reasons = ["Standard unencrypted SQLite 3 format header detected"]
    else:
        reasons = ["Non-SQLite binary stream or unallocated fragment"]

    return EncryptionAnalysis(
        is_encrypted=is_encrypted,
        confidence=confidence,
        confidence_label=confidence_label,
        scheme=sig_name,
        entropy=avg_entropy,
        header_entropy=header_entropy,
        salt_hex=salt_candidate.hex() if is_encrypted else "",
        reasons=reasons,
        has_sqlite_magic=has_sqlite_magic,
        warning=warning,
    )
