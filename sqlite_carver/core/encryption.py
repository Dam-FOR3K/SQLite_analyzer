"""
SQLite Encryption & Shannon Entropy Forensic Detector.

Analyzes raw file byte distribution, entropy metrics, and cryptographic
signatures to identify SQLCipher, SQLite Encryption Extension (SEE),
and encrypted mobile databases (e.g. WeChat EnMicroMsg.db, encrypted backups).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
import struct
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


class DecryptionError(ValueError):
    """Raised when database decryption fails with the provided credentials."""
    pass


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

    # Check for SQLite Encryption Extension (SEE) signature:
    # In SEE (AES-OFB / AES-CCM), bytes 0-15 are encrypted (not 'SQLite format 3\x00'),
    # but bytes 16-23 are stored in plaintext so the pager knows page_size and reserve bytes.
    # Offsets 21, 22, 23 must be \x40\x20\x20 (64, 32, 32), and offset 18, 19 are write/read versions (1 or 2).
    is_see = False
    see_page_size = 0
    see_reserve = 0
    if not has_sqlite_magic and data_len >= 24:
        raw_psize = struct.unpack_from(">H", raw_data, 16)[0]
        cand_psize = 65536 if raw_psize == 1 else raw_psize
        w_ver = raw_data[18]
        r_ver = raw_data[19]
        res_b = raw_data[20]
        m_pf = raw_data[21]
        min_pf = raw_data[22]
        l_pf = raw_data[23]
        if (
            cand_psize in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
            and w_ver in (1, 2)
            and r_ver in (1, 2)
            and m_pf == 64
            and min_pf == 32
            and l_pf == 32
        ):
            is_see = True
            see_page_size = cand_psize
            see_reserve = res_b

    if is_see:
        is_encrypted = True
        confidence = 0.98
        confidence_label = "HIGH"
        sig_name = "SQLite Encryption Extension (SEE - AES-OFB)"
        reasons = [
            f"SQLite Encryption Extension (SEE) signature verified",
            f"Plaintext page geometry at offset 16-23: Page Size={see_page_size}B, Reserve={see_reserve}B, Version={w_ver}/{r_ver}",
            f"Encrypted magic header at offset 0-15 and high Shannon entropy ({avg_entropy:.4f} / 8.0000)",
        ]
        warning = (
            f"Detected SQLite Encryption Extension (SEE) database. Page geometry is intact "
            f"(page size {see_page_size}B, {see_reserve}B reserved), but B-tree pages are AES-OFB encrypted. "
            f"Use --key <passphrase> or raw key to decrypt on-the-fly."
        )
    elif not has_sqlite_magic and avg_entropy >= 7.80 and salt_entropy >= 3.0:
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


def decrypt_sqlcipher_page(
    page_data: bytes | memoryview,
    page_num: int,
    key: bytes,
    page_size: int = 4096,
    reserve: int = 48,
) -> bytes:
    """
    Decrypts a single SQLCipher page (AES-256-CBC).
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(page_data) < page_size:
        raise ValueError(f"Page data ({len(page_data)} bytes) is smaller than page_size ({page_size})")

    iv = bytes(page_data[page_size - reserve : page_size - reserve + 16])
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    if page_num == 1:
        # Page 1 has 16-byte salt at start
        ciphertext = bytes(page_data[16 : page_size - reserve])
        decrypted_body = decryptor.update(ciphertext) + decryptor.finalize()
        # Restore standard SQLite magic header at offset 0
        reconstructed = bytearray(page_size)
        reconstructed[0:16] = b"SQLite format 3\x00"
        reconstructed[16 : 16 + len(decrypted_body)] = decrypted_body
        reconstructed[page_size - reserve :] = page_data[page_size - reserve :]
        return bytes(reconstructed)
    else:
        ciphertext = bytes(page_data[0 : page_size - reserve])
        decrypted_body = decryptor.update(ciphertext) + decryptor.finalize()
        reconstructed = bytearray(page_size)
        reconstructed[0 : len(decrypted_body)] = decrypted_body
        reconstructed[page_size - reserve :] = page_data[page_size - reserve :]
        return bytes(reconstructed)


def decrypt_sqlcipher_database(
    raw_bytes: bytes | memoryview,
    password: str | bytes,
    version: int = 4,
    page_size: int = 4096,
    kdf_iter: Optional[int] = None,
    reserve: int = 48,
    return_key: bool = False,
) -> Union[bytes, Tuple[bytes, bytes]]:
    """
    Decrypts an entire SQLCipher database in memory.
    Restores valid SQLite 3 format header so it can be parsed and carved seamlessly.
    """
    if len(raw_bytes) < page_size:
        raise ValueError("Database too small to be a valid SQLCipher database.")

    raw_bytes = bytes(raw_bytes)
    salt = raw_bytes[:16]

    # Parse raw key vs passphrase
    key = None
    if isinstance(password, str):
        clean_pw = password.strip()
        if clean_pw.lower().startswith("0x"):
            clean_pw = clean_pw[2:]
        elif clean_pw.lower().startswith("x'") and clean_pw.endswith("'"):
            clean_pw = clean_pw[2:-1]

        if len(clean_pw) == 64:
            try:
                key = bytes.fromhex(clean_pw)
            except ValueError:
                key = None

    if key is None:
        pw_bytes = password.encode("utf-8") if isinstance(password, str) else bytes(password)
        if version == 4:
            iterations = kdf_iter or 256000
            derived = hashlib.pbkdf2_hmac("sha512", pw_bytes, salt, iterations, 64)
            key = derived[:32]
        else:
            iterations = kdf_iter or 64000
            derived = hashlib.pbkdf2_hmac("sha1", pw_bytes, salt, iterations, 64)
            key = derived[:32]

    # Decrypt and validate Page 1
    p1 = decrypt_sqlcipher_page(raw_bytes[:page_size], page_num=1, key=key, page_size=page_size, reserve=reserve)
    dec_page_size = struct.unpack_from(">H", p1, 16)[0]
    if dec_page_size == 1:
        dec_page_size = 65536
    write_ver = p1[18]
    read_ver = p1[19]

    if dec_page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) or write_ver not in (1, 2) or read_ver not in (1, 2):
        raise ValueError(
            f"Decryption failed: decrypted page 1 does not conform to SQLite format "
            f"(detected page size {dec_page_size}, write version {write_ver}, read version {read_ver}). "
            f"Incorrect passphrase, key, or SQLCipher version."
        )

    # Decrypt all pages
    total_pages = len(raw_bytes) // page_size
    output_chunks = [p1]

    for p_idx in range(2, total_pages + 1):
        offset = (p_idx - 1) * page_size
        page_chunk = raw_bytes[offset : offset + page_size]
        dec_page = decrypt_sqlcipher_page(page_chunk, page_num=p_idx, key=key, page_size=page_size, reserve=reserve)
        output_chunks.append(dec_page)

    dec_bytes = b"".join(output_chunks)
    if return_key:
        return dec_bytes, key
    return dec_bytes


def decrypt_see_page(
    page_data: bytes | memoryview,
    page_num: int,
    key: bytes,
    page_size: int = 4096,
    reserve: int = 0,
    iv: Optional[bytes] = None,
) -> bytes:
    """
    Decrypts a single SQLite Encryption Extension (SEE) page using AES-OFB.
    Compatible with SEE-AES256-OFB (32-byte key) and SEE-AES128-OFB (16-byte key).
    
    - For page 1:
      Bytes 0-15 are decrypted to recover standard 'SQLite format 3\\x00'.
      Bytes 16-23 are stored in plaintext in SEE files and retained as-is.
      Bytes 24 to (page_size - reserve) are decrypted with keystream.
      Bytes (page_size - reserve) to page_size are reserved / nonce bytes.
    - For page N > 1:
      Bytes 0 to (page_size - reserve) are decrypted with keystream.
      Bytes (page_size - reserve) to page_size are reserved / nonce bytes.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import OFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import OFB

    if len(page_data) < page_size:
        raise ValueError(f"Page data ({len(page_data)} bytes) is smaller than page_size ({page_size})")

    page_b = bytes(page_data[:page_size])

    if iv is None:
        if reserve >= 16:
            # 16-byte nonce stored at reserved end of page
            iv = page_b[page_size - reserve : page_size - reserve + 16]
        else:
            # Deterministic IV derived from big-endian page number
            iv = struct.pack(">I", page_num).ljust(16, b"\x00")

    cipher = Cipher(algorithms.AES(key), OFB(iv))

    if page_num == 1:
        enc_0_16 = page_b[:16]
        enc_rest = page_b[24 : page_size - reserve]

        # Method A: Continuous stream advancing keystream through bytes 16-23
        dec_a = cipher.decryptor()
        p1_0_16_a = dec_a.update(enc_0_16)
        _ = dec_a.update(b"\x00" * 8)
        p1_rest_a = dec_a.update(enc_rest)

        # Method B: Stream without intermediate padding advancement
        dec_b = cipher.decryptor()
        p1_0_16_b = dec_b.update(enc_0_16)
        p1_rest_b = dec_b.update(enc_rest)

        # Determine which method produces a valid SQLite B-tree page header at offset 100
        chosen_rest = p1_rest_a
        # In page 1, offset 100 corresponds to index 76 in p1_rest (since 24 + 76 = 100)
        if len(p1_rest_a) > 76 and p1_rest_a[76] not in (0x02, 0x05, 0x0a, 0x0d):
            if len(p1_rest_b) > 76 and p1_rest_b[76] in (0x02, 0x05, 0x0a, 0x0d):
                chosen_rest = p1_rest_b

        reconstructed = bytearray(page_size)
        reconstructed[0:16] = p1_0_16_a
        reconstructed[16:24] = page_b[16:24]
        reconstructed[24 : 24 + len(chosen_rest)] = chosen_rest
        if reserve > 0:
            reconstructed[page_size - reserve :] = page_b[page_size - reserve :]
        return bytes(reconstructed)
    else:
        dec = cipher.decryptor()
        enc_body = page_b[: page_size - reserve]
        dec_body = dec.update(enc_body)
        reconstructed = bytearray(page_size)
        reconstructed[: len(dec_body)] = dec_body
        if reserve > 0:
            reconstructed[page_size - reserve :] = page_b[page_size - reserve :]
        return bytes(reconstructed)


def decrypt_see_database(
    raw_bytes: bytes | memoryview,
    password: str | bytes,
    page_size: Optional[int] = None,
    reserve: Optional[int] = None,
    return_key: bool = False,
) -> Union[bytes, Tuple[bytes, bytes]]:
    """
    Decrypts an entire SQLite Encryption Extension (SEE) database in memory.
    Supports both SEE-AES256-OFB and SEE-AES128-OFB with passphrases or raw hex keys.
    """
    raw_b = bytes(raw_bytes)
    if len(raw_b) < 100:
        raise ValueError("Database too small to be a valid SEE database.")

    # Read page size and reserve from plaintext header at offset 16-20 if not specified
    if page_size is None:
        raw_psize = struct.unpack_from(">H", raw_b, 16)[0]
        page_size = 65536 if raw_psize == 1 else raw_psize
    if reserve is None:
        reserve = raw_b[20]

    if page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
        raise ValueError(f"Invalid SEE page size: {page_size}")

    # Generate candidate keys:
    candidate_keys: List[bytes] = []
    if isinstance(password, str):
        clean_pw = password.strip()
        if clean_pw.lower().startswith("0x"):
            clean_pw = clean_pw[2:]
        elif clean_pw.lower().startswith("x'") and clean_pw.endswith("'"):
            clean_pw = clean_pw[2:-1]
        if len(clean_pw) in (64, 32):
            try:
                candidate_keys.append(bytes.fromhex(clean_pw))
            except ValueError:
                pass

    pw_bytes = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    
    # Derivations: SHA-256 (32B), SHA-256 (16B), SHA-1 (16B), direct padding/repeat
    candidate_keys.append(hashlib.sha256(pw_bytes).digest())
    candidate_keys.append(hashlib.sha256(pw_bytes).digest()[:16])
    candidate_keys.append(hashlib.sha1(pw_bytes).digest()[:16])
    candidate_keys.append((pw_bytes * (32 // max(len(pw_bytes), 1) + 1))[:32] if pw_bytes else b"\x00" * 32)
    candidate_keys.append(pw_bytes.ljust(32, b"\x00")[:32])
    candidate_keys.append((pw_bytes * (16 // max(len(pw_bytes), 1) + 1))[:16] if pw_bytes else b"\x00" * 16)
    candidate_keys.append(pw_bytes.ljust(16, b"\x00")[:16])

    # Candidate IV options for Page 1
    iv_candidates: List[Optional[bytes]] = [None]
    if reserve >= 16:
        iv_candidates.append(raw_b[page_size - reserve : page_size - reserve + 16])
    iv_candidates.append(struct.pack(">I", 1).ljust(16, b"\x00"))
    iv_candidates.append(struct.pack("<I", 1).ljust(16, b"\x00"))

    # Test candidate keys on Page 1
    valid_key: Optional[bytes] = None
    dec_p1: Optional[bytes] = None

    for cand_k in candidate_keys:
        for cand_iv in iv_candidates:
            try:
                test_p1 = decrypt_see_page(
                    raw_b[:page_size],
                    page_num=1,
                    key=cand_k,
                    page_size=page_size,
                    reserve=reserve,
                    iv=cand_iv,
                )
                if test_p1[:16] == b"SQLite format 3\x00":
                    valid_key = cand_k
                    dec_p1 = test_p1
                    break
            except Exception:
                continue
        if valid_key:
            break

    if not valid_key or not dec_p1:
        raise ValueError("SEE Decryption failed: invalid password, key, or unsupported SEE variant.")

    # Decrypt remaining pages
    total_pages = len(raw_b) // page_size
    output_chunks = [dec_p1]

    for p_idx in range(2, total_pages + 1):
        offset = (p_idx - 1) * page_size
        page_chunk = raw_b[offset : offset + page_size]
        dec_page = decrypt_see_page(
            page_chunk,
            page_num=p_idx,
            key=valid_key,
            page_size=page_size,
            reserve=reserve,
        )
        output_chunks.append(dec_page)

    dec_bytes = b"".join(output_chunks)
    if return_key:
        return dec_bytes, valid_key
    return dec_bytes


def decrypt_wal_frame_page(
    page_data: bytes | memoryview,
    page_id: int,
    key: bytes,
    scheme: str = "SQLCipher",
    page_size: int = 4096,
    reserve: int = 48,
) -> bytes:
    """
    Decrypts an encrypted WAL frame page payload in-memory.
    Supports SQLCipher (AES-256-CBC) and SQLite Encryption Extension (SEE AES-OFB).
    If decryption encounters an error (e.g. corruption), falls back gracefully to raw bytes.
    """
    try:
        scheme_lower = scheme.lower()
        if "see" in scheme_lower:
            return decrypt_see_page(
                page_data,
                page_num=page_id,
                key=key,
                page_size=page_size,
                reserve=reserve,
            )
        else:
            return decrypt_sqlcipher_page(
                page_data,
                page_num=page_id,
                key=key,
                page_size=page_size,
                reserve=reserve,
            )
    except Exception:
        return bytes(page_data[:page_size])


def try_decrypt_database(
    raw_bytes: bytes | memoryview,
    password: str | bytes,
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Forensic Auto-Decrypt Engine:
    Attempts decryption of a candidate database across SQLite Encryption Extension (SEE)
    and SQLCipher (v4, v3, multiple page sizes).
    Returns (decrypted_bytes, metadata_dict).
    """
    raw_b = bytes(raw_bytes)
    if raw_b[:16] == b"SQLite format 3\x00":
        return raw_b, {"already_decrypted": True, "scheme": "standard_sqlite"}

    # 1. Fast SEE Check: if bytes 16-23 indicate valid SQLite geometry, prioritize SEE!
    if len(raw_b) >= 24:
        raw_psize = struct.unpack_from(">H", raw_b, 16)[0]
        cand_psize = 65536 if raw_psize == 1 else raw_psize
        w_ver = raw_b[18]
        r_ver = raw_b[19]
        m_pf = raw_b[21]
        min_pf = raw_b[22]
        l_pf = raw_b[23]
        if (
            cand_psize in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
            and w_ver in (1, 2)
            and r_ver in (1, 2)
            and m_pf == 64
            and min_pf == 32
            and l_pf == 32
        ):
            try:
                decrypted, raw_key = decrypt_see_database(
                    raw_b, password, page_size=cand_psize, reserve=raw_b[20], return_key=True
                )
                meta = {
                    "version": "SQLite Encryption Extension (SEE)",
                    "scheme": "SEE-AES-OFB",
                    "cipher": "AES-OFB",
                    "page_size": cand_psize,
                    "reserve_bytes": raw_b[20],
                    "pages_decrypted": len(decrypted) // cand_psize,
                    "raw_key": raw_key,
                }
                return decrypted, meta
            except Exception:
                pass  # Fall through to try SQLCipher or fallback

    # 2. Configurations to test for SQLCipher: (version, page_size)
    configs = [
        (4, 4096),
        (4, 1024),
        (4, 2048),
        (4, 8192),
        (3, 1024),
        (3, 4096),
    ]

    last_err = None
    for ver, p_sz in configs:
        if len(raw_b) < p_sz:
            continue
        try:
            decrypted, raw_key = decrypt_sqlcipher_database(
                raw_b, password, version=ver, page_size=p_sz, return_key=True
            )
            meta = {
                "version": f"SQLCipher v{ver}",
                "scheme": f"SQLCipher v{ver}",
                "page_size": p_sz,
                "kdf": "PBKDF2-HMAC-SHA512 (256,000 iter)" if ver == 4 else "PBKDF2-HMAC-SHA1 (64,000 iter)",
                "cipher": "AES-256-CBC",
                "reserve_bytes": 48,
                "pages_decrypted": len(decrypted) // p_sz,
                "raw_key": raw_key,
            }
            return decrypted, meta
        except Exception as e:
            last_err = e
            continue

    # 3. Fallback to SEE with common default page sizes
    for p_sz in (4096, 1024):
        if len(raw_b) < p_sz:
            continue
        for res in (0, 16):
            try:
                decrypted, raw_key = decrypt_see_database(
                    raw_b, password, page_size=p_sz, reserve=res, return_key=True
                )
                meta = {
                    "version": "SQLite Encryption Extension (SEE)",
                    "scheme": "SEE-AES-OFB",
                    "cipher": "AES-OFB",
                    "page_size": p_sz,
                    "reserve_bytes": res,
                    "pages_decrypted": len(decrypted) // p_sz,
                    "raw_key": raw_key,
                }
                return decrypted, meta
            except Exception:
                continue

    raise DecryptionError(f"Failed to decrypt database with provided key/password: {last_err}")

