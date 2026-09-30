import hashlib
import os
import struct
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
try:
    from cryptography.hazmat.decrepit.ciphers.modes import OFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import OFB

from sqlite_carver.core.encryption import (
    DecryptionError,
    analyze_database_encryption,
    decrypt_see_database,
    decrypt_see_page,
    try_decrypt_database,
)


def _create_synthetic_see_db(
    password: str,
    key_size: int = 32,  # 32 = AES-256, 16 = AES-128
    page_size: int = 4096,
    reserve: int = 0,
    page_count: int = 2,
) -> bytes:
    """
    Creates a synthetic SQLite Encryption Extension (SEE) encrypted database.
    In SEE:
    - Bytes 0-15 of Page 1 are encrypted AES-OFB.
    - Bytes 16-23 of Page 1 are stored in plaintext.
    - Bytes 24 to (page_size - reserve) are encrypted AES-OFB.
    - Subsequent pages have bytes 0 to (page_size - reserve) encrypted AES-OFB.
    """
    pw_bytes = password.encode("utf-8")
    if key_size == 32:
        key = hashlib.sha256(pw_bytes).digest()
    else:
        key = hashlib.sha256(pw_bytes).digest()[:16]

    # SQLite Header for Page 1:
    # magic: 16 bytes (will be encrypted)
    # page_size: 2 bytes at offset 16 (big endian)
    # write_ver (18): 1, read_ver (19): 1
    # reserve (20): reserve, max_pf (21): 64, min_pf (22): 32, leaf_pf (23): 32
    raw_psize = 1 if page_size == 65536 else page_size
    geom = struct.pack(">HBBB BBB", raw_psize, 1, 1, reserve, 64, 32, 32)

    # Offset 100 on Page 1 is the B-tree leaf header: page_type=0x0d (table leaf), first_freeblock=0, cell_count=1
    p1_pt = bytearray(page_size)
    p1_pt[:16] = b"SQLite format 3\x00"
    p1_pt[16:24] = geom
    p1_pt[100:108] = b"\x0d\x00\x00\x01\x0f\x00\x00\x00"

    # Encrypt Page 1
    if reserve >= 16:
        iv1 = os.urandom(16)
    else:
        iv1 = struct.pack(">I", 1).ljust(16, b"\x00")

    cipher1 = Cipher(algorithms.AES(key), OFB(iv1)).encryptor()
    enc_0_16 = cipher1.update(p1_pt[:16])
    _ = cipher1.update(b"\x00" * 8)  # Advance keystream past plaintext geom
    enc_rest = cipher1.update(p1_pt[24 : page_size - reserve])

    p1_enc = bytearray(page_size)
    p1_enc[:16] = enc_0_16
    p1_enc[16:24] = geom  # Plaintext!
    p1_enc[24 : 24 + len(enc_rest)] = enc_rest
    if reserve >= 16:
        p1_enc[page_size - reserve : page_size - reserve + 16] = iv1

    # Page 2: Table Leaf with active records
    p2_pt = bytearray(page_size)
    p2_pt[0:8] = b"\x0d\x00\x00\x02\x0e\x00\x00\x00"

    if reserve >= 16:
        iv2 = os.urandom(16)
    else:
        iv2 = struct.pack(">I", 2).ljust(16, b"\x00")

    cipher2 = Cipher(algorithms.AES(key), OFB(iv2)).encryptor()
    enc_p2 = cipher2.update(p2_pt[: page_size - reserve])

    p2_enc = bytearray(page_size)
    p2_enc[: len(enc_p2)] = enc_p2
    if reserve >= 16:
        p2_enc[page_size - reserve : page_size - reserve + 16] = iv2

    return bytes(p1_enc) + bytes(p2_enc)


def test_see_detection_in_encryption_analysis():
    enc_db = _create_synthetic_see_db("ForensicKey2026", key_size=32, page_size=4096)
    analysis = analyze_database_encryption(enc_db)
    assert analysis.is_encrypted is True
    assert analysis.confidence >= 0.95
    assert "SEE" in analysis.scheme
    assert any("SEE" in r or "geometry" in r for r in analysis.reasons)


def test_see_decrypt_database_aes256_passphrase():
    password = "SuperSecretSeePassword"
    enc_db = _create_synthetic_see_db(password, key_size=32, page_size=4096, reserve=0)
    decrypted, meta = try_decrypt_database(enc_db, password)

    assert decrypted[:16] == b"SQLite format 3\x00"
    assert len(decrypted) == len(enc_db)
    assert "SEE" in meta["version"]
    assert meta["page_size"] == 4096
    assert meta["pages_decrypted"] == 2
    # Verify B-tree header on Page 1 is intact
    assert decrypted[100] == 0x0D


def test_see_decrypt_database_aes128_passphrase():
    password = "See128Password"
    enc_db = _create_synthetic_see_db(password, key_size=16, page_size=4096, reserve=0)
    decrypted, meta = try_decrypt_database(enc_db, password)

    assert decrypted[:16] == b"SQLite format 3\x00"
    assert len(decrypted) == len(enc_db)
    assert "SEE" in meta["version"]


def test_see_decrypt_database_with_raw_hex_key():
    raw_key = os.urandom(32)
    hex_key = raw_key.hex()
    page_size = 4096
    reserve = 16

    geom = struct.pack(">HBBB BBB", page_size, 1, 1, reserve, 64, 32, 32)
    p1_pt = bytearray(page_size)
    p1_pt[:16] = b"SQLite format 3\x00"
    p1_pt[16:24] = geom
    p1_pt[100:108] = b"\x0d\x00\x00\x01\x0f\x00\x00\x00"

    iv1 = os.urandom(16)
    cipher = Cipher(algorithms.AES(raw_key), OFB(iv1)).encryptor()
    enc_0_16 = cipher.update(p1_pt[:16])
    _ = cipher.update(b"\x00" * 8)
    enc_rest = cipher.update(p1_pt[24 : page_size - reserve])

    p1_enc = bytearray(page_size)
    p1_enc[:16] = enc_0_16
    p1_enc[16:24] = geom
    p1_enc[24 : 24 + len(enc_rest)] = enc_rest
    p1_enc[page_size - reserve : page_size - reserve + 16] = iv1

    decrypted, meta = try_decrypt_database(bytes(p1_enc), hex_key)
    assert decrypted[:16] == b"SQLite format 3\x00"
    assert "SEE" in meta["version"]


def test_see_decrypt_invalid_passphrase():
    enc_db = _create_synthetic_see_db("CorrectKey", key_size=32, page_size=4096)
    with pytest.raises(DecryptionError):
        try_decrypt_database(enc_db, "WrongPassword")
