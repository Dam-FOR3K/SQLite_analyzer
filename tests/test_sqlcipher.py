import os
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlite_carver.core.encryption import (
    DecryptionError,
    decrypt_sqlcipher_database,
    try_decrypt_database,
)


def _create_synthetic_sqlcipher_db(password: str, page_size: int = 4096, page_count: int = 2) -> bytes:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=256000,
    )
    enc_key = kdf.derive(password.encode("utf-8"))

    pt1 = b"SQLite format 3\x00" + b"\x10\x00\x01\x01\x00\x40\x20\x20" + (b"\x00" * (page_size - 24))
    pt2 = b"\x0d\x00\x00\x00\x01\x0f\x00\x00" + (b"\xaa" * (page_size - 8))

    iv1 = os.urandom(16)
    cipher1 = Cipher(algorithms.AES(enc_key), modes.CBC(iv1)).encryptor()
    reserve = 48
    enc_payload1 = cipher1.update(pt1[16 : page_size - reserve]) + cipher1.finalize()
    page1 = salt + enc_payload1 + iv1 + (b"\x00" * (reserve - 16))

    iv2 = os.urandom(16)
    cipher2 = Cipher(algorithms.AES(enc_key), modes.CBC(iv2)).encryptor()
    enc_payload2 = cipher2.update(pt2[: page_size - reserve]) + cipher2.finalize()
    page2 = enc_payload2 + iv2 + (b"\x00" * (reserve - 16))

    return page1 + page2


def test_try_decrypt_database_with_passphrase():
    password = "ForensicSecretPassword2026"
    enc_db = _create_synthetic_sqlcipher_db(password)

    decrypted, meta = try_decrypt_database(enc_db, password)
    assert decrypted[:16] == b"SQLite format 3\x00"
    assert len(decrypted) == len(enc_db)
    assert "SQLCipher" in meta["version"]


def test_try_decrypt_database_with_raw_hex_key():
    password = "KeyTestPassword"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=256000,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    hex_key = raw_key.hex()

    page_size = 4096
    reserve = 48
    pt1 = b"SQLite format 3\x00" + b"\x10\x00\x01\x01\x00\x40\x20\x20" + (b"\x00" * (page_size - 24))
    iv1 = os.urandom(16)
    cipher1 = Cipher(algorithms.AES(raw_key), modes.CBC(iv1)).encryptor()
    enc_payload1 = cipher1.update(pt1[16 : page_size - reserve]) + cipher1.finalize()
    page1 = salt + enc_payload1 + iv1 + (b"\x00" * (reserve - 16))

    decrypted, meta = try_decrypt_database(page1, hex_key)
    assert decrypted[:16] == b"SQLite format 3\x00"


def test_try_decrypt_database_invalid_passphrase():
    enc_db = _create_synthetic_sqlcipher_db("RightPassword")
    with pytest.raises(DecryptionError):
        try_decrypt_database(enc_db, "WrongPassword")
