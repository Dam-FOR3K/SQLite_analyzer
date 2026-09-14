import os
import pytest
from sqlite_carver.core.encryption import calculate_shannon_entropy, analyze_database_encryption


def test_shannon_entropy_calculation():
    # 0 entropy for uniform data
    assert calculate_shannon_entropy(b"\x00" * 1000) == 0.0

    # Low entropy for ascii english text
    text = b"Forensic SQLite analyzer and carver by Dam-FOR3K" * 20
    text_entropy = calculate_shannon_entropy(text)
    assert text_entropy < 5.0

    # High entropy for pseudo-random / encrypted data
    random_bytes = os.urandom(8192)
    rand_entropy = calculate_shannon_entropy(random_bytes)
    assert rand_entropy >= 7.85


def test_analyze_standard_plaintext_database():
    # Normal SQLite database header
    db_header = b"SQLite format 3\x00" + (b"\x00" * 84)
    res = analyze_database_encryption(db_header)
    assert not res.is_encrypted
    assert res.entropy < 7.0
    assert "Standard unencrypted SQLite 3 format header detected" in res.reasons


def test_analyze_sqlcipher_encrypted_database():
    # SQLCipher uses a 16-byte random salt at offset 0 followed by encrypted page data
    salt = os.urandom(16)
    encrypted_body = os.urandom(4096 - 16)
    encrypted_page1 = salt + encrypted_body

    res = analyze_database_encryption(encrypted_page1)
    assert res.is_encrypted
    assert res.entropy >= 7.80
    assert res.confidence >= 0.85
    assert "SQLCipher" in res.scheme
    assert res.salt_hex == salt.hex()
    assert len(res.reasons) > 0
