"""Token encryption (crypto.py) -- round-trip, missing key, tamper detection."""

import importlib

import pytest

import crypto


def test_encrypt_decrypt_round_trip():
    ciphertext = crypto.encrypt("a-real-looking-refresh-token")
    assert ciphertext != "a-real-looking-refresh-token"  # actually encrypted
    assert crypto.decrypt(ciphertext) == "a-real-looking-refresh-token"


def test_ciphertext_is_not_plaintext_substring():
    secret = "1//super-secret-refresh-token-value"
    ciphertext = crypto.encrypt(secret)
    assert secret not in ciphertext


def test_missing_key_raises_explicit_error(monkeypatch):
    monkeypatch.delenv("TOKEN_ENCRYPTION_KEY", raising=False)
    with pytest.raises(crypto.TokenEncryptionError):
        crypto.encrypt("x")


def test_invalid_key_raises_explicit_error(monkeypatch):
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", "not-a-valid-fernet-key")
    with pytest.raises(crypto.TokenEncryptionError):
        crypto.encrypt("x")


def test_decrypt_with_different_key_fails_explicitly(monkeypatch):
    from cryptography.fernet import Fernet

    ciphertext = crypto.encrypt("token")
    # Rotate the key, then attempt to decrypt an old ciphertext.
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with pytest.raises(crypto.TokenDecryptionError):
        crypto.decrypt(ciphertext)


def test_decrypt_of_corrupt_value_raises_decryption_error():
    with pytest.raises(crypto.TokenDecryptionError):
        crypto.decrypt("clearly-not-ciphertext")


def test_generate_key_is_usable():
    from cryptography.fernet import Fernet

    key = crypto.generate_key()
    # Must be accepted by Fernet -- proves the CLI-generated key is valid.
    Fernet(key.encode())


def test_module_reimport_is_clean():
    # Guards against import-time key loading sneaking back in (the key must
    # be read lazily, not at import).
    importlib.reload(crypto)
