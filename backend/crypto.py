"""
Symmetric encryption for Gmail OAuth tokens at rest.

Refresh tokens are long-lived credentials that grant ongoing access to a
connected mailbox -- storing them in plaintext in the database would mean
a single DB dump leaks standing access to real inboxes. This module
encrypts them with Fernet (AES-128-CBC + HMAC authentication) using a key
supplied *only* via the TOKEN_ENCRYPTION_KEY environment variable.

Design decisions:

- The key is deliberately NOT derived from SENTINEL_SECRET_KEY. Rotating
  the Flask session secret (which invalidates sessions -- a routine,
  low-consequence operation) must never silently make every stored mailbox
  token undecryptable. They have different lifecycles, so they get
  different keys.
- The key is loaded lazily (per call), not at import time, so the rest of
  the app boots and every non-Gmail feature works even when the key isn't
  configured. The requirement only bites when someone actually connects a
  mailbox.
- Decryption failure is explicit (TokenDecryptionError), never a silent
  None or a partial success. A token that can't be decrypted (key rotated,
  value corrupted) must surface as "reconnect this mailbox", not as a
  mysterious downstream Gmail-auth error.

Generate a key with:  python crypto.py generate-key
"""

import os

from cryptography.fernet import Fernet, InvalidToken

_ENV_VAR = "TOKEN_ENCRYPTION_KEY"


class TokenEncryptionError(RuntimeError):
    """Raised when encryption can't proceed (missing/invalid key)."""


class TokenDecryptionError(RuntimeError):
    """Raised when a stored ciphertext can't be decrypted -- the key
    changed, or the stored value is corrupt. Callers should treat this as
    'the mailbox must be reconnected', not retry blindly."""


def generate_key() -> str:
    """A fresh urlsafe-base64 Fernet key, suitable for TOKEN_ENCRYPTION_KEY."""
    return Fernet.generate_key().decode()


def _fernet() -> Fernet:
    key = os.environ.get(_ENV_VAR)
    if not key:
        raise TokenEncryptionError(
            f"{_ENV_VAR} is not set -- it is required to store Gmail tokens "
            f"at rest. Generate one with: python crypto.py generate-key"
        )
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as e:  # malformed key (wrong length/encoding)
        raise TokenEncryptionError(f"{_ENV_VAR} is not a valid Fernet key: {e}") from e


def encrypt(plaintext: str) -> str:
    """Encrypt a token string -> storable ciphertext string."""
    if plaintext is None:
        raise TokenEncryptionError("Refusing to encrypt None")
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a stored ciphertext string -> original token string.

    Raises TokenDecryptionError (not InvalidToken) so callers depend on
    this module's own error type rather than a cryptography-library one.
    """
    if ciphertext is None:
        raise TokenDecryptionError("No token stored to decrypt")
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as e:
        raise TokenDecryptionError(
            "Could not decrypt stored token -- TOKEN_ENCRYPTION_KEY may have "
            "changed or the value is corrupt. Reconnect the mailbox."
        ) from e


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2 and sys.argv[1] == "generate-key":
        print(generate_key())
    else:
        print("Usage: python crypto.py generate-key", file=sys.stderr)
        sys.exit(1)
