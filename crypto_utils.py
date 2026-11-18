"""
crypto_utils.py
---------------
AES-128-CBC encryption/decryption and SHA-256 hashing utilities.
Key is derived from the stego-key string via SHA-256 truncated to 16 bytes (AES-128).
"""

import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ---------------------------------------------------------------------------
# Key Derivation
# ---------------------------------------------------------------------------

def derive_key(stego_key: str) -> bytes:
    """Derive a 16-byte AES-128 key from an arbitrary stego-key string using SHA-256."""
    return hashlib.sha256(stego_key.encode("utf-8")).digest()[:16]


# ---------------------------------------------------------------------------
# AES-128-CBC Encryption
# ---------------------------------------------------------------------------

def aes_encrypt(plaintext: str, stego_key: str) -> tuple:
    """
    Encrypt a UTF-8 plaintext string with AES-128-CBC.

    Returns:
        (ciphertext_bytes, iv_bytes) -- both raw bytes.
    """
    key = derive_key(stego_key)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return ct, iv


def aes_decrypt(ciphertext: bytes, iv: bytes, stego_key: str) -> str:
    """
    Decrypt AES-128-CBC ciphertext.

    Raises:
        ValueError: If decryption fails (bad key / corrupted data).
    """
    key = derive_key(stego_key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return pt.decode("utf-8")
    except (ValueError, KeyError) as exc:
        raise ValueError(
            f"AES decryption failed -- wrong key or corrupted data: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# SHA-256 Integrity
# ---------------------------------------------------------------------------

def sha256_hash(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def verify_sha256(data: bytes, expected_hash: bytes) -> bool:
    """Return True if SHA-256(data) == expected_hash."""
    return hashlib.sha256(data).digest() == expected_hash
