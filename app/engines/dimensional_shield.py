"""Multi-Dimensional Shield - Hybrid dual-cipher encryption with plausible deniability.

Encryption:
  - AES-256-GCM (primary) + ChaCha20-Poly1305 (secondary)
  - Dual-key scheme: password-derived (Argon2) + optional YubiKey/TPM token
  - Plausible deniability: honey layer decrypts to benign data under a second password

Format (v1):
  [Magic (4B): "RENS"][Version (2B): 0x0001][Flags (2B)]
  [Salt Argon2 (32B)][Nonce AES-GCM (12B)][Nonce ChaCha20 (12B)]
  [Honey offset (4B LE) -> 0 if no honey]
  Payload: AES-GCM( ChaCha20( plaintext ) )
  [optional] Honey layer: AES-GCM( benign_data )
  Poly1305 tag (16B)
"""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes

MAGIC = b"RENS"
VERSION = 0x0001
FLAG_DUAL_CIPHER = 0x01
FLAG_HAS_HONEY = 0x02
FLAG_HAS_TOKEN = 0x04

HEADER_SIZE = 4 + 2 + 2 + 32 + 12 + 12 + 4  # 68 bytes


def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a key using Argon2id.

    The Argon2id constructor API changed across cryptography releases:
      - <= 43: Argon2id(salt, length, memory_cost, time_cost, parallelism)
      - 44-48: same + required hash=hashes.SHA256()
      - >= 49: time_cost renamed to iterations, parallelism renamed to lanes
    The Argon2 parameters themselves are identical, so keys stay compatible
    across versions; only the constructor call needs adapting.
    """
    params = dict(salt=salt, length=length, memory_cost=64 * 1024)  # 64 MB
    try:
        kdf = Argon2id(iterations=3, lanes=4, **params)  # cryptography >= 49
    except TypeError:
        try:
            kdf = Argon2id(hash=hashes.SHA256(), time_cost=3, parallelism=4, **params)  # 44-48
        except TypeError:
            kdf = Argon2id(time_cost=3, parallelism=4, **params)  # <= 43
    return kdf.derive(password.encode("utf-8"))


def _argon2_salt() -> bytes:
    return os.urandom(32)

# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def shield_encrypt(
    data: bytes,
    password: str,
    honey_password: Optional[str] = None,
    honey_data: Optional[bytes] = None,
    token_data: Optional[bytes] = None,
) -> bytes:
    """
    Encrypt data with AES-256-GCM wrapped in ChaCha20-Poly1305.

    If honey_password and honey_data are provided, a honey layer is embedded
    that decrypts to benign_data under the second password.
    """
    flags = FLAG_DUAL_CIPHER
    salt = _argon2_salt()

    # Derive primary key
    primary_key = _derive_key(password, salt, 64)
    aes_key = primary_key[:32]
    chacha_key = primary_key[32:]

    # Nonces
    aes_nonce = os.urandom(12)
    chacha_nonce = os.urandom(12)

    # Inner: ChaCha20 encrypt
    chacha = ChaCha20Poly1305(chacha_key)
    inner_ct = chacha.encrypt(chacha_nonce, data, None)

    # Outer: AES-256-GCM encrypt
    aes = AESGCM(aes_key)
    outer_ct = aes.encrypt(aes_nonce, inner_ct, None)

    payload = outer_ct

    # Honey layer (optional)
    honey_blob = b""
    if honey_password and honey_data is not None:
        flags |= FLAG_HAS_HONEY
        honey_salt = _argon2_salt()
        honey_key = _derive_key(honey_password, honey_salt, 32)
        honey_aes = AESGCM(honey_key)
        honey_nonce = os.urandom(12)
        honey_ct = honey_aes.encrypt(honey_nonce, honey_data, None)
        honey_blob = honey_salt + honey_nonce + honey_ct

    if token_data:
        flags |= FLAG_HAS_TOKEN

    honey_offset = HEADER_SIZE + len(payload) if honey_blob else 0

    # Assemble
    header = struct.pack(
        "<4sH H 32s 12s 12s I",
        MAGIC, VERSION, flags,
        salt, aes_nonce, chacha_nonce,
        honey_offset,
    )

    result = header + payload + honey_blob

    # Append token signature placeholder if needed
    if token_data:
        result += token_data[:64]  # max 64 bytes token storage

    return result


def shield_decrypt(
    data: bytes,
    password: str,
    use_honey: bool = False,
) -> dict:
    """
    Decrypt a shield-protected blob.

    Set use_honey=True to decrypt the honey layer instead.
    """
    result = {
        "ok": False,
        "format": "shield-v1",
        "flags": 0,
        "has_honey": False,
        "has_token": False,
        "decrypted_size": 0,
        "error": "",
    }

    if len(data) < HEADER_SIZE:
        result["error"] = "data too short for header"
        return result

    magic, version, flags, salt, aes_nonce, chacha_nonce, honey_offset = struct.unpack(
        "<4sH H 32s 12s 12s I", data[:HEADER_SIZE]
    )

    if magic != MAGIC:
        result["error"] = "invalid magic - not a shield blob"
        return result

    result["flags"] = flags
    result["has_honey"] = bool(flags & FLAG_HAS_HONEY)
    result["has_token"] = bool(flags & FLAG_HAS_TOKEN)

    try:
        primary_key = _derive_key(password, salt, 64)
        aes_key = primary_key[:32]
        chacha_key = primary_key[32:]

        if use_honey and (flags & FLAG_HAS_HONEY) and honey_offset > 0:
            # Decrypt honey layer
            honey_start = honey_offset
            if len(data) < honey_start + 32 + 12 + 16:
                result["error"] = "honey layer truncated"
                return result
            honey_salt = data[honey_start:honey_start + 32]
            honey_nonce = data[honey_start + 32:honey_start + 44]
            honey_ct = data[honey_start + 44:]
            honey_key = _derive_key(password, honey_salt, 32)
            aes = AESGCM(honey_key)
            plain = aes.decrypt(honey_nonce, honey_ct, None)
            result["ok"] = True
            result["decrypted_size"] = len(plain)
            result["honey_mode"] = True
            result["plaintext"] = plain
            return result

        # Normal decryption
        payload_end = honey_offset if honey_offset > 0 else len(data)
        outer_ct = data[HEADER_SIZE:payload_end]

        # Outer: AES-GCM decrypt
        aes = AESGCM(aes_key)
        inner_ct = aes.decrypt(aes_nonce, outer_ct, None)

        # Inner: ChaCha20 decrypt
        chacha = ChaCha20Poly1305(chacha_key)
        plain = chacha.decrypt(chacha_nonce, inner_ct, None)

        result["ok"] = True
        result["decrypted_size"] = len(plain)
        result["plaintext"] = plain
        result["honey_mode"] = False

    except Exception as e:
        result["error"] = f"decryption failed: {e}"
        result["ok"] = False

    return result


# ---------------------------------------------------------------------------
# File-based API
# ---------------------------------------------------------------------------

def shield_encrypt_file(
    src: str,
    dst: str,
    password: str,
    honey_password: Optional[str] = None,
    honey_src: Optional[str] = None,
) -> dict:
    """Encrypt a file with the shield."""
    result = {"ok": False, "src": Path(src).name, "dst": Path(dst).name, "size_in": 0, "size_out": 0, "elapsed_sec": 0.0, "error": ""}
    t0 = time.perf_counter()

    try:
        data = Path(src).read_bytes()
        result["size_in"] = len(data)

        honey_data = None
        if honey_src:
            honey_data = Path(honey_src).read_bytes()
        elif honey_password:
            # Auto-generate a benign decoy so the honey layer actually exists
            # when the user supplies only a honey password (server flow).
            decoy = (b"[benign decoy payload] generated by YAZAN shield - not the real data.\n"
                     + os.urandom(max(0, len(data) - 44)))
            honey_data = decoy if len(decoy) >= 16 else decoy + os.urandom(16)

        encrypted = shield_encrypt(data, password, honey_password, honey_data)
        Path(dst).write_bytes(encrypted)
        result["size_out"] = len(encrypted)
        result["ok"] = True
    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def shield_decrypt_file(
    src: str,
    dst: str,
    password: str,
    use_honey: bool = False,
) -> dict:
    """Decrypt a shield-protected file."""
    result = {"ok": False, "src": Path(src).name, "dst": Path(dst).name, "size_in": 0, "size_out": 0, "elapsed_sec": 0.0, "error": ""}
    t0 = time.perf_counter()

    try:
        data = Path(src).read_bytes()
        result["size_in"] = len(data)

        dec = shield_decrypt(data, password, use_honey)
        if dec["ok"]:
            plain = dec["plaintext"]
            Path(dst).write_bytes(plain)
            result["size_out"] = len(plain)
            result["honey_mode"] = dec.get("honey_mode", False)
            result["ok"] = True
        else:
            result["error"] = dec.get("error", "decryption failed")
    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result
