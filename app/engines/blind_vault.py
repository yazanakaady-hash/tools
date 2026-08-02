"""Blind Vault — Scattered block encryption at driver level.

Encrypts random blocks spread across the disk, making the disk appear
corrupt unless you have the seed map. Even forensic imaging sees garbage.

Simulation mode (no kernel driver): encrypts random 4KB blocks of a file,
storing the seed map in a separate encrypted index.
"""

from __future__ import annotations

import hashlib
import os
import random
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_VAULT = b"RNBV"  # RE-Nexus Blind Vault
BLOCK_SIZE = 4096
INDEX_ENTRY_SIZE = 24  # offset(u64 LE) + orig_len(u32 LE) + nonce(12B)
CRYPTO_OVERHEAD = 28  # AESGCM: nonce(12) + tag(16)


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES-256 key from password + salt."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000,
    )
    return kdf.derive(password.encode("utf-8"))


def vault_lock(
    filepath: str,
    password: str,
    block_count: int = 0,
    scatter_ratio: float = 0.3,
) -> dict:
    """
    Encrypt scattered blocks of a file.

    scatter_ratio: fraction of blocks to encrypt (0.0-1.0).
    block_count: if > 0, overrides ratio.
    Returns seed map as a separate encrypted blob.
    """
    result = {
        "ok": False, "filename": Path(filepath).name,
        "blocks_total": 0, "blocks_encrypted": 0,
        "seed_map_sha256": "", "size_bytes": 0,
        "elapsed_sec": 0.0, "error": "",
    }
    t0 = time.perf_counter()

    path = Path(filepath)
    if not path.is_file():
        result["error"] = "file not found"
        return result

    try:
        size = path.stat().st_size
        result["size_bytes"] = size
        total_blocks = max(1, (size + BLOCK_SIZE - 1) // BLOCK_SIZE)
        result["blocks_total"] = total_blocks

        if block_count <= 0:
            block_count = max(1, int(total_blocks * scatter_ratio))
        block_count = min(block_count, total_blocks)
        result["blocks_encrypted"] = block_count

        # Select random blocks
        rng = random.Random(int.from_bytes(os.urandom(8), "big"))
        target_blocks = sorted(rng.sample(range(total_blocks), block_count))

        # Build seed map
        salt = os.urandom(16)
        key = _derive_key(password, salt)

        seed_map = bytearray()
        seed_map += salt  # 16 bytes
        seed_map += struct.pack("<I", block_count)  # 4 bytes

        # Rebuild file in memory: each encrypted block EXPANDS to
        # nonce(12) + ct(len+16), so blocks are written back in full
        # and the seed map keeps every nonce + original length.
        data = path.read_bytes()
        out = bytearray()
        cursor = 0

        for blk_idx in target_blocks:
            offset = blk_idx * BLOCK_SIZE
            blk_end = min(offset + BLOCK_SIZE, size)
            out += data[cursor:offset]  # untouched gap

            block = data[offset:blk_end]
            nonce = os.urandom(12)
            aes = AESGCM(key)
            encrypted = aes.encrypt(nonce, block, None)

            # Record ACTUAL position in the expanded file (blocks grow by
            # CRYPTO_OVERHEAD, so original offsets shift), original length, nonce
            seed_map += struct.pack("<Q I", len(out), len(block))
            seed_map += nonce

            out += nonce + encrypted
            cursor = blk_end

        out += data[cursor:]  # tail after last encrypted block
        path.write_bytes(bytes(out))

        # Encrypt and save seed map
        map_key_salt = os.urandom(16)
        map_key = _derive_key(password, map_key_salt)
        map_nonce = os.urandom(12)
        map_aes = AESGCM(map_key)
        map_enc = map_aes.encrypt(map_nonce, bytes(seed_map), None)

        # Seed map format: magic + map_salt + map_nonce + encrypted_map
        map_path = path.parent / f"{path.name}.vault"
        map_blob = MAGIC_VAULT + map_key_salt + map_nonce + map_enc
        map_path.write_bytes(map_blob)

        result["seed_map_sha256"] = hashlib.sha256(map_blob).hexdigest()
        result["ok"] = True

    except Exception as e:
        result["error"] = str(e) or type(e).__name__

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def vault_unlock(
    filepath: str,
    mappath: str,
    password: str,
) -> dict:
    """Decrypt scattered blocks using the seed map."""
    result = {
        "ok": False, "filename": Path(filepath).name,
        "blocks_decrypted": 0, "size_bytes": 0,
        "elapsed_sec": 0.0, "error": "",
    }
    t0 = time.perf_counter()

    path = Path(filepath)
    map_path = Path(mappath)

    if not path.is_file():
        result["error"] = "file not found"
        return result
    if not map_path.is_file():
        result["error"] = "seed map not found"
        return result

    try:
        # Decrypt seed map
        map_blob = map_path.read_bytes()
        if map_blob[:4] != MAGIC_VAULT:
            result["error"] = "invalid seed map"
            return result

        map_key_salt = map_blob[4:20]
        map_nonce = map_blob[20:32]
        map_enc = map_blob[32:]

        map_key = _derive_key(password, map_key_salt)
        map_aes = AESGCM(map_key)
        seed_map = map_aes.decrypt(map_nonce, map_enc, None)

        salt = seed_map[:16]
        block_count = struct.unpack("<I", seed_map[16:20])[0]
        key = _derive_key(password, salt)

        entries = seed_map[20:]
        result["blocks_decrypted"] = block_count

        data = path.read_bytes()

        # Rebuild original file: copy untouched gaps, decrypt each block,
        # and strip the nonce/tag overhead via the recorded original length.
        out = bytearray()
        cursor = 0

        for i in range(block_count):
            off = i * INDEX_ENTRY_SIZE
            offset, orig_len = struct.unpack("<Q I", entries[off:off + 12])
            nonce = entries[off + 12:off + 24]

            out += data[cursor:offset]  # untouched gap

            blk_len = CRYPTO_OVERHEAD + orig_len
            blk = data[offset:offset + blk_len]
            if len(blk) < blk_len:
                raise ValueError(f"corrupt vault block at offset {offset}")

            aes = AESGCM(key)
            plain = aes.decrypt(nonce, blk[12:], None)
            out += plain

            cursor = offset + blk_len

        out += data[cursor:]  # tail after last encrypted block
        path.write_bytes(bytes(out))
        result["size_bytes"] = len(out)
        result["ok"] = True

    except Exception as e:
        result["error"] = str(e) or "wrong password or corrupt vault"

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result
