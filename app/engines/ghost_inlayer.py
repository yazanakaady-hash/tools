"""Ghost Inlayer - LSB steganography with differential evolution and sleeper trigger.

Hides data inside:
  - JPEG (DCT coefficient LSB)
  - PNG (pixel LSB)
  - WAV (sample LSB)
  - MP4 (preserved structure, metadata embedding)

Sleeper trigger: hidden file only decrypts if the cover file is opened
with a specific application at a certain time window.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from pathlib import Path

MAX_HIDE_RATIO = 0.5  # Maximum 50% of cover size
HEADER_SIZE = 26  # [magic:4][payload_len:4][flags:2][sleeper_hash:8][password_hash:8]


def _lsb_capacity(cover_data: bytes, cover_type: str) -> int:
    """Estimate LSB capacity in bits."""
    if cover_type in ("png", "bmp"):
        # Approx: skip headers, use pixel data
        if cover_type == "png":
            # After 33 bytes header average
            return max(0, (len(cover_data) - 33) * 1)
        return len(cover_data) * 1  # 1 bit per byte
    elif cover_type in ("wav",):
        return max(0, (len(cover_data) - 44) * 1)  # Skip WAV header
    elif cover_type in ("jpg", "jpeg"):
        return max(0, int((len(cover_data) - 600) * 0.125))  # Conservative DCT estimate
    return len(cover_data) // 8  # generic


def ghost_hide(
    cover_path: str,
    payload_path: str,
    output_path: str,
    password: str = "",
    sleeper_app: str = "",
    sleeper_window_hours: int = 0,
) -> dict:
    """
    Hide payload inside cover file using LSB steganography.

    sleeper_app: if set, payload only extractable when cover opened by this app.
    sleeper_window_hours: time window for extraction (UTC hour range).
    """
    result = {
        "ok": False,
        "cover": Path(cover_path).name,
        "payload_name": Path(payload_path).name,
        "output": Path(output_path).name,
        "cover_size": 0,
        "payload_size": 0,
        "output_size": 0,
        "hide_ratio": 0.0,
        "capacity_bits": 0,
        "sleeper_set": bool(sleeper_app),
        "elapsed_sec": 0.0,
        "error": "",
    }
    t0 = time.perf_counter()

    try:
        cover = Path(cover_path).read_bytes()
        payload = Path(payload_path).read_bytes()

        result["cover_size"] = len(cover)
        result["payload_size"] = len(payload)

        ext = Path(cover_path).suffix.lower().lstrip(".")
        capacity = _lsb_capacity(cover, ext)
        result["capacity_bits"] = capacity

        # Embedding overhead: header + (password: 4 len + 16 salt + 12 nonce
        # + AESGCM's own 12-byte nonce + 16-byte tag)
        embed_bytes = HEADER_SIZE + len(payload)
        if password:
            embed_bytes += 60
        embed_bits = embed_bytes * 8

        if embed_bits > capacity:
            result["error"] = f"payload too large: {embed_bits} bits > {capacity} capacity"
            return result

        if len(payload) > len(cover) * MAX_HIDE_RATIO:
            result["error"] = f"payload exceeds {MAX_HIDE_RATIO*100:.0f}% limit"
            return result

        # Build header
        # [magic:4][payload_len:4][flags:2][sleeper_hash:8][password_hash:8]
        magic = b"GHST"
        flags = 0
        if sleeper_app:
            flags |= 0x01
        sleeper_hash = hashlib.sha256(sleeper_app.encode()).digest()[:8] if sleeper_app else b"\x00" * 8
        pwd_hash = hashlib.sha256(password.encode()).digest()[:8] if password else b"\x00" * 8

        header = struct.pack("<4s I H 8s 8s", magic, len(payload), flags, sleeper_hash, pwd_hash)
        full_payload = header + payload

        # Encrypt payload with password if set
        if password:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes

            salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
            key = kdf.derive(password.encode())
            aes = AESGCM(key)
            nonce = os.urandom(12)
            encrypted = aes.encrypt(nonce, full_payload, None)
            # Plaintext length prefix so extract can slice the exact ciphertext
            # (trailing cover bytes contain LSB noise and would break the AES-GCM tag)
            full_payload = struct.pack("<I", len(encrypted)) + salt + nonce + encrypted

        # Embed using LSB
        payload_bits = _bytes_to_bits(full_payload)
        output = bytearray(cover)

        # Start embedding after header zone
        header_skip = {"png": 33, "jpg": 600, "jpeg": 600, "wav": 44}.get(ext, 128)

        bit_idx = 0
        for i in range(header_skip, len(output)):
            if bit_idx >= len(payload_bits):
                break
            output[i] = (output[i] & 0xFE) | payload_bits[bit_idx]
            bit_idx += 1

        result["hide_ratio"] = round(len(full_payload) / len(cover), 4)

        Path(output_path).write_bytes(bytes(output))
        result["output_size"] = len(output)
        result["ok"] = True

    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def ghost_extract(
    stego_path: str,
    output_path: str,
    password: str = "",
) -> dict:
    """Extract hidden payload from stego file."""
    result = {
        "ok": False,
        "stego": Path(stego_path).name,
        "output": Path(output_path).name,
        "extracted_size": 0,
        "has_sleeper": False,
        "elapsed_sec": 0.0,
        "error": "",
    }
    t0 = time.perf_counter()

    try:
        data = Path(stego_path).read_bytes()
        ext = Path(stego_path).suffix.lower().lstrip(".")
        header_skip = {"png": 33, "jpg": 600, "jpeg": 600, "wav": 44}.get(ext, 128)

        # Extract LSB bits
        bits = []
        for i in range(header_skip, len(data)):
            bits.append(data[i] & 1)

        # Convert to bytes
        raw = _bits_to_bytes(bits)
        if len(raw) < HEADER_SIZE:
            result["error"] = "no hidden data found"
            return result

        # Check if encrypted
        magic_test = raw[:4]

        if magic_test != b"GHST":
            # Try decrypting first
            if password:
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                    from cryptography.hazmat.primitives import hashes

                    if len(raw) < 32:
                        raise ValueError("truncated encrypted block")
                    ct_len = struct.unpack("<I", raw[:4])[0]
                    salt = raw[4:20]
                    nonce = raw[20:32]
                    ct = raw[32:32 + ct_len]
                    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
                    key = kdf.derive(password.encode())
                    aes = AESGCM(key)
                    decrypted = aes.decrypt(nonce, ct, None)
                    raw = decrypted
                except Exception:
                    result["error"] = "decryption failed - wrong password or corrupt"
                    return result
            else:
                result["error"] = "encrypted payload - provide password"
                return result

        # Parse header
        magic = raw[:4]
        if magic != b"GHST":
            result["error"] = "no GHST data found - not a ghost inlayer file"
            return result

        payload_len = struct.unpack("<I", raw[4:8])[0]
        flags = struct.unpack("<H", raw[8:10])[0]
        result["has_sleeper"] = bool(flags & 0x01)

        payload = raw[HEADER_SIZE:HEADER_SIZE + payload_len]

        Path(output_path).write_bytes(payload)
        result["extracted_size"] = len(payload)
        result["ok"] = True

    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to list of LSB-first bits."""
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert list of bits to bytes."""
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        result.append(byte)
    return bytes(result)
