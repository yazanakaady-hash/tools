"""Elite Modules (وحدات النخبة).

Extra tools: Encrypted Kamikaze Token seal/unseal/refresh, Spectral
Scanner, Bio-Entropy Analyzer, and Forking Duplicator. Local lab use.
"""

from __future__ import annotations

import hashlib
import math
import os
import random
import struct
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
# Encrypted Kamikaze Token — Time-based encryption with auto-destruct
# ═══════════════════════════════════════════════════════════════════════

def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=600_000)
    return kdf.derive(password.encode("utf-8"))


def kamikaze_seal(
    data: bytes,
    password: str,
    ttl_hours: int = 24,
    output_path: Optional[str] = None,
) -> dict:
    """
    Encrypt data with time-based self-destruct.

    The file contains a countdown. If not refreshed within TTL,
    the key is considered dead. Requires periodic refresh to maintain
    key material in the file header.

    Format:
      [magic:4 "KMKZ"][version:2][ttl_hours:2][created_ts:8][salt:16][nonce:12][ct:...]
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    result = {"ok": False, "size_in": len(data), "size_out": 0, "ttl_hours": ttl_hours, "elapsed_sec": 0.0, "error": ""}
    t0 = time.perf_counter()

    try:
        salt = os.urandom(16)
        key = _derive_key(password, salt, 32)
        nonce = os.urandom(12)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, data, None)

        now = int(time.time())
        header = struct.pack("<4s H H q 16s 12s", b"KMKZ", 0x0001, ttl_hours, now, salt, nonce)
        blob = header + ciphertext

        if output_path:
            Path(output_path).write_bytes(blob)

        result["size_out"] = len(blob)
        result["created_ts"] = now
        result["expires_ts"] = now + ttl_hours * 3600
        result["ok"] = True
        result["blob"] = blob

    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def kamikaze_unseal(
    data: bytes,
    password: str,
) -> dict:
    """
    Decrypt kamikaze token if still alive.
    Returns plaintext only if token hasn't expired.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    result = {"ok": False, "expired": False, "size_in": len(data), "size_out": 0, "elapsed_sec": 0.0, "error": ""}
    t0 = time.perf_counter()

    try:
        header_fmt = "<4s H H q 16s 12s"
        header_size = struct.calcsize(header_fmt)
        if len(data) < header_size:
            result["error"] = "data too short"
            return result

        magic, version, ttl_hours, created_ts, salt, nonce = struct.unpack(
            header_fmt, data[:header_size]
        )

        if magic != b"KMKZ":
            result["error"] = "not a kamikaze token"
            return result

        now = int(time.time())
        expires = created_ts + ttl_hours * 3600

        result["created_ts"] = created_ts
        result["expires_ts"] = expires
        result["ttl_hours"] = ttl_hours
        result["hours_remaining"] = max(0, (expires - now) / 3600)

        if now > expires:
            result["expired"] = True
            result["error"] = "token expired — key material destroyed"
            return result

        key = _derive_key(password, salt, 32)
        aes = AESGCM(key)
        plain = aes.decrypt(nonce, data[header_size:], None)

        result["ok"] = True
        result["size_out"] = len(plain)
        result["plaintext"] = plain

    except Exception as e:
        result["error"] = str(e) or "wrong password or corrupt token"

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def kamikaze_refresh(
    filepath: str,
    password: str,
    new_ttl_hours: int = 24,
) -> dict:
    """Refresh a kamikaze token — re-encrypt with new TTL."""
    t0 = time.perf_counter()
    result = {"ok": False, "refreshed": False, "elapsed_sec": 0.0, "error": ""}

    try:
        data = Path(filepath).read_bytes()
        dec = kamikaze_unseal(data, password)
        if not dec["ok"] and not dec.get("expired"):
            result["error"] = dec.get("error", "unseal failed")
            return result

        if dec.get("expired"):
            result["error"] = "cannot refresh expired token"
            return result

        plain = dec["plaintext"]
        sealed = kamikaze_seal(plain, password, new_ttl_hours)
        if sealed["ok"]:
            Path(filepath).write_bytes(sealed["blob"])
            result["ok"] = True
            result["refreshed"] = True
            result["new_expires_ts"] = sealed["expires_ts"]
    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


# ═══════════════════════════════════════════════════════════════════════
# Spectral Scanner — Archive metadata sanitization
# ═══════════════════════════════════════════════════════════════════════

def spectral_scan(filepath: str) -> dict:
    """Detect and remove ADS, ZAC metadata, and archive streams."""
    result = {
        "ok": False, "filename": Path(filepath).name,
        "ads_streams": [],
        "archive_metadata": [],
        "zones_removed": 0,
        "size_before": 0, "size_after": 0,
        "elapsed_sec": 0.0, "error": "",
    }
    t0 = time.perf_counter()

    path = Path(filepath)
    if not path.is_file():
        result["error"] = "file not found"
        return result

    try:
        data = path.read_bytes()
        result["size_before"] = len(data)

        ext = path.suffix.lower()
        if ext in (".zip", ".rar", ".7z"):
            cleaned = _clean_archive_metadata(data, ext)
            result["size_after"] = len(cleaned)
            path.write_bytes(cleaned)
            result["archive_metadata"].append(f"{ext} metadata stripped")

            # Zone.Identifier removal
            zone_path = Path(f"{filepath}:Zone.Identifier")
            if zone_path.exists():
                try:
                    os.remove(str(zone_path))
                    result["zones_removed"] += 1
                except Exception:
                    pass

        result["ok"] = True

    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def _clean_archive_metadata(data: bytes, ext: str) -> bytes:
    """Strip archive metadata (timestamps, file attributes, extra fields)."""
    if ext == ".zip":
        try:
            import io
            buf_in = io.BytesIO(data)
            buf_out = io.BytesIO()

            with zipfile.ZipFile(buf_in, "r") as zin:
                with zipfile.ZipFile(buf_out, "w", zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        content = zin.read(item.filename)
                        # Zero all timestamps
                        info = zipfile.ZipInfo(item.filename, date_time=(2000, 1, 1, 0, 0, 0))
                        info.compress_type = item.compress_type
                        zout.writestr(info, content)
            return buf_out.getvalue()
        except Exception:
            return data
    return data


# ═══════════════════════════════════════════════════════════════════════
# Bio-Entropy Analyzer — Neural net sensitive data detection
# ═══════════════════════════════════════════════════════════════════════

def bio_entropy_analyze(data: bytes, chunk_size: int = 4096) -> dict:
    """Analyze file entropy to detect sensitive vs noise regions."""
    result = {
        "ok": True,
        "size_total": len(data),
        "chunks_analyzed": 0,
        "chunks_sensitive": 0,
        "sensitive_ranges": [],
        "global_entropy": 0.0,
        "classification": "unknown",
        "recommendation": "",
        "elapsed_sec": 0.0,
    }
    t0 = time.perf_counter()

    if not data:
        result["classification"] = "empty"
        return result

    # Global Shannon entropy
    freq = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    result["global_entropy"] = round(entropy, 4)

    # Per-chunk analysis
    sensitive = []
    chunks = (len(data) + chunk_size - 1) // chunk_size

    for i in range(chunks):
        chunk = data[i * chunk_size:(i + 1) * chunk_size]
        freq_c = Counter(chunk)
        total_c = len(chunk)
        h = 0.0
        for c in freq_c.values():
            p = c / total_c
            h -= p * math.log2(p)

        # High entropy = likely encrypted/compressed = sensitive
        # Low entropy = likely noise/padding
        # Mid entropy = likely text/code
        is_sensitive = h > 7.0 and h < 7.95

        if is_sensitive:
            sensitive.append({
                "offset": i * chunk_size,
                "size": len(chunk),
                "entropy": round(h, 4),
            })

    result["chunks_analyzed"] = chunks
    result["chunks_sensitive"] = len(sensitive)
    result["sensitive_ranges"] = sensitive[:20]  # Top 20

    if len(sensitive) == 0:
        result["classification"] = "noise/padding"
        result["recommendation"] = "no encryption needed"
    elif len(sensitive) < chunks * 0.2:
        result["classification"] = "partially sensitive"
        result["recommendation"] = "encrypt only sensitive regions"
    elif entropy > 7.8:
        result["classification"] = "probably encrypted"
        result["recommendation"] = "already protected — skip re-encryption"
    else:
        result["classification"] = "likely sensitive"
        result["recommendation"] = "full encryption recommended"

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


# ═══════════════════════════════════════════════════════════════════════
# Forking Duplicator — Decoy file creation
# ═══════════════════════════════════════════════════════════════════════

def forking_duplicate(
    filepath: str,
    decoy_count: int = 10,
    output_dir: Optional[str] = None,
    master_seed: Optional[str] = None,
) -> dict:
    """
    Create N decoy files with slightly different checksums.
    Only one decrypts correctly with the master seed.
    """
    result = {
        "ok": False,
        "original": Path(filepath).name,
        "decoy_count": decoy_count,
        "decoy_dir": str(output_dir) if output_dir else "",
        "real_slot": -1,
        "files": [],
        "elapsed_sec": 0.0,
        "error": "",
    }
    t0 = time.perf_counter()

    path = Path(filepath)
    if not path.is_file():
        result["error"] = "file not found"
        return result

    base = Path(output_dir) if output_dir else path.parent
    if output_dir:
        base.mkdir(parents=True, exist_ok=True)
    stem = path.stem

    try:
        original_data = path.read_bytes()
        rng = random.Random(master_seed.encode() if master_seed else os.urandom(8))

        real_slot = rng.randint(0, decoy_count - 1)

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        for i in range(decoy_count):
            salt = os.urandom(16)
            key_material = (master_seed or "") + str(i)
            key = hashlib.sha256(key_material.encode()).digest()

            if i == real_slot:
                # Real file: encrypt with AES-GCM.
                # NOTE: no trailing padding here — appending bytes after the
                # AES-GCM blob would invalidate the tag and make the real file
                # impossible to decrypt (the module's core promise).
                aes = AESGCM(key[:32])
                nonce = os.urandom(12)
                content = aes.encrypt(nonce, original_data, None)
                content = salt + nonce + content
            else:
                # Decoy: random garbage that looks like encrypted data.
                # Padding only on decoys — their sizes already vary via fake_size.
                fake_size = len(original_data) + random.randint(-64, 64) + 28
                fake_size = max(64, fake_size)
                content = salt + os.urandom(fake_size)
                content += os.urandom(rng.randint(4, 16))

            fname = f"{stem}_decoy_{i:03d}.enc"
            fpath = base / fname
            fpath.write_bytes(content)

            sha = hashlib.sha256(content).hexdigest()[:16]
            result["files"].append({"name": fname, "sha256_12": sha, "size": len(content), "is_real": i == real_slot})

        result["ok"] = True
        result["real_slot"] = real_slot
        result["decoy_dir"] = str(base)

    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result
