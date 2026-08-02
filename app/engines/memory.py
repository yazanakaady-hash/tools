"""Live Memory Key Hunting — scan dumps / process memory for key-like material."""
from __future__ import annotations

import re
import struct
from collections import Counter
from typing import Any

from .common import entropy, sha256


# Windows optional process read
def list_processes() -> list[dict[str, Any]]:
    try:
        import psutil  # type: ignore
    except ImportError:
        return []
    out = []
    for p in psutil.process_iter(["pid", "name", "username", "memory_info"]):
        try:
            info = p.info
            rss = info["memory_info"].rss if info.get("memory_info") else 0
            out.append(
                {
                    "pid": info["pid"],
                    "name": info.get("name") or "?",
                    "user": info.get("username") or "?",
                    "rss": rss,
                }
            )
        except (psutil.Error, Exception):
            continue
    out.sort(key=lambda x: x["rss"], reverse=True)
    return out[:200]


def read_process_memory(pid: int, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    """Best-effort read of process memory (Windows). May require admin."""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception as e:
        raise RuntimeError(f"ctypes unavailable: {e}") from e

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE
    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    ReadProcessMemory.restype = wintypes.BOOL
    CloseHandle = kernel32.CloseHandle

    h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise RuntimeError("OpenProcess failed — need privileges or invalid PID")

    # Walk a few standard regions via VirtualQueryEx is heavy; sample common bases
    chunks = []
    total = 0
    try:
        # Read first modules via toolhelp if available — fallback fixed probe ranges (user dump preferred)
        VirtualQueryEx = kernel32.VirtualQueryEx

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
        VirtualQueryEx.restype = ctypes.c_size_t

        MEM_COMMIT = 0x1000
        PAGE_NOACCESS = 0x01
        PAGE_GUARD = 0x100
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while total < max_bytes and address < 0x7FFFFFFF0000:
            ret = VirtualQueryEx(h, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not ret:
                break
            base = mbi.BaseAddress or 0
            size = int(mbi.RegionSize or 0)
            protect = int(mbi.Protect or 0)
            state = int(mbi.State or 0)
            next_addr = (base + size) if base else address + 0x10000
            if state == MEM_COMMIT and not (protect & PAGE_NOACCESS) and not (protect & PAGE_GUARD):
                # readable-ish
                if protect in (0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x42, 0x44, 0x48):  # common R/RW/RX
                    to_read = min(size, max_bytes - total, 512 * 1024)
                    if to_read > 0:
                        buf = (ctypes.c_char * to_read)()
                        read = ctypes.c_size_t(0)
                        ok = ReadProcessMemory(h, ctypes.c_void_p(base), buf, to_read, ctypes.byref(read))
                        if ok and read.value:
                            chunks.append(bytes(buf[: read.value]))
                            total += read.value
            address = next_addr
            if address <= base:
                break
    finally:
        CloseHandle(h)

    return b"".join(chunks)


def _window_entropy(buf: bytes) -> float:
    return entropy(buf)


def _is_printable_key(b: bytes) -> bool:
    try:
        s = b.decode("ascii")
        return all(32 <= ord(c) < 127 for c in s) and any(c.isalnum() for c in s)
    except Exception:
        return False


def _score_key_candidate(blob: bytes, context: bytes) -> dict[str, Any]:
    ent = _window_entropy(blob)
    score = 0.0
    reasons = []
    if len(blob) in (16, 24, 32):
        score += 25
        reasons.append(f"AES-like length {len(blob)}")
    if len(blob) == 32:
        score += 5
        reasons.append("possible AES-256 key")
    if ent >= 7.5:
        score += 35
        reasons.append(f"high entropy {ent}")
    elif ent >= 6.5:
        score += 20
        reasons.append(f"moderate-high entropy {ent}")
    else:
        score -= 10
        reasons.append(f"low entropy {ent}")

    # uniqueness of bytes
    uniq = len(set(blob)) / max(len(blob), 1)
    if uniq > 0.85:
        score += 15
        reasons.append("high byte diversity")
    elif uniq < 0.4:
        score -= 15
        reasons.append("repetitive bytes")

    # reject if mostly same byte
    if blob and Counter(blob).most_common(1)[0][1] > len(blob) * 0.6:
        score -= 40
        reasons.append("dominant single byte")

    # hex keyword context
    ctx = context.lower()
    for kw, pts in (
        (b"aes", 10),
        (b"key", 8),
        (b"crypt", 10),
        (b"ransom", 12),
        (b"salsa", 8),
        (b"chacha", 8),
        (b"nonce", 6),
        (b"iv", 4),
    ):
        if kw in ctx:
            score += pts
            reasons.append(f"context:{kw.decode()}")

    return {"score": round(score, 1), "entropy": ent, "reasons": reasons}


def hunt_keys(
    data: bytes,
    *,
    max_hits: int = 80,
    min_score: float = 40.0,
) -> dict[str, Any]:
    """Scan a memory dump / raw blob for key-like material."""
    if not data:
        return {"ok": False, "error": "empty dump"}

    hits: list[dict[str, Any]] = []
    seen = set()

    # 1) sliding windows for AES key sizes on high-entropy islands
    # Sample every step fro large files
    step = 4 if len(data) < 2_000_000 else 16
    # Precompute block entropy map coarsely
    block = 256
    hot_regions = []
    for i in range(0, len(data) - block, block):
        e = entropy(data[i : i + block])
        if e >= 7.2:
            hot_regions.append(i)

    def consider(offset: int, length: int, kind: str):
        if offset < 0 or offset + length > len(data):
            return
        blob = data[offset : offset + length]
        key = sha256(blob)
        if key in seen:
            return
        ctx = data[max(0, offset - 48) : offset + length + 48]
        meta = _score_key_candidate(blob, ctx)
        if meta["score"] < min_score:
            return
        seen.add(key)
        hits.append(
            {
                "offset": offset,
                "length": length,
                "kind": kind,
                "hex": blob.hex(),
                "ascii": blob.decode("ascii", errors="replace") if _is_printable_key(blob) else None,
                "sha256": key,
                **meta,
            }
        )

    for base in hot_regions:
        for length in (16, 24, 32):
            for off in range(base, min(base + block, len(data) - length), step):
                consider(off, length, "entropy_window")

    # 2) printable passphrase-like
    for m in re.finditer(rb"[\x20-\x7e]{16,64}", data):
        s = m.group()
        # skip path-like and URL
        if b"\\" in s or b"/" in s or b"http" in s.lower():
            continue
        if re.search(rb"(?i)(key|secret|password|token|aes|priv)", s) or entropy(s) > 4.5:
            consider(m.start(), len(s), "printable_secret")

    # 3) hex-encoded 32/64 char keys (score decoded AES key bytes)
    for m in re.finditer(rb"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64})(?![0-9a-fA-F])", data):
        hx = m.group()
        try:
            raw_key = bytes.fromhex(hx.decode("ascii"))
        except Exception:
            continue
        key = sha256(raw_key)
        if key in seen:
            continue
        ctx = data[max(0, m.start() - 48) : m.end() + 48]
        meta = _score_key_candidate(raw_key, ctx)
        meta["score"] = round(meta["score"] + 20, 1)  # bonus: clean hex form
        meta["reasons"] = list(meta["reasons"]) + ["hex-encoded key material"]
        if meta["score"] < min_score:
            continue
        seen.add(key)
        hits.append(
            {
                "offset": m.start(),
                "length": len(hx),
                "kind": "hex_string",
                "hex": raw_key.hex(),
                "ascii": hx.decode("ascii"),
                "sha256": key,
                **meta,
            }
        )

    # 4) RSA PEM blobs
    for m in re.finditer(
        rb"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]{32,8192}?-----END (?:RSA )?PRIVATE KEY-----",
        data,
    ):
        blob = m.group()
        hits.append(
            {
                "offset": m.start(),
                "length": len(blob),
                "kind": "pem_private_key",
                "hex": blob[:64].hex() + "...",
                "ascii": blob[:80].decode("ascii", errors="replace") + "…",
                "sha256": sha256(blob),
                "score": 95,
                "entropy": entropy(blob[:2048]),
                "reasons": ["PEM private key block"],
            }
        )

    hits.sort(key=lambda h: h["score"], reverse=True)
    hits = hits[:max_hits]

    return {
        "ok": True,
        "dump_size": len(data),
        "dump_sha256": sha256(data),
        "hot_regions": len(hot_regions),
        "hits": hits,
        "hit_count": len(hits),
        "note": "Candidates only — verify before use. False positives common in compressed/packed data.",
    }


def try_decrypt_sample(ciphertext: bytes, key_hex: str, mode: str = "aes-ecb") -> dict[str, Any]:
    """Optional probe decrypt with a candidate key (AES ECB/CBC trial)."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return {"ok": False, "error": "install cryptography for decrypt probe: pip install cryptography"}

    try:
        key = bytes.fromhex(key_hex)
    except Exception:
        return {"ok": False, "error": "invalid key hex"}
    if len(key) not in (16, 24, 32):
        return {"ok": False, "error": "key must be 16/24/32 bytes"}

    ct = ciphertext[: min(len(ciphertext), 4096)]
    # pad to block
    if len(ct) % 16:
        ct = ct[: len(ct) - (len(ct) % 16)]
    if len(ct) < 16:
        return {"ok": False, "error": "ciphertext too short"}

    results = []
    backend = default_backend()
    # ECB
    try:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        dec = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        results.append({"mode": "AES-ECB", "entropy": entropy(dec), "preview": dec[:32].hex(), "printable": sum(32 <= b < 127 for b in dec[:64])})
    except Exception as e:
        results.append({"mode": "AES-ECB", "error": str(e)})
    # CBC zero IV
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16), backend=backend)
        d = cipher.decryptor()
        dec = d.update(ct) + d.finalize()
        results.append({"mode": "AES-CBC(iv=0)", "entropy": entropy(dec), "preview": dec[:32].hex(), "printable": sum(32 <= b < 127 for b in dec[:64])})
    except Exception as e:
        results.append({"mode": "AES-CBC(iv=0)", "error": str(e)})

    # rank by lowest entropy / most printable
    for r in results:
        if "error" not in r:
            r["plausibility"] = round(r["printable"] * 2 - r["entropy"] * 5, 2)

    return {"ok": True, "trials": results}
