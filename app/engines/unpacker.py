"""unpacker — مصنع فك التغليف (Unpacking Factory).

يكتشف غلاف/صيغة الملف المعبأ (UPX، ASPack، Petite، FSG، Themida،
VMProtect، WinLicense، .NET Enigma، MEW، Morphine، MPRESS، NsPack،
Obsidium، PECompact، Y0da، Armadillo) أو الحاويات المضغوطة
(gzip/bz2/zlib/xz/lzma/zip/base64/hex) ثم يستخرج الحمولة المفككة.

يَذكر الطريقة الناجحة في ذاكرة الوحدة (ENGINE_STATS) ويستخدمها
تلقائياً في الملفات القادمة نفس التوقيع، ويرتبط بالمنظف العصبي
neural_clean لإخراج نسخة نظيفة إذا طُلب.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import os
import gzip
import io
import lzma
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Any

from .common import entropy, sha256

MAX_UNPACK = 64 * 1024 * 1024  # سقف الأمان لحجم الناتج
_HEAD_SCAN = 8192

# توقيعات أغلفة PE المرئية (اسم → بصمة تُبحث في أول 8KB + جدول الأقسام)
PACKER_SIGNATURES: list[tuple[str, bytes]] = [
    ("UPX", b"UPX!"),
    ("ASPack", b".aspack"),
    ("Petite", b"PETITE"),
    ("FSG", b"FSG!"),
    ("Themida", b".themida"),
    ("WinLicense", b".winlice"),
    ("VMProtect", b".vmp0"),
    ("VMProtect", b".vmp1"),
    ("VMProtect", b".vmp2"),
    ("VMProtect", b".vmp3"),
    ("Enigma", b".enigma1"),
    ("Enigma", b".enigma2"),
    ("MEW", b"MEW"),
    ("Morphine", b".morphine"),
    ("MPRESS", b".MPRESS1"),
    ("NsPack", b".nsp0"),
    ("NsPack", b".nsp1"),
    ("Obsidium", b".obsidium"),
    ("PECompact", b"PEC2"),
    ("PELock", b"PELock"),
    ("Y0da", b"Y0da"),
    ("Armadillo", b".armadillo"),
]


def _pe_section_names(data: bytes) -> list[str]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return []
        nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec = e_lfanew + 24 + opt_size
        names = []
        for _ in range(min(nsec, 30)):
            names.append(data[sec:sec + 8].rstrip(b"\x00").decode("latin-1", "replace"))
            sec += 40
        return names
    except Exception:
        return []


def _detect_packer(data: bytes) -> dict[str, Any]:
    head = data[:_HEAD_SCAN]
    hits: list[str] = []
    for name, sig in PACKER_SIGNATURES:
        if sig in head:
            hits.append(name)
    if not hits:
        names = _pe_section_names(data)
        for n in set(names):
            nl = n.lower()
            if any(k in nl for k in ("upx", "aspack", "petite", "fsg", "themida",
                                     "winlice", "vmp", "enigma", "mew", "morphine",
                                     "mpress", "nsp", "obsidium", "pec", "armadillo")):
                hits.append(n.strip())
    return {
        "packer": "/".join(dict.fromkeys(hits))[:80] if hits else None,
        "section_names": names if (names := _pe_section_names(data)) else [],
        "entropy": round(entropy(data), 4),
    }


# ── ذاكرة الطرق الناجحة (ROTE MEMMORY: يتعلم المصنع من نجاحاته) ──
ENGINE_STATS: dict[str, Any] = {
    "hits": defaultdict(int),          # اسم المحرك → عدد النجاحات
    "last_success": "",                # آخر محرك نجح
    "signature_memory": {},            # (توقيع أول 8 بايت) → محرك
    "total_runs": 0,
    "successes": 0,
}


def _remember(sig_key: object, engine: str) -> None:
    key = _sig_key(sig_key)
    ENGINE_STATS["hits"][engine] += 1
    ENGINE_STATS["last_success"] = engine
    ENGINE_STATS["successes"] += 1
    mem = ENGINE_STATS["signature_memory"]
    if not mem:
        ENGINE_STATS["signature_memory"] = _sig_key(sig_key)
    else:
        try:
            if engine in mem.values():
                return
        except AttributeError:
            pass
    ENGINE_STATS["signature_memory"] = key  # آخر توقيع ناجح فقط (ذاكرة خفيفة)


def _sig_key(data: bytes) -> str:
    return sha256(data[:4096])[:12]


# ── محركات الاستخراج ──

def _try_gzip(data: bytes) -> bytes | None:
    if data[:2] != b"\x1f\x8b":
        return None
    try:
        out = gzip.decompress(data)
        return out if 0 < len(out) < MAX_UNPACK else None
    except Exception:
        return None


def _try_bz2(data: bytes) -> bytes | None:
    if not data.startswith(b"BZh"):
        return None
    try:
        out = bz2.decompress(data)
        return out if 0 < len(out) < MAX_UNPACK else None
    except Exception:
        return None


def _try_zlib(data: bytes) -> bytes | None:
    if data[:1] != b"\x78":
        return None
    for wbits in (15, -15, 47):
        try:
            out = zlib.decompress(data, wbits)
            return out if 0 < len(out) < MAX_UNPACK else None
        except Exception:
            continue
    return None


def _try_xz(data: bytes) -> bytes | None:
    if data[:6] != b"\xfd7zXZ\x00":
        return None
    try:
        out = lzma.decompress(data)
        return out if 0 < len(out) < MAX_UNPACK else None
    except Exception:
        return None


def _try_lzma(data: bytes) -> bytes | None:
    if data[:3] != b"\x5d\x00\x00":
        return None
    try:
        out = lzma.decompress(data)
        return out if 0 < len(out) < MAX_UNPACK else None
    except Exception:
        return None


def _try_zip(data: bytes) -> dict[str, bytes | None]:
    if not data.startswith(b"PK\x03\x04"):
        return {"out": None}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            if len(names) != 1:
                return {"out": None, "members": len(names)}
            info = zf.getinfo(names[0])
            if info.file_size > MAX_UNPACK:
                return {"out": None}
            return {"out": zf.read(names[0])}
    except Exception:
        return {"out": None}


def _try_base64(data: bytes) -> bytes | None:
    if len(data) < 32:
        return None
    sample = data[:512].strip()
    valid = sum(1 for c in sample if chr(c) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if valid / max(1, len(sample)) < 0.9:
        return None
    try:
        out = base64.b64decode(b"".join(data.split()), validate=True)
    except Exception:
        return None
    if len(out) < 16 or entropy(out) < 0.4:
        return None
    return out if len(out) < MAX_UNPACK else None


def _try_hex(data: bytes) -> bytes | None:
    if len(data) > 4 * 1024 * 1024:
        return None
    s = b"".join(data.split()).decode("ascii", "replace")
    if len(s) < 32 or len(s) % 2 != 0:
        return None
    if sum(c in "0123456789abcdefABCDEF" for c in s) / len(s) < 0.98:
        return None
    try:
        out = binascii.unhexlify(s)
    except Exception:
        return None
    return out if 0 < len(out) < MAX_UNPACK else None


def _pe_overlay(data: bytes) -> dict[str, Any]:
    """استخراج البيانات الملحقة بعد نهاية آخر قسم PE (overlay)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"out": None}
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return {"out": None}
        nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec = e_lfanew + 24 + opt_size
        last_end = 0
        for _ in range(min(nsec, 30)):
            if sec + 40 > len(data):
                break
            raw_size = struct.unpack_from("<I", data, sec + 16)[0]
            raw_off = struct.unpack_from("<I", data, sec + 20)[0]
            last_end = max(last_end, raw_off + raw_size)
            sec += 40
        if last_end >= len(data):
            return {"out": None}
        overlay = data[last_end:]
        return {"out": overlay, "offset": last_end}
    except Exception:
        return {"out": None}


def _try_upx(data: bytes, filename: str) -> dict[str, Any]:
    """فك UPX حقيقياً عبر أداة upx -d إن وُجدت."""
    exe = shutil.which("upx")
    if not exe:
        return {"out": None, "reason": "upx binary not installed"}
    fd, tmp = tempfile.mkstemp(suffix="_packed.bin")
    upx_out = tmp + ".unpacked"
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        proc = subprocess.run(
            [exe, "-d", "-o", upx_out, tmp],
            capture_output=True, timeout=20,
        )
        if proc.returncode == 0 and Path(upx_out).exists():
            out = Path(upx_out).read_bytes()
            if 0 < len(out) < MAX_UNPACK:
                return {"out": out, "tool": exe}
    except Exception as e:
        return {"out": None, "reason": str(e)}
    finally:
        for p in (tmp, upx_out):
            try:
                os.unlink(p)
            except OSError:
                pass
    return {"out": None}


# ترتيب المحركات: السجلات الناجحة أولاً (يتذكر المصنع)
def _engine_order() -> list[str]:
    base = ["gzip", "bz2", "zlib", "xz", "lzma", "zip", "base64", "hex", "pe_overlay", "upx"]
    hits = ENGINE_STATS["hits"]
    return sorted(base, key=lambda e: (-hits.get(e, 0), base.index(e)))


def unpack_factory(
    data: bytes,
    filename: str = "sample.bin",
    save_to: str | Path | None = None,
    clean_with_digital: bool = True,
    prefer: str | None = None,
) -> dict[str, Any]:
    """فك تغليف/ضغط الملف عبر كل الطرق وسجل النتائج.

    Parameters
    ----------
    data : bytes — بايتات الملف المدروس.
    filename : str — اسم الملف الأصلي.
    save_to : str|Path|None — مسار حفظ النسخة المفككة (اختياري).
    clean_with_digital : bool — تشغيل neural_clean على النسخة المفككة.
    prefer : str|None — فرض محرك معين (مثال: "upx").

    Returns
    -------
    dict — تقرير المصنع: الغلاف، الطريقة، المقارنة الإحصائية، وحالة neural_clean.
    """
    t0 = time.perf_counter()
    ENGINE_STATS["total_runs"] += 1
    result: dict[str, Any] = {
        "ok": False,
        "filename": filename,
        "packer": None,
        "section_names": [],
        "method": None,
        "methods_tried": [],
        "unpacked": False,
        "error": "",
        "elapsed_sec": 0.0,
    }

    if not data:
        result["error"] = "empty input"
        return result

    pe = _detect_packer(data)
    result["packer"] = pe["packer"]
    result["section_names"] = pe["section_names"]
    result["entropy_before"] = pe["entropy"]

    engines: dict[str, Any] = {
        "gzip": lambda: _try_gzip(data),
        "bz2": lambda: _try_bz2(data),
        "zlib": lambda: _try_zlib(data),
        "xz": lambda: _try_xz(data),
        "lzma": lambda: _try_lzma(data),
        "zip": lambda: (_try_zip(data).get("out")),
        "base64": lambda: _try_base64(data),
        "hex": lambda: _try_hex(data),
        "pe_overlay": lambda: (_pe_overlay(data).get("out")),
        "upx": lambda: _try_upx(data, filename).get("out"),
    }

    order = _engine_order()
    if prefer and prefer in engines:
        order.insert(0, prefer)

    out: bytes | None = None
    used: str | None = None
    notes: list[str] = []
    for name in order:
        result["methods_tried"].append(name)
        try:
            out = engines[name]()
        except Exception as ex:
            out = None
            notes.append(f"{name}: {ex}")
        if out and len(out) >= 8:
            used = name
            _remember(data[:8], name)
            break
        out = None

    delivered = out
    if delivered is None and result["packer"]:
        notes.append(f"غلاف مكتشف ({result['packer']}) لكن لم تتوفر أداة فك — ثبّت upx أو استعن بـ Ghidra.")

    result["ok"] = delivered is not None
    result["unpacked"] = delivered is not None
    result["method"] = used
    result["notes"] = notes
    result["engine_stats"] = {
        "hits": dict(ENGINE_STATS["hits"]),
        "last_success": ENGINE_STATS["last_success"],
        "successes": ENGINE_STATS["successes"],
        "total_runs": ENGINE_STATS["total_runs"],
    }

    if delivered is not None:
        result["unpacked_size"] = len(delivered)
        result["sha256_unpacked"] = sha256(delivered)
        result["entropy_after"] = round(entropy(delivered), 4)
        result["size_ratio"] = round(len(delivered) / max(1, len(data)), 4)
        result["output_name"] = None
        if save_to:
            path = Path(save_to)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(delivered)
                result["output_name"] = path.name
                result["saved_to"] = str(path)
            except OSError as ex:
                result["notes"].append(f"save failed: {ex}")

        if clean_with_digital and result["output_name"]:
            try:
                from .neural_cleaner import neural_clean
                is_exe = delivered[:2] == b"MZ" or delivered[:4] in (b"\x7fELF", b"\xfe\xed\xfa")
                clean = neural_clean(str(path), strip_ads=not is_exe and True, dry_run=is_exe)
                result["neural_clean"] = {
                    "dry_run": bool(clean.get("dry_run")),
                    "stripped_metadata": clean.get("stripped_metadata", []),
                    "ads_removed": clean.get("ads_removed", []),
                    "bytes_changed": clean.get("bytes_changed", 0),
                }
                if is_exe and clean.get("bytes_changed", 0) == 0:
                    result["neural_clean"]["note"] = "ميول: نسخة قابلة للتنفيذ — فحص جاف (لم يُعدَّل المحتوى)."
            except Exception as ex:
                result["notes"].append(f"neural_clean: {ex}")
    else:
        result["error"] = "لم يتم العثور على طبقة قابلة للفك بجميع المحركات."

    result["elapsed_sec"] = round(time.perf_counter() - t0, 4)
    return result
