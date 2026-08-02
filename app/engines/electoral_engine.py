"""Electoral Engine (المحرك الانتخاري) — selective analysis router.

Votes on the best analysis pipeline for a given binary/blob: inspects magic
bytes, entropy, and size, then dispatches to the most relevant engine set.
Runs only lightweight probes so it can route in <50ms.
"""
from __future__ import annotations

import math
import struct
import time
import zlib
from collections import Counter
from typing import Any

# ── signature probes ───────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _probe(data: bytes, filename: str = "sample.bin") -> dict[str, Any]:
    ext = (filename or "").lower()
    sig: list[str] = []
    if data[:2] == b"MZ":
        sig.append("pe")
    if data[:4] == b"\x7fELF":
        sig.append("elf")
    if data[:4] == b"\x89PNG":
        sig.append("png")
    if data[:2] == b"\xff\xd8":
        sig.append("jpeg")
    if data[:4] == b"PK\x03\x04":
        sig.append("zip")
    if data[:2] == b"\x1f\x8b":
        sig.append("gzip")
    if data[:3] == b"BZh":
        sig.append("bzip2")
    if data[:5] == b"<html" or data[:5] == b"<?xml" or data[:6] == b"<!DOCT":
        sig.append("markup")
    if data[:4] in (b"\xd0\xcf\x11\xe0",):
        sig.append("ole")
    if data[:4] in (b"RENS", b"KMKZ", b"GHST", b"VAULT"):
        sig.append("encrypted")
    if data[:8] == b"\x4d\x3c\xb2\xa1\x00\x00\x00\x00" or b"\xfe\xed\xfa\xce" in data[:16] or b"\xfe\xed\xfa\xcf" in data[:16]:
        sig.append("macho")
    if b"import " in data[:4096] or b"#include" in data[:4096]:
        sig.append("source-c")
    if b"<script" in data[:4096] or b"function " in data[:4096]:
        sig.append("source-js")
    if not sig:
        ent = _entropy(data[:4096])
        if ent > 7.2:
            sig.append("high-entropy")
        else:
            sig.append("text-or-unknown")
    if sig and ext:
        for s in ("pyc", "py", "js", "json", "html", "xml", "csv", "zip", "png", "jpg", "pcap", "elf", "exe", "dll"):
            if ext.endswith(s):
                sig.append(f"ext:{s}")
    return {
        "size": len(data),
        "entropy": round(_entropy(data[:8192]), 4),
        "signatures": list(dict.fromkeys(sig)),
    }


# ── engine tables ──────────────────────────────────────────────────

ROUTES: dict[str, list[str]] = {
    "pe": ["shell_ripper", "sovereignty", "reverse_timestamp", "tetra_cube", "memory_keys"],
    "elf": ["shell_ripper", "ghost_spectrum", "author", "reverse_timestamp"],
    "encrypted": ["speculative_brute", "entropy", "kamikaze"],
    "zip": ["shell_ripper", "spectral", "fork"],
    "gzip": ["shell_ripper", "author"],
    "bzip2": ["shell_ripper", "author"],
    "png": ["ghost_inlayer", "neural_clean", "entropy"],
    "jpeg": ["neural_clean", "entropy"],
    "markup": ["author", "compiler_flip"],
    "ole": ["shell_ripper", "sovereignty", "memory_keys"],
    "source-c": ["author", "brain_link"],
    "source-js": ["compiler_flip", "author"],
    "high-entropy": ["entropy", "speculative_brute"],
    "text-or-unknown": ["author", "entropy"],
    "macho": ["ghost_spectrum", "author"],
}

PRIORITIES: dict[str, int] = {
    "shell_ripper": 5, "sovereignty": 4, "reverse_timestamp": 4, "tetra_cube": 4,
    "memory_keys": 3, "ghost_spectrum": 4, "author": 2, "speculative_brute": 3,
    "entropy": 2, "kamikaze": 3, "spectral": 2, "fork": 2, "ghost_inlayer": 3,
    "neural_clean": 2, "compiler_flip": 3, "brain_link": 3,
}

ENGINE_LABELS: dict[str, str] = {
    "shell_ripper": "تمزيق الأصداف", "sovereignty": "محطم السيادة",
    "reverse_timestamp": "البصمة الزمنية المعكوسة", "tetra_cube": "المكعب الرباعي",
    "memory_keys": "مصيدة المفاتيح", "ghost_spectrum": "الطيف الخفي",
    "author": "إسناد المؤلف", "speculative_brute": "الاختراق التخميني",
    "entropy": "الانتروبيا الحيوية", "kamikaze": "المحرك الانتحاري",
    "spectral": "الماسح الطيفي", "fork": "الناسخ المتشعب",
    "ghost_inlayer": "المدمج الخفي", "neural_clean": "المنظف العصبي",
    "compiler_flip": "مقلب المترجم", "brain_link": "الوصلة الدماغية",
}


def electoral_route(data: bytes, filename: str = "sample.bin",
                    max_engines: int = 6) -> dict[str, Any]:
    """Vote on the best engine pipeline for this blob."""
    result: dict[str, Any] = {"ok": True, "filename": filename, "elapsed_sec": 0.0}
    t0 = time.perf_counter()
    try:
        probe = _probe(data, filename)
        result["probe"] = probe

        votes: dict[str, int] = {}
        for sig in probe["signatures"]:
            key = sig[4:] if sig.startswith("ext:") else sig
            for eng in ROUTES.get(key, []):
                votes[eng] = votes.get(eng, 0) + PRIORITIES.get(eng, 1)

        if probe["signatures"] and not votes:
            votes["entropy"] = 1
            votes["author"] = 1

        ranked = sorted(votes.items(), key=lambda kv: kv[1], reverse=True)
        result["pipeline"] = [
            {"engine": eng, "label": ENGINE_LABELS.get(eng, eng), "score": score}
            for eng, score in ranked[:max_engines]
        ]
        result["primary"] = result["pipeline"][0]["engine"] if result["pipeline"] else "entropy"
        result["recommendation"] = _recommendation(probe, result["primary"])
        result["ok"] = True
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)
    result["elapsed_sec"] = round(time.perf_counter() - t0, 4)
    return result


def _recommendation(probe: dict[str, Any], primary: str) -> str:
    sigs = probe.get("signatures", [])
    if "encrypted" in sigs:
        return "ملف مشفر: جرّب كلمات ضعيفة أولاً ثم استخرج ببصمة الإنتروبيا."
    if "pe" in sigs:
        return "ملف PE: سحق الحماية أولاً ثم قِس الطبقات والزمن."
    if "zip" in sigs or "gzip" in sigs or "bzip2" in sigs:
        return "أرشيف: قشّر الطبقات واكتشف النوى."
    if "png" in sigs or "jpeg" in sigs:
        return "صورة: ابحث عن حمولة مخفية ثم نظّف البيانات الوصفية."
    return f"المحرك الأقوى هنا: {ENGINE_LABELS.get(primary, primary)}."

