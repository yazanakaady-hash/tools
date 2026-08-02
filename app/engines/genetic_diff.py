"""genetic_diff — الوراثة التفاضلية (Genetic Diffing).

مقارنة ملفين "تطورياً" عبر difflib.SequenceMatcher على مستوى الكتل
والسطور، ومسافة Levenshtein على صفوف النصوص، مع ملف تعريف تشابه الكتل،
والسلاسل الغريبة المشتركة، واستنتاج "التوقيع الشخصي للمبرمج"
(إزاحة، أقواس، تسمية، تعليقات، نهايات الأسطر) لتقدير القرابة.

المنهجية: التشابه ≥ 0.80 = نفس العائلة (fork/متغيّر)،
≥ 0.50 = قرابة، أقل من ذلك = لا قرابة.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from pathlib import Path
from typing import Any

from .common import extract_ascii_strings

_MAX_ROWS = 20000      # سقف أسطر النص لمسار Levenshtein
_MAX_DIFF_LINES = 40   # أسطر معاينة الفروقات
_FAMILY_THRESHOLD = 0.80
_RELATED_THRESHOLD = 0.50

# تلوث مترجم/أداة مشترك يُستبعد من "السلاسل الغريبة المشتركة"
_NOISE_STRINGS = {
    "gcc", "clang", "msvc", ".rdata", ".data", ".text", "ffffffff", "00000000",
    "std::", "__cxa", "libc", "abort", "malloc", "free", "memcpy", "memset",
    "printf", "scanf", "main", "crt", "nullptr", "true", "false", "return",
    "int ", "char ", "void ", "static", "extern", "sizeof", "struct",
    "GCC:", ".debug", "VersionInfo", "kernel32", "user32", "ntdll",
}


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _lv_distance(a: list[str], b: list[str]) -> tuple[int, int]:
    """مسافة Levenshtein (صفوف) مع حد السقف — تُرجع (المسافة، عدد الصفوف)."""
    n, m = len(a), len(b)
    if n * m > _MAX_ROWS * 500:
        return -1, max(n, m)  # مكلفة جداً
    prev = list(range(m + 1))
    cur = [0] * (m + 1)
    for i in range(1, n + 1):
        cur[0] = i
        for j in range(1, m + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev, cur = cur, prev
    return prev[m], max(n, m)


def _pct_stats(items: list[float]) -> dict[str, float]:
    if not items:
        return {}
    s = sorted(items)
    n = len(s)

    def q(p: float) -> float:
        k = (n - 1) * p
        lo, hi = int(k), min(n - 1, int(k) + 1)
        return s[lo] + (s[hi] - s[lo]) * (k - lo)

    return {
        "min": round(s[0], 4),
        "max": round(s[-1], 4),
        "mean": round(sum(s) / n, 4),
        "median": round(q(0.5), 4),
        "q1": round(q(0.25), 4),
        "q3": round(q(0.75), 4),
        "count": n,
    }


def _is_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:65536]
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return b"\x00" not in sample


def _shared_unusual_strings(a: bytes, b: bytes, limit: int = 25) -> list[str]:
    sa = set(extract_ascii_strings(a, min_len=8))
    sb = set(extract_ascii_strings(b, min_len=8))
    shared = sa & sb
    out = []
    for s in shared:
        low = s.lower()
        if any(ns in low for ns in _NOISE_STRINGS):
            continue
        if low.isdigit() or all(c in "0123456789abcdefABCDEF" for c in low):
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return sorted(out)


def _programmer_signature(a: str, b: str) -> dict[str, Any]:
    """استدلال نمط الكود المشترك بين نصين."""
    la = a.splitlines()
    lb = b.splitlines()
    sample_a = [l for l in la if l.strip()][:4000]
    sample_b = [l for l in lb if l.strip()][:4000]
    if not sample_a or not sample_b:
        return {"confidence": 0.0, "hints": []}

    def counts(lines: list[str]) -> dict[str, Any]:
        tabs = spaces4 = spaces2 = braces_same = braces_next = 0
        snake = camel = hash_c = slash_c = star_c = 0
        crlf = 0
        for ln in lines:
            if "\r\n" in ln:
                crlf += 1
            if ln.startswith("\t"):
                tabs += 1
            elif ln.startswith("    "):
                spaces4 += 1
            elif ln.startswith("  "):
                spaces2 += 1
        for ln in lines:
            s = ln.strip()
            if re.search(r"\{\s*$", s):
                braces_same += 1
            elif re.match(r"^\{", s):
                braces_next += 1
            if re.search(r"\b[a-z]+_[a-z0-9_]*\b", s):
                snake += 1
            if re.search(r"\b[a-z]+[A-Z][A-Za-z0-9]*\b", s):
                camel += 1
            if s.startswith("#"):
                hash_c += 1
            if s.startswith("//"):
                slash_c += 1
            if s.startswith(("/*", "*", "/**")):
                star_c += 1
        return {
            "tabs": tabs, "spaces4": spaces4, "spaces2": spaces2,
            "braces_same_line": braces_same, "braces_next_line": braces_next,
            "snake_case": snake, "camelCase": camel,
            "hash_comments": hash_c, "slash_comments": slash_c, "star_comments": star_c,
            "crlf": crlf,
        }

    ca, cb = counts(sample_a), counts(sample_b)
    agree = 0
    total = 0
    hints: list[str] = []

    def dom(c: dict[str, int], keys: list[str]) -> str:
        best, bv = "", -1
        for k in keys:
            if c[k] > bv:
                best, bv = k, c[k]
        return best

    ind_a, ind_b = dom(ca, ["tabs", "spaces4", "spaces2"]), dom(cb, ["tabs", "spaces4", "spaces2"])
    total += 1
    if ind_a == ind_b and ca[ind_a] > 3:
        agree += 1
        hints.append(f"إزاحة متطابقة: {ind_a} (قوة {ca[ind_a]}+{cb[ind_b]})")
    else:
        hints.append(f"إزاحة مختلفة: A={ind_a} / B={ind_b}")

    brace_a, brace_b = dom(ca, ["braces_same_line", "braces_next_line"]), dom(cb, ["braces_same_line", "braces_next_line"])
    total += 1
    if brace_a == brace_b and ca[brace_a] > 1:
        agree += 1
        hints.append(f"أسلوب الأقواس متطابق: {'سطر الافتتاح نفسه' if brace_a == 'braces_same_line' else 'سطر مستقل'}")
    else:
        hints.append("أسلوب أقواس مختلف/ضعيف")

    naming_a, naming_b = dom(ca, ["snake_case", "camelCase"]), dom(cb, ["snake_case", "camelCase"])
    total += 1
    if naming_a == naming_b and ca[naming_a] > 1:
        agree += 1
        hints.append(f"تسمية متطابقة: {naming_a}")
    else:
        hints.append("اصطلاح تسمية مختلف")

    com_a = max(ca["hash_comments"], ca["slash_comments"], ca["star_comments"])
    com_b = max(cb["hash_comments"], cb["slash_comments"], cb["star_comments"])
    total += 1
    if (ca["hash_comments"] and cb["hash_comments"]) or (ca["slash_comments"] and cb["slash_comments"]):
        agree += 1
        hints.append("أسلوب تعليقات متقارب")
    else:
        hints.append("أسلوب تعليقات مختلف/ضعيف")

    if ca["crlf"] == cb["crlf"] and (ca["crlf"] or len(sample_a) - ca["crlf"]):
        total += 1
        agree += 1
        hints.append("نهايات أسطر متطابقة (CRLF/LF)")

    return {
        "confidence": round(agree / max(1, total), 2),
        "hints": hints,
    }


def genetic_diff(path_a: str, path_b: str, block_size: int = 4096) -> dict[str, Any]:
    """مقارنة ملفين عبر الوراثة التفاضلية.

    Parameters
    ----------
    path_a : str — الملف الأول.
    path_b : str — الملف الثاني.
    block_size : int — حجم الكتلة لملف تعريف التشابه.

    Returns
    -------
    dict — نسب التشابه، قرابة العائلة، توقيع المبرمج، والفروقات.
    """
    pa, pb = Path(path_a), Path(path_b)
    for p, key in ((pa, "a"), (pb, "b")):
        if not p.is_file():
            return {"ok": False, "error": f"ملف {key} غير موجود: {p}"}

    da = pa.read_bytes()
    db = pb.read_bytes()

    result: dict[str, Any] = {
        "ok": True,
        "path_a": str(pa.resolve()),
        "path_b": str(pb.resolve()),
        "files": {
            "a": {"name": pa.name, "size": len(da), "sha256": _sha(pa)},
            "b": {"name": pb.name, "size": len(db), "sha256": _sha(pb)},
        },
    }

    # ── تشابه الكتل (SequenceMatcher) ──
    ba = [da[i:i + block_size] for i in range(0, max(1, len(da)), block_size)]
    bb = [db[i:i + block_size] for i in range(0, max(1, len(db)), block_size)]
    sm = difflib.SequenceMatcher(None, ba, bb, autojunk=False)
    block_ratio = sm.ratio()
    matches = sm.get_matching_blocks()
    matched_blocks = sum(m.size for m in matches)
    identical = sum(1 for m in matches if m.size == max(1, len(da) // max(1, len(ba))))
    block_ratios = []
    i = j = 0
    for m in matches:
        while i < m.a:
            block_ratios.append(0.0)
            i += 1
        while j < m.b:
            block_ratios.append(0.0)
            j += 1
        for _ in range(m.size):
            block_ratios.append(1.0)
            i += 1
            j += 1
    while i < len(ba):
        block_ratios.append(0.0)
        i += 1
    while j < len(bb):
        block_ratios.append(0.0)
        j += 1

    result["block_profile"] = {
        "block_size": block_size,
        "blocks_a": len(ba),
        "blocks_b": len(bb),
        "matched_blocks": matched_blocks,
        "identical_blocks_pct": round(100.0 * (matched_blocks / max(1, min(len(ba), len(bb)))), 1),
        "stats": _pct_stats(block_ratios),
    }

    # ── مستوى السطور + Levenshtein ──
    text_a = _is_text(da)
    line_ratio = 0.0
    lv = {"rows_a": 0, "rows_b": 0, "distance": 0, "normalized": 0.0, "computed": False}
    diff_preview: list[str] = []
    if text_a and _is_text(db):
        try:
            ta = da.decode("utf-8", "replace")
            tb = db.decode("utf-8", "replace")
        except Exception:
            ta = tb = ""
        la, lb = ta.splitlines(), tb.splitlines()
        line_ratio = difflib.SequenceMatcher(None, la, lb, autojunk=False).ratio()
        d, rows = _lv_distance(la, lb)
        if d >= 0:
            lv = {
                "rows_a": len(la), "rows_b": len(lb),
                "distance": d,
                "normalized": round(1.0 - d / max(1, max(len(la), len(lb))), 4),
                "computed": True,
            }
        if len(la) + len(lb) <= _MAX_ROWS * 2 and max(len(da), len(db)) <= 2 * 1024 * 1024:
            diff = difflib.unified_diff(la, lb, fromfile=pa.name, tofile=pb.name, n=2)
            diff_preview = list(diff)[:_MAX_DIFF_LINES]
    result["overall"] = {
        "ratio_blocks": round(block_ratio, 4),
        "ratio_lines": round(line_ratio, 4),
        "same_family": block_ratio >= _FAMILY_THRESHOLD,
        "related": _RELATED_THRESHOLD <= block_ratio < _FAMILY_THRESHOLD,
    }
    result["levenshtein"] = lv
    result["diff_preview"] = diff_preview
    result["shared_unusual_strings"] = _shared_unusual_strings(da, db)

    if text_a:
        result["programmer_signature"] = _programmer_signature(ta, tb)
    else:
        result["programmer_signature"] = {"confidence": 0.0, "hints": ["ملفات ثنائية — لا يمكن استدلال نمط الشيفرة"]}

    if result["overall"]["same_family"]:
        verdict = "نفس العائلة — ملفان متقاربان جداً (fork / متغيّر / إعادة بناء)"
    elif result["overall"]["related"]:
        verdict = "قرابة متوسطة — تشابه جزئي (مكتبات مشتركة أو تعديلات)"
    else:
        verdict = "لا قرابة جوهرية — ملفان مختلفان"
    result["verdict"] = verdict

    family_note = f"تشابه الكتل {result['overall']['ratio_blocks']:.0%}"
    if lv["computed"]:
        family_note += f" · Levenshtein صفوف {lv['normalized']:.0%}"
    if result["shared_unusual_strings"]:
        family_note += f" · {len(result['shared_unusual_strings'])} سلسلة غريبة مشتركة"
    result["family_note"] = family_note
    return result
