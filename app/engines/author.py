"""Code Author Attribution — stylometry / toolchain fingerprinting."""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from .common import entropy, extract_ascii_strings, pe_imports_and_sections


# Expandable fingerprint corpus: toolchains, packing styles, demo "authors"
# Real attribution needs large labeled corpora — these are instruction-family fingerprints.
PROFILES: list[dict[str, Any]] = [
    {
        "id": "msvc_cpp",
        "name": "MSVC C/C++ toolchain",
        "tags": ["windows", "native"],
        "import_hints": ["KERNEL32.dll", "VCRUNTIME", "api-ms-win", "MSVCP"],
        "string_hints": [r"Microsoft Visual C\+\+", r"Runtime Error", r"RTTI", r"\.pdb$"],
        "section_hints": [".text", ".rdata", ".data", ".pdata", ".rsrc"],
        "notes": "Typical Visual Studio native binary",
    },
    {
        "id": "mingw_gcc",
        "name": "MinGW / GCC",
        "tags": ["windows", "gnu"],
        "import_hints": ["msvcrt.dll", "libgcc", "libwinpthread"],
        "string_hints": [r"GCC:", r"mingw", r"libgcj", r"__mingw"],
        "section_hints": [".text", ".data", ".rdata", ".bss", ".idata"],
        "notes": "GNU binutils Windows target",
    },
    {
        "id": "golang",
        "name": "Go compiler",
        "tags": ["go"],
        "import_hints": ["kernel32.dll", "advapi32.dll"],
        "string_hints": [r"runtime\.", r"go\.buildid", r"Go build ID", r"runtime_main"],
        "section_hints": [".text", ".rdata", ".data", ".zdebug"],
        "notes": "Go static-ish binaries with rich runtime strings",
    },
    {
        "id": "rust",
        "name": "Rust (rustc)",
        "tags": ["rust"],
        "import_hints": ["kernel32.dll", "bcryptprimitives.dll"],
        "string_hints": [r"rustc", r"CARGO_PKG", r"called `Option::unwrap\(\)`", r"panic"],
        "section_hints": [".text", ".rdata", ".data"],
        "notes": "Rust panic / fmt strings",
    },
    {
        "id": "dotnet",
        "name": ".NET / CLR",
        "tags": ["managed"],
        "import_hints": ["mscoree.dll"],
        "string_hints": [r"mscoree", r"\.NETFramework", r"System\.", r"BSJB"],
        "section_hints": [".text", ".rsrc", ".reloc"],
        "notes": "Managed assembly",
    },
    {
        "id": "python_frozen",
        "name": "PyInstaller / frozen Python",
        "tags": ["python"],
        "import_hints": [],
        "string_hints": [r"PyInstaller", r"python3", r"MEI\d+", r"_MEIPASS", r"pyi_"],
        "section_hints": [],
        "notes": "Packaged Python application",
    },
    {
        "id": "autoit",
        "name": "AutoIt script packer",
        "tags": ["script"],
        "import_hints": [],
        "string_hints": [r"AutoIt", r"AU3!", r">>>AUTOIT"],
        "section_hints": [],
        "notes": "AutoIt compiled script",
    },
    {
        "id": "upx_packed",
        "name": "UPX packer style",
        "tags": ["packer"],
        "import_hints": ["KERNEL32.DLL", "LoadLibraryA", "GetProcAddress"],
        "string_hints": [r"UPX\d*", r"UPX!"],
        "section_hints": ["UPX0", "UPX1", "UPX2"],
        "notes": "UPX compressed stub",
    },
    {
        "id": "delphi",
        "name": "Borland/Embarcadero Delphi",
        "tags": ["delphi"],
        "import_hints": ["user32.dll", "kernel32.dll"],
        "string_hints": [r"Borland", r"Embarcadero", r"TForm", r"System\.SysUtils"],
        "section_hints": [".text", ".itext", ".data", ".bss", ".idata", ".tls", ".rdata", ".reloc", ".rsrc"],
        "notes": "Delphi VCL patterns",
    },
    {
        "id": "rust_cobalt_adjacent",
        "name": "Beacon-like import pattern (generic)",
        "tags": ["tradecraft"],
        "import_hints": ["WININET.dll", "WINHTTP.dll", "WS2_32.dll", "ADVAPI32.dll"],
        "string_hints": [r"%02d/%02d/%02d", r"beacon", r"pipe\\\\"],  # cautious
        "section_hints": [".text", ".rdata", ".data"],
        "notes": "Generic C2-ish WinINet + sockets blend — not family ID",
    },
    {
        "id": "style_alpha",
        "name": "Demo Author α (short hungarian vars)",
        "tags": ["demo_author"],
        "import_hints": [],
        "string_hints": [r"\bstr[A-Z]\w+", r"\bn[A-Z]\w+", r"TODO:", r"FIXME"],
        "section_hints": [],
        "style": {"avg_ident_len": (4, 8), "comment_density": (0.0, 0.05)},
        "notes": "Synthetic stylometry persona for demo matching",
    },
    {
        "id": "style_beta",
        "name": "Demo Author β (verbose snake_case)",
        "tags": ["demo_author"],
        "import_hints": [],
        "string_hints": [r"[a-z]+_[a-z]+_[a-z]+", r"error_message", r"result_code"],
        "section_hints": [],
        "style": {"avg_ident_len": (10, 22), "comment_density": (0.02, 0.2)},
        "notes": "Synthetic stylometry persona for demo matching",
    },
]


def _features_from_binary(data: bytes) -> dict[str, Any]:
    strings = extract_ascii_strings(data, 5)
    pe = pe_imports_and_sections(data)
    dlls = [i["dll"] for i in pe.get("imports", [])]
    funcs = [f for i in pe.get("imports", []) for f in i.get("funcs", [])]
    sections = [s["name"] for s in pe.get("sections", [])]

    # identifier-like tokens from strings
    idents = []
    for s in strings[:5000]:
        idents += re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,40}\b", s)
    avg_ident = sum(len(x) for x in idents) / max(len(idents), 1)
    snake = sum(1 for x in idents if "_" in x) / max(len(idents), 1)
    camel = sum(1 for x in idents if re.search(r"[a-z][A-Z]", x)) / max(len(idents), 1)
    comments = sum(1 for s in strings if s.strip().startswith(("//", "/*", "#", ";")))
    comment_density = comments / max(len(strings), 1)

    return {
        "strings": strings[:8000],
        "string_count": len(strings),
        "dlls": dlls,
        "funcs": funcs[:500],
        "sections": sections,
        "pe_valid": pe.get("valid", False),
        "avg_ident_len": round(avg_ident, 2),
        "snake_ratio": round(snake, 3),
        "camel_ratio": round(camel, 3),
        "comment_density": round(comment_density, 4),
        "entropy": entropy(data[: min(len(data), 256 * 1024)]),
        "nested_braces_hint": _brace_nest_hint(strings),
    }


def _brace_nest_hint(strings: list[str]) -> int:
    # crude: longest run of { in any string (embedded source?)
    m = 0
    for s in strings:
        depth = cur = 0
        for ch in s:
            if ch == "{":
                cur += 1
                depth = max(depth, cur)
            elif ch == "}":
                cur = max(0, cur - 1)
        m = max(m, depth)
    return m


def _score_profile(feat: dict[str, Any], profile: dict[str, Any]) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    blob = "\n".join(feat["strings"][:3000])
    dlls_l = [d.lower() for d in feat["dlls"]]
    secs = feat["sections"]

    for h in profile.get("import_hints", []):
        hl = h.lower()
        if any(hl in d for d in dlls_l) or any(hl in f.lower() for f in feat["funcs"]):
            score += 12
            reasons.append(f"import:{h}")

    for h in profile.get("string_hints", [])[:20]:
        try:
            if re.search(h, blob, re.I | re.M):
                score += 10
                reasons.append(f"string:/{h}/")
        except re.error:
            if h.lower() in blob.lower():
                score += 8
                reasons.append(f"string:{h}")

    for h in profile.get("section_hints", []):
        if h in secs or any(h.lower() in s.lower() for s in secs):
            score += 8
            reasons.append(f"section:{h}")

    style = profile.get("style")
    if style:
        lo, hi = style.get("avg_ident_len", (0, 99))
        if lo <= feat["avg_ident_len"] <= hi:
            score += 15
            reasons.append(f"ident_len={feat['avg_ident_len']}")
        clo, chi = style.get("comment_density", (0, 1))
        if clo <= feat["comment_density"] <= chi:
            score += 8
            reasons.append(f"comments={feat['comment_density']}")

    # normalize loosely to %
    pct = min(99.0, score)
    return pct, reasons


def _features_from_source(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    comments = sum(1 for l in lines if l.strip().startswith(("//", "#", "/*", "*", ";")))
    idents = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,40}\b", text)
    avg_ident = sum(len(x) for x in idents) / max(len(idents), 1)
    snake = sum(1 for x in idents if "_" in x) / max(len(idents), 1)
    camel = sum(1 for x in idents if re.search(r"[a-z][A-Z]", x)) / max(len(idents), 1)
    # nesting depth
    depth = cur = max_d = 0
    for ch in text:
        if ch in "{(":
            cur += 1
            max_d = max(max_d, cur)
        elif ch in "})":
            cur = max(0, cur - 1)
    return {
        "strings": lines[:5000],
        "string_count": len(lines),
        "dlls": [],
        "funcs": [],
        "sections": [],
        "pe_valid": False,
        "avg_ident_len": round(avg_ident, 2),
        "snake_ratio": round(snake, 3),
        "camel_ratio": round(camel, 3),
        "comment_density": round(comments / max(len(lines), 1), 4),
        "entropy": entropy(text.encode("utf-8", errors="ignore")[:65536]),
        "nested_braces_hint": max_d,
    }


def attribute_author(data: bytes, filename: str = "") -> dict[str, Any]:
    # source?
    is_text = False
    try:
        if filename.endswith((".c", ".cpp", ".h", ".py", ".rs", ".go", ".cs", ".js", ".java")):
            is_text = True
        elif entropy(data[:4096]) < 5.0:
            data.decode("utf-8")
            is_text = True
    except Exception:
        is_text = False

    if is_text:
        try:
            feat = _features_from_source(data.decode("utf-8", errors="replace"))
            mode = "source"
        except Exception:
            feat = _features_from_binary(data)
            mode = "binary"
    else:
        feat = _features_from_binary(data)
        mode = "binary"

    ranked = []
    for p in PROFILES:
        pct, reasons = _score_profile(feat, p)
        ranked.append(
            {
                "id": p["id"],
                "name": p["name"],
                "match_pct": round(pct, 1),
                "tags": p.get("tags", []),
                "reasons": reasons[:12],
                "notes": p.get("notes", ""),
            }
        )
    ranked.sort(key=lambda x: x["match_pct"], reverse=True)

    top = ranked[0] if ranked else None
    return {
        "ok": True,
        "mode": mode,
        "filename": filename,
        "features": {
            "avg_ident_len": feat["avg_ident_len"],
            "snake_ratio": feat["snake_ratio"],
            "camel_ratio": feat["camel_ratio"],
            "comment_density": feat["comment_density"],
            "nesting_hint": feat["nested_braces_hint"],
            "string_count": feat["string_count"],
            "sections": feat["sections"],
            "import_dlls": feat["dlls"][:30],
            "entropy": feat["entropy"],
            "pe_valid": feat["pe_valid"],
        },
        "matches": ranked[:8],
        "best": top,
        "disclaimer": (
            "Stylometry + toolchain fingerprinting — probabilistic only. "
            "Demo author personas are synthetic. Expand PROFILES with your own labeled corpus "
            "for real investigations. Not court-admissible without peer-reviewed method + large dataset."
        ),
    }
