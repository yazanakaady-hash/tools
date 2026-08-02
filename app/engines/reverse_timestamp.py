"""Reverse Timestamp — compiler optimization fingerprints -> CVE hypothetics.

Maps Rich header / linker / opt signatures to known toolchain-era CVEs and
emits a lab exploit *plan* (not a live rootkit). Probabilistic.
"""
from __future__ import annotations

import re
import struct
from typing import Any

from .common import extract_ascii_strings, pe_imports_and_sections, sha256


# Toolchain signature -> era + sample CVEs (historical compiler/runtime chain)
TOOLCHAIN_CVE = [
    {
        "id": "msvc_vs2015_v140",
        "markers": [b"MSVC", b"VCRUNTIME140", b"api-ms-win-crt", b"GSHandlerCheck"],
        "era": "VS2015-2017",
        "opts": ["/GS", "/O2", "/GL possible"],
        "cves": [
            {"cve": "CVE-2016-0040", "note": "Win32k era side-channel paired with CRT age"},
            {"cve": "CVE-2015-6112", "note": "ATMFD-era chain correlation with older MSVC stacks"},
        ],
        "weight": 0,
    },
    {
        "id": "msvc_vs2019_v142",
        "markers": [b"VCRUNTIME140_1", b"__CxxFrameHandler4", b"vcruntime140_1"],
        "era": "VS2019+",
        "opts": ["/guard:cf possible", "/Gy"],
        "cves": [
            {"cve": "CVE-2020-17087", "note": "kernel queue — only relevant if driver adjacent"},
        ],
        "weight": 0,
    },
    {
        "id": "mingw_gcc",
        "markers": [b"libgcc", b"mingw", b"__mingw_", b"GCC:", b"_Jv_RegisterClasses"],
        "era": "MinGW-GCC",
        "opts": ["-O2", "-fstack-protector?"],
        "cves": [
            {"cve": "CVE-2018-12882", "note": "GCC stack clash class — check ssp"},
        ],
        "weight": 0,
    },
    {
        "id": "golang",
        "markers": [b"runtime.main", b"go.buildid", b"runtime.G", b"runtime.sched"],
        "era": "Go toolchain",
        "opts": ["register abi", "PIE default modern"],
        "cves": [
            {"cve": "CVE-2019-16276", "note": "net/http smuggling class if Go HTTP linked"},
        ],
        "weight": 0,
    },
    {
        "id": "rustc",
        "markers": [b"rustc", b"rust_begin_unwind", b"core::panicking"],
        "era": "Rustc",
        "opts": ["LLVM opts"],
        "cves": [
            {"cve": "CVE-2024-24576", "note": "Windows batch escaping — only if Command::new used"},
        ],
        "weight": 0,
    },
    {
        "id": "delphi_borland",
        "markers": [b"Borland", b"Embarcadero", b"TForm", b"System.SysUtils"],
        "era": "Delphi/Borland",
        "opts": ["fastcall-ish"],
        "cves": [
            {"cve": "CVE-2011-0611", "note": "historical Flash/Delphi dropper correlation only"},
        ],
        "weight": 0,
    },
]


def _rich_header(data: bytes) -> dict[str, Any] | None:
    if data[:2] != b"MZ" or len(data) < 0x200:
        return None
    # Rich header sits before PE header
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off <= 0x80 or pe_off > len(data):
        return None
    region = data[0x80:pe_off]
    idx = region.find(b"Rich")
    if idx < 0:
        return None
    return {
        "offset": 0x80 + idx,
        "present": True,
        "preview": region[max(0, idx - 16) : idx + 8].hex(),
    }


def reverse_timestamp(data: bytes, filename: str = "sample") -> dict[str, Any]:
    pe = pe_imports_and_sections(data)
    strings = extract_ascii_strings(data, 4)
    blob = data  # byte search
    ranked = []
    for tool in TOOLCHAIN_CVE:
        hits = []
        for m in tool["markers"]:
            if m in blob or any(m.decode("latin1", errors="ignore").lower() in s.lower() for s in strings):
                hits.append(m.decode("latin1", errors="ignore"))
        score = len(hits) * 22
        if hits:
            ranked.append(
                {
                    "id": tool["id"],
                    "era": tool["era"],
                    "opts": tool["opts"],
                    "match_pct": min(96, score),
                    "markers_hit": hits,
                    "cves": tool["cves"],
                }
            )
    ranked.sort(key=lambda x: x["match_pct"], reverse=True)
    best = ranked[0] if ranked else None

    # PE TimeDateStamp
    ts = None
    if pe.get("valid"):
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            ts = struct.unpack_from("<I", data, pe_off + 8)[0]
        except Exception:
            ts = None

    rich = _rich_header(data)

    # Lab exploit plan (static recommendations — not a weaponized rootkit)
    exploit_plan = []
    if best:
        for c in best.get("cves") or []:
            exploit_plan.append(
                {
                    "cve": c["cve"],
                    "phase": "recon",
                    "steps": [
                        f"Confirm toolchain era {best['era']} via markers {best['markers_hit'][:3]}",
                        f"Validate applicability: {c['note']}",
                        "Map gadget density / CFG openness (pair with Ant Colony)",
                        "If applicable, craft *lab* PoC under authorization — no persistence module emitted",
                    ],
                }
            )
    else:
        exploit_plan.append(
            {
                "cve": None,
                "phase": "fingerprint-only",
                "steps": ["No strong toolchain markers — enrich with more string/IAT coverage"],
            }
        )

    return {
        "ok": True,
        "module": "Reverse Timestamp",
        "filename": filename,
        "pe_timedatestamp": ts,
        "pe_timedatestamp_hex": f"0x{ts:08x}" if ts is not None else None,
        "rich_header": rich,
        "best_toolchain": best,
        "rankings": ranked,
        "exploit_plan": exploit_plan,
        "disclaimer": "CVE links are correlative hypotheses from compiler fingerprints — not confirmed exploitability.",
        "sample_sha256": sha256(data),
        "summary": (
            f"Reverse Timestamp: toolchain={(best or {}).get('id', 'unknown')} "
            f"match={(best or {}).get('match_pct', 0)}% · CVEs={len((best or {}).get('cves') or [])}"
        ),
    }
