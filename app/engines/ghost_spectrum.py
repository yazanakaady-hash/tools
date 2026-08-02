"""Ghost Spectrum — PE/ELF header + PEB-stealth static lab report.

User-mode analysis only: maps PEB BeingDebugged / NtGlobalFlag patterns,
ELF note sections, and crafts an in-memory stealth plan (no kernel driver).
"""
from __future__ import annotations

import struct
from typing import Any

from .common import extract_ascii_strings, pe_imports_and_sections, sha256


PEB_MARKERS = [
    (bytes.fromhex("65488b042560000000"), "x64 gs:[0x60] PEB"),
    (bytes.fromhex("64a130000000"), "x86 fs:[0x30] PEB"),
    (bytes.fromhex("80b80000000000"), "cmp [rax+0] BeingDebugged prob"),
    (b"BeingDebugged", "PEB.BeingDebugged string"),
    (b"NtGlobalFlag", "PEB.NtGlobalFlag string"),
    (b"ProcessHeap", "PEB.ProcessHeap string"),
]


def _elf_info(data: bytes) -> dict[str, Any]:
    if data[:4] != b"\x7fELF":
        return {"valid": False}
    ei_class = data[4]  # 1=32 2=64
    ei_data = data[5]   # 1=LE 2=BE
    return {
        "valid": True,
        "class": "ELF64" if ei_class == 2 else "ELF32",
        "endian": "LE" if ei_data == 1 else "BE",
        "type": struct.unpack_from("<H", data, 16)[0] if ei_data == 1 and len(data) > 18 else None,
        "machine": struct.unpack_from("<H", data, 18)[0] if ei_data == 1 and len(data) > 20 else None,
    }


def _header_patch_plan(data: bytes, pe: dict) -> list[dict[str, Any]]:
    plan = []
    if pe.get("valid"):
        plan.append(
            {
                "target": "IMAGE_FILE_HEADER.Characteristics",
                "action": "clear DEBUG_STRIPPED noise / hide stripped bit inconsistencies",
                "lab_only": True,
            }
        )
        plan.append(
            {
                "target": "OptionalHeader.CheckSum",
                "action": "zero checksum for loader bypass testing",
                "lab_only": True,
            }
        )
        plan.append(
            {
                "target": "PEB.BeingDebugged (runtime)",
                "action": "hook/zero via hardware BP or vehicular loader stub — cache-only",
                "lab_only": True,
            }
        )
        plan.append(
            {
                "target": "PEB.NtGlobalFlag",
                "action": "mask FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS",
                "lab_only": True,
            }
        )
    if data[:4] == b"\x7fELF":
        plan.append(
            {
                "target": "ELF e_flags / .note.ABI-tag",
                "action": "normalize notes that fingerprint sandbox loaders",
                "lab_only": True,
            }
        )
    return plan


def ghost_spectrum(data: bytes, filename: str = "sample") -> dict[str, Any]:
    pe = pe_imports_and_sections(data)
    elf = _elf_info(data)
    markers: list[dict[str, Any]] = []
    for sig, label in PEB_MARKERS:
        off = 0
        hits = 0
        while True:
            i = data.find(sig, off)
            if i < 0:
                break
            hits += 1
            if hits <= 8:
                markers.append({"offset": i, "label": label, "sig_hex": sig[:12].hex()})
            off = i + 1
            if hits > 32:
                break

    strings = extract_ascii_strings(data, 5)
    ghost_strings = [
        s for s in strings
        if any(k in s.lower() for k in ("peb", "ntdll", "dbg", "beingdebugged", "ntglobalflag", "heapflags"))
    ][:40]

    invisibility = min(99, 40 + len(markers) * 4 + (12 if pe.get("valid") else 0))
    plan = _header_patch_plan(data, pe)

    # Simulate cache-only patch artifact (report, not on-disk mutation of host)
    cache_blob = {
        "mode": "cache_only",
        "spectrum_id": sha256(data)[:16],
        "patches": len(plan),
        "kernel_visible": False,
        "note": "lab report — no kernel driver attached",
    }

    return {
        "ok": True,
        "module": "Ghost Spectrum",
        "filename": filename,
        "pe": {"valid": pe.get("valid"), "machine": pe.get("machine"), "sections": len(pe.get("sections") or [])},
        "elf": elf,
        "peb_markers": markers,
        "marker_count": len(markers),
        "ghost_strings": ghost_strings,
        "invisibility_score": invisibility,
        "header_patch_plan": plan,
        "cache_plan": cache_blob,
        "summary": f"Ghost Spectrum: {len(markers)} PEB/header markers · invisibility={invisibility}",
    }
