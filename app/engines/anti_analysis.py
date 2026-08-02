"""Advanced Anti-Analysis detection + optional static bypass patches."""
from __future__ import annotations

import re
import struct
from typing import Any

from .common import extract_ascii_strings, pe_imports_and_sections, sha256


# Patterns: name, indicator type, severity, description, optional patch strategy
PATTERNS = [
    # API imports
    {"id": "IsDebuggerPresent", "kind": "api", "sev": "high", "desc": "Classic PEB debugger flag check"},
    {"id": "CheckRemoteDebuggerPresent", "kind": "api", "sev": "high", "desc": "Remote debugger detection"},
    {"id": "NtQueryInformationProcess", "kind": "api", "sev": "high", "desc": "ProcessDebugPort / flags class"},
    {"id": "NtSetInformationThread", "kind": "api", "sev": "medium", "desc": "Hide thread from debugger"},
    {"id": "OutputDebugStringA", "kind": "api", "sev": "low", "desc": "Debugger presence via last error trick"},
    {"id": "OutputDebugStringW", "kind": "api", "sev": "low", "desc": "Debugger presence via last error trick"},
    {"id": "GetTickCount", "kind": "api", "sev": "medium", "desc": "Timing anti-sandbox (often with Sleep)"},
    {"id": "GetTickCount64", "kind": "api", "sev": "medium", "desc": "Timing anti-sandbox"},
    {"id": "QueryPerformanceCounter", "kind": "api", "sev": "medium", "desc": "High-res timing checks"},
    {"id": "NtQuerySystemInformation", "kind": "api", "sev": "medium", "desc": "System kernel debugger / process list"},
    {"id": "FindWindowA", "kind": "api", "sev": "medium", "desc": "Search analysis tool windows"},
    {"id": "FindWindowW", "kind": "api", "sev": "medium", "desc": "Search analysis tool windows"},
    {"id": "EnumProcesses", "kind": "api", "sev": "low", "desc": "Process list reconnaissance"},
    {"id": "CreateToolhelp32Snapshot", "kind": "api", "sev": "low", "desc": "Process/module snapshot"},
    {"id": "GetSystemFirmwareTable", "kind": "api", "sev": "medium", "desc": "SMBIOS VM detection"},
    {"id": "cpuid", "kind": "string", "sev": "medium", "desc": "CPUID hypervisor bit strings"},
    # strings recognizers
]

STRING_INDICATORS = [
    (r"(?i)ollydbg", "tool", "high", "OllyDbg"),
    (r"(?i)x64dbg", "tool", "high", "x64dbg"),
    (r"(?i)x32dbg", "tool", "high", "x32dbg"),
    (r"(?i)windbg", "tool", "high", "WinDbg"),
    (r"(?i)ida(q|pro|64)?", "tool", "high", "IDA Pro"),
    (r"(?i)ghidra", "tool", "high", "Ghidra"),
    (r"(?i)wireshark", "tool", "medium", "Wireshark"),
    (r"(?i)processhacker", "tool", "medium", "Process Hacker"),
    (r"(?i)procmon", "tool", "medium", "Process Monitor"),
    (r"(?i)fiddler", "tool", "low", "Fiddler"),
    (r"(?i)vbox|virtualbox|vmware|qemu|xen|virtual\s*machine", "vm", "high", "VM environment string"),
    (r"(?i)sandboxie|cuckoo|any\.?run|joebox|threattrack", "sandbox", "high", "Sandbox product string"),
    (r"(?i)SbieDll", "sandbox", "high", "Sandboxie DLL"),
    (r"(?i)vmci|vmmemctl|VBoxGuest|VBoxMouse|vmtoolsd", "vm", "high", "VM guest additions artifact"),
    (r"(?i)debugger|isdebuggerpresent", "dbg", "medium", "Debugger-related string"),
]


# x86/x64 instruction signatures coding IsDebuggerPresent-style PEB walk is complex;
# we scan byte patterns for common stubs:
BYTE_PATTERNS = [
    # 64-bit: mov rax, gs:[0x60]  => 65 48 8B 04 25 60 00 00 00
    {"id": "peb_gs_60", "sig": bytes.fromhex("65488b042560000000"), "sev": "high", "desc": "x64 PEB access gs:[0x60]"},
    # 32-bit: mov eax, fs:[0x30] => 64 A1 30 00 00 00
    {"id": "peb_fs_30", "sig": bytes.fromhex("64a130000000"), "sev": "high", "desc": "x86 PEB access fs:[0x30]"},
    # int 2d / icebp anti-debug
    {"id": "int2d", "sig": bytes.fromhex("cd2d"), "sev": "medium", "desc": "INT 2D kernel debugger probe"},
    {"id": "icebp", "sig": bytes.fromhex("f1"), "sev": "low", "desc": "ICEBP (F1) single-byte trap"},
    # rdtsc
    {"id": "rdtsc", "sig": bytes.fromhex("0f31"), "sev": "medium", "desc": "RDTSC timing"},
    # cpuid
    {"id": "cpuid", "sig": bytes.fromhex("0fa2"), "sev": "low", "desc": "CPUID instruction"},
]


def scan_anti_analysis(data: bytes) -> dict[str, Any]:
    pe = pe_imports_and_sections(data)
    findings: list[dict[str, Any]] = []
    imports_flat = []
    for imp in pe.get("imports", []):
        for f in imp.get("funcs", []):
            imports_flat.append((imp.get("dll") or "", f))

    for api in PATTERNS:
        if api["kind"] != "api":
            continue
        for dll, fn in imports_flat:
            if fn.lower() == api["id"].lower() or api["id"].lower() in fn.lower():
                findings.append(
                    {
                        "id": api["id"],
                        "kind": "import",
                        "severity": api["sev"],
                        "where": f"{dll}!{fn}",
                        "desc": api["desc"],
                        "patchable": api["id"]
                        in (
                            "IsDebuggerPresent",
                            "CheckRemoteDebuggerPresent",
                        ),
                    }
                )

    strings = extract_ascii_strings(data, 4)
    blob_index = {}  # string -> offsets approx via find
    joined_cache = data  # binary search
    for s in strings:
        for rx, kind, sev, label in STRING_INDICATORS:
            if re.search(rx, s):
                off = data.find(s.encode("ascii", errors="ignore")[:64])
                findings.append(
                    {
                        "id": label,
                        "kind": kind,
                        "severity": sev,
                        "where": f'string@0x{off:x}' if off >= 0 else "string",
                        "desc": f"Artifact string matched /{rx}/ → {s[:80]}",
                        "patchable": False,
                        "string": s[:120],
                    }
                )
                break  # one match per string

    for bp in BYTE_PATTERNS:
        start = 0
        hits = 0
        sig = bp["sig"]
        while hits < 8:
            idx = data.find(sig, start)
            if idx < 0:
                break
            findings.append(
                {
                    "id": bp["id"],
                    "kind": "bytesig",
                    "severity": bp["sev"],
                    "where": f"offset 0x{idx:x}",
                    "desc": bp["desc"],
                    "patchable": bp["id"] in ("peb_gs_60", "peb_fs_30", "int2d", "icebp"),
                    "offset": idx,
                    "length": len(sig),
                }
            )
            hits += 1
            start = idx + 1

    # score
    sev_w = {"high": 3, "medium": 2, "low": 1}
    score = sum(sev_w.get(f["severity"], 1) for f in findings)
    # dedupe by id+where
    uniq = []
    seen = set()
    for f in findings:
        k = (f["id"], f["where"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)

    return {
        "ok": True,
        "sha256": sha256(data),
        "pe_valid": pe.get("valid", False),
        "findings": uniq[:200],
        "count": len(uniq),
        "risk_score": min(100, score * 3),
        "summary": _summary(uniq),
        "bypass_plan": _bypass_plan(uniq),
    }


def _summary(findings: list[dict]) -> str:
    if not findings:
        return "No common anti-analysis indicators found (may still be present)."
    highs = sum(1 for f in findings if f["severity"] == "high")
    return f"{len(findings)} indicators ({highs} high). Runtime patching available for subset."


def _bypass_plan(findings: list[dict]) -> list[str]:
    plan = []
    ids = {f["id"] for f in findings}
    if "IsDebuggerPresent" in ids or "peb_gs_60" in ids or "peb_fs_30" in ids:
        plan.append("Patch PEB BeingDebugged / force IsDebuggerPresent → return 0 (xor eax,eax; ret)")
    if "CheckRemoteDebuggerPresent" in ids:
        plan.append("Hook/patch CheckRemoteDebuggerPresent to clear debugger flag")
    if "rdtsc" in ids or "GetTickCount" in ids:
        plan.append("Normalize timing: Sleep-skip + RDTSC spoof (sandbox policy)")
    if any(f["kind"] in ("vm", "sandbox") for f in findings):
        plan.append("Spoof environment strings / hide VBox/VMware artifacts (Advanced)")
    if any(f["kind"] == "tool" for f in findings):
        plan.append("Rename analyst tools or patch FindWindow string compares")
    if not plan:
        plan.append("No automated patch recipe — manual triage recommended")
    return plan


def apply_bypass_patches(data: bytes, aggressive: bool = False) -> dict[str, Any]:
    """
    Produce a patched *copy* of the sample with common anti-debug stubs neutralized.
    For lab use only on samples you are authorized to modify.
    """
    buf = bytearray(data)
    patches = []

    def patch_at(off: int, new: bytes, reason: str):
        if off < 0 or off + len(new) > len(buf):
            return
        old = bytes(buf[off : off + len(new)])
        buf[off : off + len(new)] = new
        patches.append({"offset": off, "old": old.hex(), "new": new.hex(), "reason": reason})

    # NOP peb reads / replace with xor rax,rax sequence is architecture specific —
    # Safer early strategy: patch import thunk IsDebuggerPresent via code cave search looks for
    # call [IsDebuggerPresent] patterns is complex. We apply:
    # 1) Freeze int2d -> nop nop
    start = 0
    while True:
        idx = bytes(buf).find(bytes.fromhex("cd2d"), start)
        if idx < 0:
            break
        patch_at(idx, b"\x90\x90", "INT2D -> NOP NOP")
        start = idx + 2

    # 2) ICEBP -> NOP
    if aggressive:
        start = 0
        count = 0
        while count < 20:
            idx = bytes(buf).find(b"\xf1", start)
            if idx < 0:
                break
            # avoid patching inside entropy data randomly — only near code sections if PE
            patch_at(idx, b"\x90", "ICEBP -> NOP")
            count += 1
            start = idx + 1

    # 3) IsDebuggerPresent prologue patch: find import stubs hard —
    # Pattern for common wrapper: FF 15 xx xx xx xx (call dword ptr) near string
    # Patch ASCII "IsDebuggerPresent" keep string; instead modify PEB x64 sequence
    # 65 48 8B 04 25 60 00 00 00  -> 48 31 C0 90 90 90 90 90 90  (xor rax,rax + nops) so later deref may crash
    # Safer: only replace full known stub: 64 A1 30 00 00 00 0F B6 40 02 C3  (mov eax,fs:30; movzx eax,[eax+2]; ret)
    stubs = [
        (bytes.fromhex("64a1300000000fb64002c3"), bytes.fromhex("31c0c390909090909090"), "x86 IsDebuggerPresent-like PEB.BeingDebugged"),
        (bytes.fromhex("64a1300000008a4002c3"), bytes.fromhex("31c0c3909090909090"), "x86 BeingDebugged short"),
    ]
    for old, new, reason in stubs:
        start = 0
        while True:
            idx = bytes(buf).find(old, start)
            if idx < 0:
                break
            patch_at(idx, new, reason)
            start = idx + 1

    # x64: mov rax, gs:[0x60]; movzx eax, byte ptr [rax+2]; ret
    # 65 48 8B 04 25 60 00 00 00 0F B6 40 02 C3
    old = bytes.fromhex("65488b0425600000000fb64002c3")
    new = bytes.fromhex("4831c0c390909090909090909090")  # xor rax,rax; ret; nops
    start = 0
    while True:
        idx = bytes(buf).find(old, start)
        if idx < 0:
            break
        patch_at(idx, new[: len(old)], "x64 PEB.BeingDebugged stub -> return 0")
        start = idx + 1

    return {
        "ok": True,
        "patches_applied": len(patches),
        "patches": patches[:100],
        "patched_sha256": sha256(bytes(buf)),
        "original_sha256": sha256(data),
        "data": bytes(buf) if patches else data,
        "note": "Static patches are best-effort. Runtime instrumentation (ScyllaHide / custom DBI) is stronger.",
    }
