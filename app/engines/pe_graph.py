"""Build 3D attack-surface graph from PE imports / strings / sections."""
from __future__ import annotations

import hashlib
from typing import Any

from .common import extract_ascii_strings, pe_imports_and_sections


DANGEROUS = {
    # code injection / memory
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "QueueUserAPC", "RtlCreateUserThread",
    "MapViewOfFile", "OpenProcess",
    # persistence / files
    "DeleteFileA", "DeleteFileW", "CreateFileA", "CreateFileW",
    "RegSetValue", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
    # network
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpOpenRequestA",
    "WinHttpOpen", "WSAStartup", "connect", "send", "recv", "URLDownloadToFileA",
    # crypto
    "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
    # recon
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetAsyncKeyState",
    "CreateToolhelp32Snapshot", "Process32FirstW",
    # shell
    "ShellExecuteA", "ShellExecuteW", "WinExec", "system",
    "CreateProcessA", "CreateProcessW",
}


def _nid(*parts: str) -> str:
    h = hashlib.md5("|".join(parts).encode()).hexdigest()[:12]
    return h


def build_attack_graph(data: bytes, filename: str = "sample") -> dict[str, Any]:
    pe = pe_imports_and_sections(data)
    strings = extract_ascii_strings(data, 6)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    root_id = _nid("root", filename)
    nodes.append(
        {
            "id": root_id,
            "label": filename[:40],
            "group": "root",
            "size": 14,
            "risk": 0,
            "detail": f"size={len(data)} pe={pe.get('valid')}",
        }
    )

    # sections
    for s in pe.get("sections", []):
        sid = _nid("sec", s["name"])
        risk = 0
        if s.get("entropy", 0) > 7.2:
            risk = 2
        if s["name"] in ("UPX0", "UPX1", ".aspack", ".themida"):
            risk = 3
        nodes.append(
            {
                "id": sid,
                "label": s["name"],
                "group": "section",
                "size": 6 + min(10, (s.get("raw_size") or 0) / 50000),
                "risk": risk,
                "detail": f"entropy={s.get('entropy')} vsize={s.get('vsize')}",
            }
        )
        edges.append({"source": root_id, "target": sid, "relation": "contains"})

    # imports
    for imp in pe.get("imports", []):
        dll = imp.get("dll") or "unknown.dll"
        did = _nid("dll", dll)
        nodes.append(
            {
                "id": did,
                "label": dll,
                "group": "dll",
                "size": 8,
                "risk": 1 if dll.lower() in ("wininet.dll", "winhttp.dll", "ws2_32.dll") else 0,
                "detail": f"{len(imp.get('funcs', []))} APIs",
            }
        )
        edges.append({"source": root_id, "target": did, "relation": "imports"})
        for fn in imp.get("funcs", [])[:80]:
            fid = _nid("fn", dll, fn)
            dang = fn in DANGEROUS or any(fn.startswith(d) for d in DANGEROUS)
            nodes.append(
                {
                    "id": fid,
                    "label": fn,
                    "group": "dangerous" if dang else "api",
                    "size": 10 if dang else 5,
                    "risk": 3 if dang else 0,
                    "detail": f"{dll}!{fn}",
                }
            )
            edges.append({"source": did, "target": fid, "relation": "exports"})

    import re

    # Fallback: mine API / DLL names from plain strings when IAT empty or incomplete
    existing_labels = {n["label"].lower() for n in nodes}
    str_set = set(strings)
    dll_bucket = _nid("dll", "string-imports")
    dll_added = False
    for api in sorted(DANGEROUS):
        if api in str_set or any(api.lower() in s.lower() for s in strings if len(s) <= 64):
            if api.lower() in existing_labels:
                continue
            if not dll_added:
                nodes.append(
                    {
                        "id": dll_bucket,
                        "label": "*string APIs*",
                        "group": "dll",
                        "size": 9,
                        "risk": 1,
                        "detail": "resolved from embedded strings (no full IAT)",
                    }
                )
                edges.append({"source": root_id, "target": dll_bucket, "relation": "imports"})
                dll_added = True
            fid = _nid("fn", "str", api)
            nodes.append(
                {
                    "id": fid,
                    "label": api,
                    "group": "dangerous",
                    "size": 10,
                    "risk": 3,
                    "detail": f"string hit · {api}",
                }
            )
            edges.append({"source": dll_bucket, "target": fid, "relation": "exports"})
            existing_labels.add(api.lower())

    # common DLLs as string hits
    for dll_name in ("kernel32.dll", "ntdll.dll", "advapi32.dll", "wininet.dll", "ws2_32.dll", "user32.dll"):
        if any(dll_name.lower() in s.lower() for s in strings):
            did = _nid("dll", dll_name)
            if did not in {n["id"] for n in nodes}:
                nodes.append(
                    {
                        "id": did,
                        "label": dll_name,
                        "group": "dll",
                        "size": 8,
                        "risk": 1 if "wininet" in dll_name or "ws2" in dll_name else 0,
                        "detail": "DLL string present",
                    }
                )
                edges.append({"source": root_id, "target": did, "relation": "imports"})

    # URL / IP-like / artifact strings as IOC nodes
    ioc_count = 0
    for s in strings:
        if ioc_count > 25:
            break
        if re.search(r"https?://[^\s\"']+", s) or re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", s) or s.endswith(".pdb"):
            iid = _nid("ioc", s[:80])
            nodes.append(
                {
                    "id": iid,
                    "label": s[:48],
                    "group": "ioc",
                    "size": 7,
                    "risk": 2,
                    "detail": s[:200],
                }
            )
            edges.append({"source": root_id, "target": iid, "relation": "string"})
            ioc_count += 1

    # dedupe nodes by id
    uniq = {}
    for n in nodes:
        uniq[n["id"]] = n
    nodes = list(uniq.values())

    # layout seeds (circle-ish deterministic)
    import math

    for i, n in enumerate(nodes):
        ang = (i / max(len(nodes), 1)) * math.pi * 2
        ring = {"root": 0, "section": 40, "dll": 70, "api": 100, "dangerous": 110, "ioc": 90}.get(n["group"], 80)
        n["x"] = math.cos(ang) * ring
        n["y"] = (n["risk"] - 1) * 18
        n["z"] = math.sin(ang) * ring

    dangerous_count = sum(1 for n in nodes if n["group"] == "dangerous")
    return {
        "ok": True,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "dangerous_apis": dangerous_count,
            "sections": len(pe.get("sections") or []),
            "dlls": len(pe.get("imports") or []),
        },
        "pe": {
            "valid": pe.get("valid"),
            "machine": pe.get("machine"),
            "imports": [
                {"dll": i["dll"], "count": len(i.get("funcs", []))} for i in pe.get("imports", [])
            ],
        },
    }
