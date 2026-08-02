"""Blackhole Engineer — ETW forensic log analysis + pre-deletion playbook.

Lab-mode analysis: enumerates Windows ETW providers, maps Process/Thread/DLL
trace events, and emits a forensic-blindness plan. Does NOT modify kernel
ETW buffers — produces a tactical report.
"""
from __future__ import annotations

import re
import subprocess
from typing import Any

from .common import sha256


ETW_PROVIDERS = [
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-Kernel-Thread",
    "Microsoft-Windows-Kernel-File",
    "Microsoft-Windows-Kernel-Registry",
    "Microsoft-Windows-Kernel-Network",
    "Microsoft-Windows-DotNETRuntime",
    "Microsoft-Windows-PowerShell",
    "Microsoft-Windows-Sysmon",
    "Microsoft-Windows-Security-Auditing",
]


def _list_etw_sessions() -> list[str]:
    try:
        out = subprocess.check_output(
            ["logman", "query", "-ets"], shell=True, text=True, errors="ignore", timeout=5
        )
        return [line.strip() for line in out.splitlines() if line.strip()][:40]
    except Exception:
        return []


def _forensic_sinks() -> list[dict[str, Any]]:
    sinks = []
    # Check common forensic artifacts
    paths = [
        "%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx",
        "%SystemRoot%\\System32\\winevt\\Logs\\System.evtx",
        "%SystemRoot%\\System32\\winevt\\Logs\\Application.evtx",
        "%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
    ]
    import os
    for p in paths:
        expanded = os.path.expandvars(p)
        import glob as g
        matches = g.glob(expanded)
        for m in matches:
            try:
                size = os.path.getsize(m)
                sinks.append({"path": m, "size": size, "size_mb": round(size / 1024 / 1024, 2)})
            except Exception:
                sinks.append({"path": m, "size": 0, "size_mb": 0})
    return sinks


def blackhole_engineer(data: bytes, filename: str = "sample") -> dict[str, Any]:
    sessions = _list_etw_sessions()
    sinks = _forensic_sinks()

    # Build tactical blindness playbook
    playbook = [
        "=== Blackhole Engineer Playbook (lab report) ===",
        "",
        "[Phase 1 — ETW Recon]",
        f"Visible ETW sessions: {len(sessions)}",
        "Target providers: " + ", ".join(ETW_PROVIDERS[:6]) + " ...",
        "",
        "[Phase 2 — Buffer Pre-Deletion (lab abstract)]",
        "• Map EtwEventWrite / NtTraceEvent IAT entries",
        "• Hook EtwEventWriteFull → return STATUS_SUCCESS (ring3 lab)",
        "• Patch EtwEventWrite at call site → NOP sled (static PE)",
        "• Clear EtwRegistration->ProviderHandle in .data",
        "",
        "[Phase 3 — Forensic Sink Blindness]",
    ]
    for s in sinks:
        playbook.append(f"• {s['path']} ({s['size_mb']} MB)")
    playbook += [
        "",
        "[Phase 4 — Verification]",
        "• logman query -ets → expect 0 sessions with target providers",
        "• wevtutil qe Security /c:1 /rd:true → expect 0 recent events",
        "",
        "NOTE: Lab-only tactical report. No kernel buffer modification performed.",
    ]

    impacted_sinks = sum(1 for s in sinks if s.get("size", 0) > 0)

    return {
        "ok": True,
        "module": "Blackhole Engineer",
        "filename": filename,
        "etw_sessions_visible": len(sessions),
        "sessions": sessions[:15],
        "target_providers": ETW_PROVIDERS,
        "forensic_sinks": sinks,
        "impacted_sinks": impacted_sinks,
        "playbook": playbook,
        "blindness_effectiveness": min(99, 40 + impacted_sinks * 15 + min(len(sessions), 10) * 3),
        "sample_sha256": sha256(data),
        "summary": (
            f"Blackhole Engineer: {len(sessions)} ETW sessions · "
            f"{impacted_sinks} forensic sinks · blindness={min(99, 40 + impacted_sinks * 15 + min(len(sessions), 10) * 3)}%"
        ),
    }
