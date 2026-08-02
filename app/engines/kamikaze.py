"""Kamikaze Engine — detection-response fragmentation plan (lab).

When anti-analysis markers fire, emits a micro-process reassembly strategy
map. Does not actually shatter the host OS; produces a forensic playbook and
self-check checksum shards.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .anti_analysis import scan_anti_analysis
from .common import sha256


def _shards(data: bytes, n: int = 500) -> list[dict[str, Any]]:
    if not data:
        return []
    n = max(16, min(n, 500))
    chunk = max(1, len(data) // n)
    out = []
    for i in range(n):
        start = i * chunk
        piece = data[start : start + chunk] if start < len(data) else data[-4:]
        if not piece:
            piece = bytes([i & 0xFF])
        h = hashlib.md5(piece + bytes([i & 0xFF])).hexdigest()[:10]
        out.append(
            {
                "shard": i,
                "core_affinity": i % max(1, _cpu_count()),
                "md5_10": h,
                "size": len(piece),
            }
        )
    return out


def _cpu_count() -> int:
    try:
        import os

        return os.cpu_count() or 4
    except Exception:
        return 4


def kamikaze_engine(data: bytes, filename: str = "sample", micro_count: int = 500) -> dict[str, Any]:
    anti = scan_anti_analysis(data)
    risk = int(anti.get("risk_score") or 0)
    detected = risk >= 35 or (anti.get("count") or 0) >= 3

    shards = _shards(data, micro_count) if detected else _shards(data, min(64, micro_count))
    cores = sorted({s["core_affinity"] for s in shards})

    reassembly = {
        "trigger": "anti_analysis_risk" if detected else "standby",
        "micro_processes": len(shards),
        "cpu_cores_mapped": cores,
        "rendezvous": "shared memory ring · lab abstract",
        "reassembly_hash": sha256(b"".join(s["md5_10"].encode() for s in shards[:64]))[:24],
        "blind_defender": detected,
    }

    playbook = [
        "Freeze inspector-facing handles (lab checklist)",
        f"Fragment analysis state into {len(shards)} checksum shards",
        f"Pin shards across cores {cores[:8]}{'…' if len(cores) > 8 else ''}",
        "Reassemble on alternate core after detector noise window",
        "Resume RE workflow with Ghost Spectrum cache plan",
    ]
    if not detected:
        playbook.insert(0, "No strong detection — Kamikaze stays ARM standby")

    return {
        "ok": True,
        "module": "Kamikaze Engine",
        "filename": filename,
        "armed": detected,
        "risk_score": risk,
        "anti_hits": anti.get("count"),
        "reassembly": reassembly,
        "shards_preview": shards[:12],
        "shard_count": len(shards),
        "playbook": playbook,
        "glow": "blood" if detected else "cyan",
        "summary": (
            f"Kamikaze: {'ARMED' if detected else 'standby'} · risk={risk} · "
            f"shards={len(shards)} · cores={len(cores)}"
        ),
    }
