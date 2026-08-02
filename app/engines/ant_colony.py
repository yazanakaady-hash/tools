"""Ant Colony — concurrent CFG branch mutational fuzzer (lab scale).

Spawns worker simulation that hammers conditional-jump sites mined from
x86/x64 code sections and reports weakest branch within a tight budget.
"""
from __future__ import annotations

import hashlib
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .common import pe_imports_and_sections, sha256


# common short conditional jumps / test-jcc primers
JCC_SIGS = [
    (b"\x74", "JZ/JE rel8"),
    (b"\x75", "JNZ/JNE rel8"),
    (b"\x7c", "JL rel8"),
    (b"\x7d", "JGE rel8"),
    (b"\x7e", "JLE rel8"),
    (b"\x7f", "JG rel8"),
    (b"\x72", "JB/JC rel8"),
    (b"\x73", "JAE/JNC rel8"),
    (b"\x0f\x84", "JZ/JE rel32"),
    (b"\x0f\x85", "JNZ rel32"),
    (b"\x0f\x8c", "JL rel32"),
    (b"\x0f\x8d", "JGE rel32"),
    (b"\x0f\x8e", "JLE rel32"),
    (b"\x0f\x8f", "JG rel32"),
]


def _mine_branches(data: bytes, limit: int = 400) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    # Focus on PE .text if available
    pe = pe_imports_and_sections(data)
    windows: list[tuple[int, bytes]] = []
    if pe.get("valid") and pe.get("sections"):
        for s in pe["sections"]:
            name = (s.get("name") or "").lower()
            if "text" in name or name in (".code", "code"):
                # pe parser may not give raw slice — scan whole blob keyed by name
                windows.append((0, data))
                break
    if not windows:
        windows.append((0, data[: min(len(data), 2 * 1024 * 1024)]))

    for base, blob in windows:
        for sig, label in JCC_SIGS:
            start = 0
            while len(found) < limit:
                i = blob.find(sig, start)
                if i < 0:
                    break
                # skip obvious string noise (ASCII high density nearby)
                ctx = blob[max(0, i - 2) : i + 8]
                if sum(32 <= b < 127 for b in ctx) > 6 and sig[0] >= 0x20:
                    start = i + 1
                    continue
                found.append(
                    {
                        "offset": base + i,
                        "op": label,
                        "bytes": blob[i : i + min(6, len(blob) - i)].hex(),
                    }
                )
                start = i + 1
    return found[:limit]


def _fuzz_branch(branch: dict[str, Any], ants: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed ^ branch["offset"])
    # Simulated coverage: flip path preference; weaker branches have high.
    # entropy of local encoding (random-ish displacement -> weaker)
    disp_entropy = abs(hash(branch["bytes"])) % 1000 / 1000.0
    crush = 0.0
    crashes = 0
    new_edges = 0
    for _ in range(ants):
        # path coin flip + input mutant
        path = rng.random()
        mutant = rng.getrandbits(32)
        crush_score = (1.0 - abs(path - 0.5) * 2) * (0.4 + disp_entropy * 0.6)
        crush = max(crush, crush_score)
        if mutant & 0xFF == branch["offset"] & 0xFF:
            crashes += 1
        if path > 0.92:
            new_edges += 1
    weakness = round(min(99.9, crush * 100 + crashes * 3 + new_edges * 0.5), 2)
    return {
        **branch,
        "weakness": weakness,
        "crashes_sim": crashes,
        "new_edges_sim": new_edges,
        "ants_local": ants,
    }


def ant_colony(
    data: bytes,
    filename: str = "sample",
    virtual_ants: int = 10_000,
    budget_ms: int = 300,
) -> dict[str, Any]:
    t0 = time.perf_counter()
    branches = _mine_branches(data)
    if not branches:
        # synthesize pseudo-CFG nodes from entropy windows so UI never empty
        step = max(64, len(data) // 32) if data else 64
        for i in range(0, min(len(data), step * 24), step):
            branches.append(
                {
                    "offset": i,
                    "op": "SYNTH-EDGE",
                    "bytes": data[i : i + 4].hex() if data else "00",
                }
            )

    n_br = max(len(branches), 1)
    ants_each = max(1, virtual_ants // n_br)
    seed = int(sha256(data)[:8], 16) if data else 1

    results: list[dict[str, Any]] = []
    workers = min(32, n_br)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [
            pool.submit(_fuzz_branch, b, ants_each, seed + i)
            for i, b in enumerate(branches)
        ]
        for fut in as_completed(futs):
            results.append(fut.result())
            elapsed_ms = (time.perf_counter() - t0) * 1000
            if elapsed_ms > budget_ms * 3:
                break

    results.sort(key=lambda r: r["weakness"], reverse=True)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    weakest = results[0] if results else None

    return {
        "ok": True,
        "module": "Ant Colony",
        "filename": filename,
        "virtual_ants": virtual_ants,
        "budget_ms": budget_ms,
        "elapsed_ms": elapsed_ms,
        "branches_mined": len(branches),
        "branches_fuzzed": len(results),
        "weakest_jump": weakest,
        "top_weak": results[:15],
        "coverage_hint": {
            "edge_hits_sim": sum(r["new_edges_sim"] for r in results),
            "crash_sites_sim": sum(1 for r in results if r["crashes_sim"] > 0),
        },
        "hive_hash": hashlib.sha256((filename + str(weakest)).encode()).hexdigest()[:16],
        "summary": (
            f"Ant Colony: {virtual_ants} ants · {len(results)} branches · "
            f"weakest @0x{(weakest or {}).get('offset', 0):x} weakness={(weakest or {}).get('weakness')} "
            f"in {elapsed_ms}ms"
        ),
    }
