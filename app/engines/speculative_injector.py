"""Speculative Injector — Spectre-v2 style branch prediction analysis.

Maps conditional branch sites and simulates speculative execution paths.
Emits a branch-confusion matrix + training plan. Lab analysis only.
"""
from __future__ import annotations

import struct
from typing import Any

from .common import pe_imports_and_sections, sha256


# Branch target injection (BTI) / Spectre-v2 relevant patterns
SPECTRE_GADGETS = [
    (bytes.fromhex("0f84"), "JZ rel32 — train not-taken, speculatively execute fallthrough"),
    (bytes.fromhex("0f85"), "JNZ rel32 — train taken, leak from mispredict path"),
    (bytes.fromhex("488b"), "MOV R64, [mem] — potential load gadget"),
    (bytes.fromhex("488b04"), "SIB load — array access pattern"),
    (bytes.fromhex("0fb6"), "MOVZX byte — byte-granularity leak"),
    (bytes.fromhex("c4e2"), "VEX prefix — AVX speculative window"),
]


def _find_gadgets(data: bytes, limit: int = 200) -> list[dict[str, Any]]:
    gadgets = []
    for sig, desc in SPECTRE_GADGETS:
        start = 0
        while len(gadgets) < limit:
            i = data.find(sig, start)
            if i < 0:
                break
            ctx = data[max(0, i - 8) : i + 16]
            secret_proximity = any(
                b in ctx
                for b in (
                    b"pass", b"key", b"aes", b"rc4", b"token", b"cookie",
                    b"auth", b"cred", b"secret",
                )
            )
            gadgets.append(
                {
                    "offset": i,
                    "sig": sig.hex(),
                    "desc": desc,
                    "context": ctx.hex(),
                    "secret_proximity": secret_proximity,
                    "trainable": sig[0] in (0x0F,),
                }
            )
            start = i + 1
    return gadgets[:limit]


def speculative_injector(data: bytes, filename: str = "sample") -> dict[str, Any]:
    gadgets = _find_gadgets(data)
    trainable = [g for g in gadgets if g["trainable"]]
    secret_near = [g for g in gadgets if g["secret_proximity"]]

    # Build branch confusion matrix (simplified)
    confusion = {
        "trainable_branches": len(trainable),
        "secret_adjacent": len(secret_near),
        "total_gadgets": len(gadgets),
        "bti_candidates": len([g for g in trainable if "JZ" in g["desc"] or "JNZ" in g["desc"]]),
    }

    # Training plan
    training_plan = [
        "=== Speculative Injector Plan (lab) ===",
        "",
        "[Step 1 — Alias Mapping]",
        "Map virtual address space for cross-process BHB collision",
        "",
        "[Step 2 — Branch Training]",
        f"Train {confusion['bti_candidates']} conditional branches to predictable direction",
        "Use same virtual offset in attacker process for BHB congruence",
        "",
        "[Step 3 — Gadget Selection]",
        f"Top {min(5, len(secret_near))} secret-proximate gadgets identified",
        "Prioritize MOVZX byte-grained gadgets for byte-at-a-time leak",
        "",
        "[Step 4 — Covert Channel]",
        "Flush+Reload or Prime+Probe on shared cache lines",
        "Measure access time deltas to reconstruct secret",
        "",
        "[Constraints]",
        "Lab analysis only — no cross-process BTI deployed",
        "Requires shared CPU core scheduling for BHB collision",
    ]

    pe = pe_imports_and_sections(data)
    injectability = min(95, confusion["bti_candidates"] * 3 + confusion["secret_adjacent"] * 8)

    return {
        "ok": True,
        "module": "Speculative Injector",
        "filename": filename,
        "gadgets_total": len(gadgets),
        "trainable_branches": confusion["trainable_branches"],
        "secret_adjacent_gadgets": confusion["secret_adjacent"],
        "bti_candidates": confusion["bti_candidates"],
        "injectability_score": injectability,
        "top_gadgets": gadgets[:12],
        "training_plan": training_plan,
        "pe": {"valid": pe.get("valid"), "sections": len(pe.get("sections") or [])},
        "disclaimer": "Spectre-v2 style analysis — no speculative execution exploit deployed.",
        "summary": (
            f"Speculative Injector: {len(gadgets)} gadgets · "
            f"{confusion['bti_candidates']} BTI candidates · injectability={injectability}"
        ),
    }
