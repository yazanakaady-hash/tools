"""Silent Plague — UEFI/SMRAM persistence analysis + lab playbook.

Analyzes PE for firmware-persistence indicators and emits a bootkit-style
persistence strategy report (lab-only). No firmware modification deployed.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any

from .common import extract_ascii_strings, pe_imports_and_sections, sha256


UEFI_ARTIFACTS = [
    (b"_SC_", "UEFI system configuration"),
    (b"EFI_", "EFI entry point prefix"),
    (b".efi", "EFI extension"),
    (b"uefi:", "UEFI string"),
    (b"\\EFI\\", "EFI path"),
    (b"SMRAM", "System Management RAM reference"),
    (b"SMM", "System Management Mode"),
    (b"ACPI", "ACPI table reference"),
    (b"DSDT", "Differentiated System Description Table"),
    (b"FACP", "Fixed ACPI Description Table"),
    (b"UEFI", "UEFI explicit"),
    (b"bootmgfw", "Windows Boot Manager"),
    (b"winload", "Windows OS Loader"),
    (b"DXE", "Driver Execution Environment"),
]


def _find_uefi_artifacts(data: bytes) -> list[dict[str, Any]]:
    hits = []
    for sig, label in UEFI_ARTIFACTS:
        off = 0
        count = 0
        while count < 6:
            i = data.find(sig, off)
            if i < 0:
                break
            hits.append({"offset": i, "sig": sig.decode("latin-1", errors="ignore"), "label": label})
            count += 1
            off = i + 1
    return hits


def _build_persistence_playbook(hits: list[dict[str, Any]], pe: dict[str, Any]) -> list[str]:
    playbook = [
        "=== Silent Plague Persistence Strategy ===",
        "",
        "[Firmware Artifacts Found]",
        f"  {len(hits)} indicators in binary",
    ]
    for h in hits[:12]:
        playbook.append(f"  • 0x{h['offset']:x} — {h['label']}")

    playbook += [
        "",
        "[Phase 1 — UEFI Boot Chain Mapping]",
        "  Map DXE dispatch order via UEFI shell memmap",
        "  Identify SMRAM region: SMRR MSR 0x1F2 reads",
        "",
        "[Phase 2 — SMRAM Persistence (lab abstract)]",
        "  Locate SMM entry point in SMRAM (0x30000-0x3FFFF region)",
        "  Craft SMM driver with trampoline to SMRAM resident payload",
        "  Install via System Management Interrupt (SMI) handler SW SMI port 0xB2",
        "  SMRAM payload: re-injection stub that hooks OS loader handoff",
        "",
        "[Phase 3 — ACPI Table Hijack]",
        "  Overlay DSDT/SSDT with Method that triggers at _INI (init)",
        "  ACPI _INI runs before OS kernel loads → early execution",
        "  Payload re-injects into kernel .data before PatchGuard init",
        "",
        "[Phase 4 — Verification]",
        "  Reboot → check UEFI DXE dispatch log for SMM driver",
        "  Live RAM scan for SMRAM resident bytes (requires chipsec)",
        "  ACPI table dump: acpidump -b && iasl -d dsdt.dat",
        "",
        "[Constraints — Lab Only]",
        "  No firmware modification deployed",
        "  Requires hardware SPI programmer for real SMRAM write",
        "  Chipsec/lspci validation only with authorized hardware",
    ]
    return playbook


def silent_plague(data: bytes, filename: str = "sample") -> dict[str, Any]:
    pe = pe_imports_and_sections(data)
    artifacts = _find_uefi_artifacts(data)
    strings = extract_ascii_strings(data, 4)

    firmware_strings = [
        s for s in strings
        if any(
            k in s.lower()
            for k in ("uefi", "smram", "acpi", "dsdt", "dxe", "pei", "smm", "tcg", "tpm", "spi")
        )
    ][:20]

    playbook = _build_persistence_playbook(artifacts, pe)
    persistence_score = min(98, len(artifacts) * 5 + len(firmware_strings) * 3 + (25 if pe.get("valid") else 0))

    return {
        "ok": True,
        "module": "Silent Plague",
        "filename": filename,
        "uefi_artifacts": artifacts,
        "artifact_count": len(artifacts),
        "firmware_strings": firmware_strings,
        "persistence_score": persistence_score,
        "persistence_playbook": playbook,
        "pe": {"valid": pe.get("valid"), "machine": pe.get("machine")},
        "disclaimer": "UEFI/SMRAM persistence analysis — no firmware modification deployed in lab.",
        "summary": (
            f"Silent Plague: {len(artifacts)} UEFI artifacts · "
            f"persistence={persistence_score}% · {'bootkit-style plan ready' if persistence_score > 30 else 'low UEFI surface'}"
        ),
    }
