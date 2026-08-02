"""Compiler Flipper — JIT AST manipulation analysis for Python/JS/.NET.

Scans bytecode/IL for eval/exec patterns and emits a JIT-hijack strategy
report. Works on .pyc, .js, and .NET IL artifacts.
"""
from __future__ import annotations

import dis as _dis
import marshal
import re
import struct
import sys
from typing import Any

from .common import extract_ascii_strings, sha256


PY_JIT_SINKS = {"eval", "exec", "compile", "__import__", "open", "os.system", "subprocess", "pickle.loads"}
JS_JIT_SINKS = {"eval", "Function", "setTimeout", "setInterval", "import(", "WebAssembly.instantiate"}
DOTNET_PATTERNS = [
    b"System.Reflection.Emit",
    b"System.CodeDom",
    b"Microsoft.CSharp",
    b"System.Reflection.Assembly",
    b"MethodInfo",
    b"Invoke",
]


def _analyze_pyc(data: bytes) -> dict[str, Any]:
    """Decompile .pyc bytecode to find JIT-eval sinks."""
    sinks_found = []
    try:
        if data[:4] == b"\xee\x0c\x0d\n" or data[:4] in (
            b"\x55\x0d\x0d\n", b"\x42\x0d\x0d\n", b"\x0d\x0d\x0d\n",
        ):
            # skip magic + timestamp
            code = marshal.loads(data[16:]) if len(data) > 16 else None
            if code is None:
                code = marshal.loads(data[12:])
            if hasattr(code, "co_code"):
                bytecode = code.co_code
                consts = code.co_consts
                names = code.co_names
                for instr in _dis.get_instructions(code):
                    if instr.opname == "LOAD_GLOBAL" and instr.argval in PY_JIT_SINKS:
                        sinks_found.append(
                            {
                                "sink": instr.argval,
                                "offset": instr.offset,
                                "opname": instr.opname,
                                "context": f"line ~{instr.positions.lineno if instr.positions else '?'}",
                            }
                        )
                    elif instr.opname == "LOAD_NAME" and instr.argval in PY_JIT_SINKS:
                        sinks_found.append(
                            {
                                "sink": instr.argval,
                                "offset": instr.offset,
                                "opname": instr.opname,
                                "context": "local scope",
                            }
                        )
    except Exception:
        pass
    return {"format": "pyc", "sinks": sinks_found, "sink_count": len(sinks_found)}


def _analyze_js(data: bytes) -> dict[str, Any]:
    sinks = []
    text = data.decode("utf-8", errors="ignore")
    for sink in JS_JIT_SINKS:
        for m in re.finditer(re.escape(sink), text):
            ctx = text[max(0, m.start() - 30) : m.end() + 30]
            sinks.append(
                {
                    "sink": sink,
                    "offset": m.start(),
                    "context": ctx.strip()[:80],
                }
            )
    return {"format": "js", "sinks": sinks, "sink_count": len(sinks)}


def _analyze_dotnet(data: bytes) -> dict[str, Any]:
    pe = __import__("analyzers.common", fromlist=["pe_imports_and_sections"]).pe_imports_and_sections(data)
    strings = extract_ascii_strings(data, 4)
    sinks = []
    for pat in DOTNET_PATTERNS:
        if pat in data:
            sinks.append({"sink": pat.decode("latin-1"), "offset": data.find(pat), "context": "binary signature"})
        for s in strings:
            if pat.decode("latin-1").lower() in s.lower():
                sinks.append({"sink": pat.decode("latin-1"), "offset": 0, "context": s[:80]})
    return {"format": "dotnet", "sinks": sinks, "sink_count": len(sinks)}


def compiler_flipper(data: bytes, filename: str = "sample") -> dict[str, Any]:
    name_lower = filename.lower()
    if name_lower.endswith(".pyc") or data[:4] in (b"\x55\x0d\x0d\n", b"\x42\x0d\x0d\n", b"\xee\x0c\x0d\n"):
        analysis = _analyze_pyc(data)
    elif name_lower.endswith(".js") or b"function" in data[:512] or b"const " in data[:512]:
        analysis = _analyze_js(data)
    elif name_lower.endswith((".dll", ".exe")) and (b"BSJB" in data or b"System." in data):
        analysis = _analyze_dotnet(data)
    else:
        # Try all
        analysis = _analyze_js(data)
        if not analysis["sinks"]:
            try:
                analysis = _analyze_pyc(data)
            except Exception:
                analysis = _analyze_dotnet(data)

    sinks = analysis.get("sinks", [])
    strategy = []
    if sinks:
        strategy = [
            "=== Compiler Flipper Hijack Strategy ===",
            "",
            f"[Target Runtime] {analysis.get('format', 'unknown')}",
            f"[Sinks Found] {len(sinks)}",
            "",
            "[JIT Hijack Points]",
        ]
        for s in sinks[:10]:
            strategy.append(f"  • {s['sink']} @{s.get('offset', '?')} — {s.get('context', '')[:60]}")
        strategy += [
            "",
            "[AST Injection Plan]",
            "1. Hook JIT compiler's AST visitor (e.g., Python's ast.NodeTransformer)",
            "2. Intercept Call nodes matching target sinks",
            "3. Insert payload wrapper: `payload_wrapper(original_call(args))`",
            "4. Recompile modified AST → bytecode without touching source",
            "",
            "[Detection Bypass]",
            "- No source modification → static scanners see clean code",
            "- Bytecode differs only at JIT time → runtime-only visibility",
            "- Use __code__ replacement for pure Python runtime hijack",
        ]
    else:
        strategy = ["No JIT-eval sinks detected in analyzed format."]

    return {
        "ok": True,
        "module": "Compiler Flipper",
        "filename": filename,
        "runtime_format": analysis.get("format", "unknown"),
        "sinks": sinks,
        "sink_count": len(sinks),
        "strategy": strategy,
        "exploitability": "high" if len(sinks) >= 2 else "medium" if sinks else "low",
        "disclaimer": "JIT manipulation analysis — no runtime hijack deployed in lab.",
        "summary": f"Compiler Flipper: {len(sinks)} JIT sinks in {analysis.get('format', '?')} · exploitability={('high' if len(sinks) >= 2 else 'medium' if sinks else 'low')}",
    }
