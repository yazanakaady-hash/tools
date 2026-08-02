"""Brain-Link — heuristic assembly -> pseudo-C predictor for lab RE.

Not a full decompiler. Pattern-matches common x86/x64 prologues, API calls,
and control-flow idioms into readable pseudo-C with confidence scores.
"""
from __future__ import annotations

import re
from typing import Any

from .common import extract_ascii_strings, pe_imports_and_sections, sha256


API_TO_C = {
    "CreateFileA": 'HANDLE h = CreateFileA(path, GENERIC_READ, ...);',
    "CreateFileW": 'HANDLE h = CreateFileW(wpath, GENERIC_READ, ...);',
    "ReadFile": 'ReadFile(h, buf, n, &got, NULL);',
    "WriteFile": 'WriteFile(h, buf, n, &wrote, NULL);',
    "VirtualAlloc": 'void* p = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);',
    "VirtualAllocEx": 'void* p = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT, PAGE_RWX);',
    "WriteProcessMemory": 'WriteProcessMemory(hProc, remote, local, n, &w);',
    "CreateRemoteThread": 'CreateRemoteThread(hProc, NULL, 0, start, arg, 0, NULL);',
    "IsDebuggerPresent": 'if (IsDebuggerPresent()) { /* anti-debug branch */ }',
    "GetProcAddress": 'FARPROC f = GetProcAddress(hMod, name);',
    "LoadLibraryA": 'HMODULE m = LoadLibraryA(dll);',
    "LoadLibraryW": 'HMODULE m = LoadLibraryW(wdll);',
    "WinExec": 'WinExec(cmd, SW_HIDE);',
    "ShellExecuteA": 'ShellExecuteA(NULL, "open", path, args, NULL, SW_HIDE);',
    "socket": 'SOCKET s = socket(AF_INET, SOCK_STREAM, 0);',
    "connect": 'connect(s, (sockaddr*)&addr, sizeof addr);',
    "send": 'send(s, buf, len, 0);',
    "recv": 'recv(s, buf, len, 0);',
    "InternetOpenA": 'HINTERNET h = InternetOpenA(ua, ...STATTLE...);',
    "HttpOpenRequestA": 'HttpOpenRequestA(conn, "GET", path, ...);',
    "RegSetValueExA": 'RegSetValueExA(key, name, 0, REG_SZ, data, n);',
    "CreateProcessA": 'CreateProcessA(NULL, cmd, ...);',
    "Sleep": 'Sleep(ms);',
    "GetTickCount": 'DWORD t0 = GetTickCount();',
}


PROLOGUES = [
    (bytes.fromhex("554889e5"), "push rbp; mov rbp, rsp  /* x64 function frame */", 0.85),
    (bytes.fromhex("4883ec"), "sub rsp, imm8  /* x64 shadow/local alloc */", 0.7),
    (bytes.fromhex("4881ec"), "sub rsp, imm32 /* large stack frame */", 0.72),
    (bytes.fromhex("55 89 e5".replace(" ", "")), "push ebp; mov ebp, esp /* x86 frame */", 0.85),
    (bytes.fromhex("83ec"), "sub esp, imm8 /* x86 locals */", 0.65),
]


def brain_link(data: bytes, filename: str = "sample") -> dict[str, Any]:
    pe = pe_imports_and_sections(data)
    strings = extract_ascii_strings(data, 4)
    lines: list[dict[str, Any]] = []
    confidences: list[float] = []

    lines.append(
        {
            "kind": "header",
            "code": f"/* Brain-Link pseudo-C · sample={filename} · pe={pe.get('valid')} */",
            "confidence": 1.0,
        }
    )
    lines.append({"kind": "header", "code": "#include <windows.h>", "confidence": 0.9})
    lines.append({"kind": "header", "code": "", "confidence": 1.0})
    lines.append({"kind": "func", "code": "int predicted_entry(void) {", "confidence": 0.55})

    # prologues
    for sig, desc, conf in PROLOGUES:
        if sig in data[: min(len(data), 512 * 1024)]:
            lines.append({"kind": "asm", "code": f"    // {desc}", "confidence": conf})
            confidences.append(conf)

    # imports -> C
    imports_flat = []
    for imp in pe.get("imports") or []:
        for fn in imp.get("funcs") or []:
            imports_flat.append(fn)
    # string-mined APIs
    for api, snippet in API_TO_C.items():
        hit = api in imports_flat or any(api in s for s in strings)
        if hit:
            conf = 0.88 if api in imports_flat else 0.62
            lines.append({"kind": "call", "code": f"    {snippet}", "confidence": conf, "api": api})
            confidences.append(conf)

    # string literals as likely args
    interesting = [
        s for s in strings
        if re.search(r"https?://|\.dll$|\.exe$|\\\\|cmd\.exe|powershell|%s|SOFTWARE\\\\", s, re.I)
    ][:18]
    for s in interesting:
        safe = s.replace("\\", "\\\\").replace('"', '\\"')[:80]
        lines.append(
            {
                "kind": "string",
                "code": f'    const char* s_{abs(hash(s))%10000} = "{safe}";',
                "confidence": 0.74,
            }
        )
        confidences.append(0.74)

    # control flow guess
    if b"\x74" in data or b"\x0f\x84" in data:
        lines.append(
            {
                "kind": "flow",
                "code": "    if (condition_from_jcc) {\n        /* taken branch — see Ant Colony weakest jump */\n    }",
                "confidence": 0.48,
            }
        )
        confidences.append(0.48)

    if any(x in imports_flat or any(x in s for s in strings) for x in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent")):
        lines.append(
            {
                "kind": "flow",
                "code": "    if (IsDebuggerPresent()) return 0xDEAD;  /* anti-analysis egress */",
                "confidence": 0.8,
            }
        )

    lines.append({"kind": "func", "code": "    return 0;\n}", "confidence": 0.5})

    # Ollybaster / packer noise hint
    obfuscated = any(
        k in data
        for k in (b"UPX", b"Themida", b"VMProtect", b"Obsidium", b".aspack", b"Olly")
    )
    avg = round(sum(confidences) / max(len(confidences), 1) * 100, 1) if confidences else 35.0
    # Marketing 98.7 is fantasy — we publish honest ensemble confidence
    if obfuscated:
        avg = round(avg * 0.55, 1)

    code_text = "\n".join(l["code"] for l in lines)

    return {
        "ok": True,
        "module": "Brain-Link",
        "filename": filename,
        "pseudo_c": code_text,
        "lines": lines,
        "confidence_pct": avg,
        "confidence_note": "Heuristic ensemble — not a verified 98.7% decompile.",
        "obfuscation_suspected": obfuscated,
        "api_recoveries": sum(1 for l in lines if l.get("kind") == "call"),
        "sample_sha256": sha256(data),
        "summary": f"Brain-Link: conf={avg}% · APIs={sum(1 for l in lines if l.get('kind')=='call')} · obfuscated={obfuscated}",
    }
