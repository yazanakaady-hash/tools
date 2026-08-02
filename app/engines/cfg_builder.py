"""cfg_builder — خريطة تدفق التحكم (Control Flow Graph Builder).

يبني تمثيلاً لخريطة تدفق التحكم (CFG) للكود المنفَّذ عبر ماسح opcode
استدلالي لمعمارية x86/x64: بلوكات أساسية، حواف قفز/استدعاء/سقوط حر،
وظائف محتملة (نقاط دخول الاستدعاءات)، مسارات خطرة تلامس دوال النظام،
وتصدير DOT جاهز للرسم عبر Graphviz.

المرجع: منهجية تحليل البرمجيات الخبيثة ثابتة —
  - E8/E9 rel32 → call/jmp مباشر بمسافة 32-بت (الهدف = الموضع + 5 + rel)
  - EB rel8 → jmp قصير (الهدف = الموضع + 2 + rel)
  - 0x70–0x7F → jcc قصير (الهدف = الموضع + 2 + rel)
  - 0F 80–8F → jcc بعيد (الهدف = الموضع + 6 + rel)
  - FF /2 و FF /4 → jmp/call غير مباشر عبر ModRM
  - C3/C2/CB/CA → ret · CC → int3 · E0–E2 → loop · CD 2D → int 2Dh
"""
from __future__ import annotations

import struct
from collections import deque, defaultdict
from typing import Any

from .common import extract_ascii_strings

_MAX_NODES = 4096
_SINK_STRINGS = (
    b"socket", b"connect", b"send", b"recv", b"bind", b"listen",
    b"CreateProcess", b"WinExec", b"ShellExecute", b"RegSetValue",
    b"RegCreateKey", b"LoadLibrary", b"WriteProcessMemory", b"CreateRemoteThread",
    b"VirtualAlloc", b"CryptEncrypt", b"GetTempPath", b"URLDownloadToFile",
    b"DeleteFile", b"MoveFile", b"SetWindowsHook", b"OpenProcess",
)


def _le16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0] if o + 2 <= len(d) else 0


def _le32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0] if o + 4 <= len(d) else 0


def _pe_layout(d: bytes) -> dict[str, Any]:
    """استخراج عنوان الدخول من PE (32/64-بت) مع خريطة RVA→ملف."""
    if len(d) < 0x40 or d[:2] != b"MZ":
        return {"kind": None}
    e_lfanew = _le32(d, 0x3C)
    if e_lfanew + 24 > len(d) or d[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"kind": None}
    coff = e_lfanew + 4
    nsec = _le16(d, coff + 2)
    opt_size = _le16(d, coff + 16)
    opt = coff + 20
    if opt + opt_size > len(d):
        return {"kind": None}
    magic = _le16(d, opt)
    entry_rva = _le32(d, opt + 16)
    sections = []
    sec = opt + opt_size
    for _ in range(nsec):
        if sec + 40 > len(d):
            break
        name = d[sec:sec + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize = _le32(d, sec + 8)
        vaddr = _le32(d, sec + 12)
        rsize = _le32(d, sec + 16)
        roff = _le32(d, sec + 20)
        sections.append({"name": name, "va": vaddr, "vs": max(vsize, rsize), "raw": roff})
        sec += 40
    return {
        "kind": "pe",
        "pe32_plus": magic == 0x20B,
        "entry_rva": entry_rva,
        "sections": sections,
    }


def _rva_to_off(layout: dict[str, Any], rva: int) -> int:
    for s in layout.get("sections", []):
        if s["va"] <= rva < s["va"] + s["vs"]:
            return s["raw"] + (rva - s["va"])
    return rva


def _elf_entry(d: bytes) -> dict[str, Any]:
    if len(d) < 0x40 or d[:4] != b"\x7fELF":
        return {"kind": None}
    is64 = d[4] == 2
    fmt = "Q" if is64 else "I"
    entry = struct.unpack_from(f"<{fmt}", d, 0x18)[0]
    return {"kind": "elf", "entry": entry & 0xFFFFFFFF if entry < 0xFFFFFFFF else entry}


def _modrm_target(d: bytes, pos: int, ins_len: int) -> tuple[int, int]:
    """قراءة هدف ModRM (مباشر أو عبر جدول البايت التالي) — استدلالي."""
    if pos + 2 > len(d):
        return pos + ins_len, ins_len
    modrm = d[pos + 1]
    mod = modrm >> 6
    rm = modrm & 0x07
    disp = 0
    extra = 0
    if mod == 0 and rm == 5:
        disp = struct.unpack_from("<i", d, pos + 2)[0] if pos + 6 <= len(d) else 0
        extra = 4
    elif mod == 1:
        disp = d[pos + 2] if pos + 3 <= len(d) else 0
        extra = 1
    elif mod == 2:
        disp = struct.unpack_from("<i", d, pos + 2)[0] if pos + 6 <= len(d) else 0
        extra = 4
    return (pos + ins_len + 1 + extra) & 0xFFFFFFFF, (pos + ins_len + 1 + extra) - pos


def _scan_branches(data: bytes, start: int, end: int, layout: dict[str, Any]) -> list[dict[str, Any]]:
    """ماسح تعليمات استدلالي يعيد قائمة الفروع (نوع/هدف/سقوط حر)."""
    branches: list[dict[str, Any]] = []
    i = start
    n = len(data)
    while i < min(end, n - 1):
        op = data[i]
        consumed = True
        ins_len = 1
        kind = None
        tgt = None
        fall = None

        if op == 0xE8 or op == 0xE9:  # call/jmp rel32
            if i + 5 <= n:
                rel = struct.unpack_from("<i", data, i + 1)[0]
                tgt = (i + 5 + rel) & 0xFFFFFFFF
                ins_len = 5
                kind = "call" if op == 0xE8 else "jmp"
                fall = i + 5 if op == 0xE8 else None
        elif op == 0xEB:  # jmp rel8
            rel = struct.unpack_from("<b", data, i + 1)[0] if i + 2 <= n else 0
            tgt = (i + 2 + rel) & 0xFFFFFFFF
            ins_len = 2
            kind = "jmp"
        elif 0x70 <= op <= 0x7F:  # jcc rel8
            rel = struct.unpack_from("<b", data, i + 1)[0] if i + 2 <= n else 0
            tgt = (i + 2 + rel) & 0xFFFFFFFF
            ins_len = 2
            kind = f"jcc{op - 0x70:02x}"
            fall = i + 2
        elif op == 0x0F and i + 1 < n and 0x80 <= data[i + 1] <= 0x8F:  # jcc rel32
            if i + 6 <= n:
                rel = struct.unpack_from("<i", data, i + 2)[0]
                tgt = (i + 6 + rel) & 0xFFFFFFFF
                ins_len = 6
                kind = f"jcc{data[i + 1] - 0x80:02x}"
                fall = i + 6
        elif op == 0xFF and i + 1 < n:  # jmp/call r/m
            reg = (data[i + 1] >> 3) & 0x07
            if reg in (2, 4):
                tgt, ext = _modrm_target(data, i, ins_len)
                ins_len += ext
                kind = "call" if reg == 2 else "jmp"
                fall = i + ins_len if reg == 2 else None
        elif op in (0xC3, 0xCB):  # ret (near/far)
            kind = "ret"
            ins_len = 1
        elif op in (0xC2, 0xCA):  # ret imm16
            kind = "ret"
            ins_len = 3
        elif op == 0xCC:  # int3
            kind = "int3"
            ins_len = 1
        elif 0xE0 <= op <= 0xE2:  # loop rel8
            rel = struct.unpack_from("<b", data, i + 1)[0] if i + 2 <= n else 0
            tgt = (i + 2 + rel) & 0xFFFFFFFF
            ins_len = 2
            kind = "loop"
            fall = i + 2

        if kind:
            branches.append({
                "pos": i, "kind": kind, "len": ins_len,
                "target": tgt, "fall": fall,
            })
            i += ins_len
            continue

        # تقدّم تقريبي عبر بادئات عامة شائعة لتقليل الانحراف
        if op in (0x66, 0x67, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65):
            ins_len = 2 if i + 1 < n and data[i + 1] in (0x0F, 0xFF) else (1 if i + 1 >= n else 2)
        elif op == 0x0F:
            ins_len = 3 if i + 1 < n and data[i + 1] in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                                          0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F) else 2
        elif op == 0xCD:
            ins_len = 2
        i += ins_len
    return branches


def build_cfg(data: bytes, filename: str = "sample.bin", max_nodes: int = _MAX_NODES) -> dict[str, Any]:
    """بناء خريطة تدفق التحكم + تصدير DOT.

    Parameters
    ----------
    data : bytes — بايتات الملف.
    filename : str — اسم الملف للعرض.
    max_nodes : int — سقف عدد البلوكات الناتجة.

    Returns
    -------
    dict — يحتوي nodes/edges/functions/stats/dot/threat_index إلخ.
    """
    if not data:
        return {"ok": False, "error": "empty file"}
    if len(data) > 64 * 1024 * 1024:
        return {"ok": False, "error": "file too large (max 64MB)"}

    layout = _pe_layout(data)
    if layout["kind"] is None:
        layout = _elf_entry(data)
    if layout["kind"] is None:
        layout = {"kind": "raw"}

    # نقطة الدخول
    if layout["kind"] == "pe":
        entry = _rva_to_off(layout, layout["entry_rva"])
        # نصوص/سلاسل عائمة لكل الفروع
    elif layout["kind"] == "elf":
        entry = layout["entry"] if layout["entry"] < len(data) else 0
    else:
        entry = 0

    branches = _scan_branches(data, 0, len(data), layout)

    # نقاط بداية البلوكات: الدخول + أهداف الفروع + السقوط الحر بعد الفرع
    starts = {0, entry}
    for b in branches:
        if b["target"] is not None:
            starts.add(b["target"])
        if b["fall"] is not None:
            starts.add(b["fall"])
    starts = sorted(s for s in starts if s < len(data))

    # بناء البلوكات بالسير المتسلسل
    blocks: list[dict[str, Any]] = []
    block_of: dict[int, int] = {}  # start → block index
    for s in starts[: max_nodes * 2]:
        if s in block_of:
            continue
        nxt = None
        for s2 in starts:
            if s2 > s and (nxt is None or s2 < nxt):
                nxt = s2
        end = nxt if nxt is not None else len(data)
        blocks.append({"start": s, "end": end})
        block_of[s] = len(blocks) - 1

    # تذييل البلوكات بالفروع الداخلية وحوافّها
    edges: list[dict[str, Any]] = []
    exit_id = max(block_of.values()) + 1 if block_of else 1
    for b in blocks:
        in_b = [br for br in branches if b["start"] <= br["pos"] < b["end"]]
        for br in in_b:
            src = block_of[b["start"]]
            if br["kind"] == "ret" or br["kind"] == "int3" or br["kind"].startswith("jmp"):
                dst_off = br["target"]
            else:
                dst_off = br["target"]
            if br["fall"] is not None and br["fall"] in block_of:
                edges.append({"src": src, "dst": block_of[br["fall"]], "kind": "fallthrough"})
            if dst_off is not None and dst_off in block_of:
                label = "call" if br["kind"] == "call" else ("loop" if br["kind"] == "loop" else "jcc" if br["kind"].startswith("jcc") else "jmp")
                edges.append({"src": src, "dst": block_of[dst_off], "kind": label})
            elif br["kind"] in ("ret", "int3"):
                edges.append({"src": src, "dst": exit_id, "kind": "exit"})
        # بلوك بلا فرع ينساب لنهاية الملف أو للبلوك التالي
        if not in_b and b["end"] < len(data) and b["end"] in block_of and block_of[b["end"]] != block_of[b["start"]]:
            edges.append({"src": block_of[b["start"]], "dst": block_of[b["end"]], "kind": "fallthrough"})

    # تلقيح البلوكات بالسلاسل (sink strings → أحمر)
    strings = extract_ascii_strings(data, min_len=4)
    node_strings: dict[int, list[str]] = defaultdict(list)
    for s in strings:
        idx = data.find(s)
        if idx < 0:
            continue
        for b in blocks:
            if b["start"] <= idx < b["end"]:
                node_strings[block_of[b["start"]]].append(s)
                break

    sink_nodes: set[int] = set()
    for nid, ss in node_strings.items():
        for s in ss:
            for sig in _SINK_STRINGS:
                if sig in s:
                    sink_nodes.add(nid)
                    break

    nodes = []
    for i, b in enumerate(blocks[:max_nodes]):
        ss = node_strings.get(i, [])
        nodes.append({
            "id": i,
            "start": b["start"],
            "end": b["end"],
            "size": b["end"] - b["start"],
            "strings": ss[:20],
            "is_entry": b["start"] == entry,
            "is_sink": i in sink_nodes,
            "dangerous": i in sink_nodes,
        })

    # الوظائف المحتملة: أهداف الاستدعاءات + الدخول
    func_entries = sorted({e["dst"] for e in edges if e["kind"] == "call" and e["dst"] != exit_id})
    if entry in block_of and entry not in func_entries:
        func_entries.insert(0, entry)

    functions = []
    for fe in func_entries[:200]:
        bid = block_of.get(fe)
        if bid is None:
            continue
        calls = [e for e in edges if e["src"] == bid and e["kind"] == "call"]
        functions.append({
            "id": f"fn_{bid}",
            "entry_offset": fe,
            "calls": [c["dst"] for c in calls],
        })

    # المسارات الخطرة — BFS من الدخول نحو نقاط الغرق
    dangerous_paths: list[list[int]] = []
    if entry in block_of:
        start_id = block_of[entry]
        adj: dict[int, list[int]] = defaultdict(list)
        for e in edges:
            adj[e["src"]].append(e["dst"])
        q = deque([(start_id, [start_id])])
        seen: set[int] = set()
        while q and len(dangerous_paths) < 10:
            cur, path = q.popleft()
            if cur in sink_nodes:
                dangerous_paths.append(path)
                continue
            if len(path) > 64 or cur in seen:
                continue
            seen.add(cur)
            for nx in adj.get(cur, []):
                if nx == exit_id or nx in path or len(path) > 63:
                    continue
                q.append((nx, path + [nx]))

    # مؤشر التهديد
    threat = 0
    for e in edges:
        if e["kind"] == "call":
            threat += 1
    threat += len(sink_nodes) * 3 + len(dangerous_paths) * 4
    threat = max(1, threat) if dangerous_paths else 0

    # تصدير DOT
    buf: list[str] = ['digraph cfg {', '  node [shape=box, fontname="Courier New", fontsize=9];', '  rankdir=TB;']
    for nd in nodes:
        label = f"B{nd['id']}\\n0x{nd['start']:X}|0x{nd['end']:X}"
        if nd["strings"]:
            label += "\\n" + nd["strings"][0][:24].replace("\\", "/")
        style = "style=filled"
        color = "#d9ead3"
        if nd["is_entry"]:
            color = "#38761d"
        if nd["is_sink"]:
            color = "#cc0000"
        if nd["is_entry"] and nd["is_sink"]:
            color = "#783f04"
        buf.append(f'  b{nd["id"]} [label="{label}", {style}, fillcolor="{color}"];')
    for e in edges:
        buf.append(f'  b{e["src"]} -> b{e["dst"]} [label="{e["kind"]}"];')

    dot = "\n".join(buf) + "\n}\n"

    return {
        "ok": True,
        "filename": filename,
        "format": layout["kind"].upper() if layout["kind"] else "RAW",
        "entry_offset": entry,
        "nodes": nodes,
        "edges": edges,
        "functions": functions,
        "dangerous_paths": dangerous_paths,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "functions": len(functions),
            "dangerous_paths": len(dangerous_paths),
            "threat_index": threat,
            "coverage_pct": round(100.0 * sum(b["size"] for b in blocks) / max(1, len(data)), 1),
        },
        "dot": dot,
        "analysis": (
            "CFG استدلالي: قد تتضمن تعليمات بيانات (data misalignment). "
            "قارن DOT عبر Graphviz أو استخدم Ghidra للتأكيد." if layout["kind"] == "raw"
            else "CFG مبني من نقطة الدخول; تحقق من الفروع غير المباشرة يدوياً."
        ),
    }
