"""Shared helpers: magic, entropy, hashing, PE basics."""
from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Any


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 4)


def hexdump_preview(data: bytes, n: int = 64) -> str:
    chunk = data[:n]
    return " ".join(f"{b:02x}" for b in chunk)


def detect_magic(data: bytes) -> dict[str, Any]:
    """Identify container / encoding layer from magic bytes."""
    if not data:
        return {"type": "empty", "label": "Empty"}

    # PE / DOS
    if data[:2] == b"MZ":
        pe_off = None
        try:
            if len(data) >= 0x40:
                pe_off = struct.unpack_from("<I", data, 0x3C)[0]
                if 0 < pe_off < len(data) - 4 and data[pe_off : pe_off + 4] == b"PE\0\0":
                    return {"type": "pe", "label": "Windows PE (EXE/DLL)", "pe_offset": pe_off}
        except Exception:
            pass
        return {"type": "mz", "label": "DOS MZ (possible PE)"}

    if data[:4] == b"\x7fELF":
        return {"type": "elf", "label": "ELF binary"}
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return {"type": "macho", "label": "Mach-O"}
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06" or data[:4] == b"PK\x07\x08":
        return {"type": "zip", "label": "ZIP archive"}
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return {"type": "7z", "label": "7-Zip archive"}
    if data[:4] == b"Rar!" :
        return {"type": "rar", "label": "RAR archive"}
    if data[:2] == b"\x1f\x8b":
        return {"type": "gzip", "label": "GZIP compressed"}
    if data[:3] == b"BZh":
        return {"type": "bzip2", "label": "BZIP2 compressed"}
    if data[:4] == b"\x28\xb5\x2f\xfd":
        return {"type": "zstd", "label": "Zstandard compressed"}
    if data[:4] == b"\x04\x22\x4d\x18":
        return {"type": "lz4", "label": "LZ4 frame"}
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return {"type": "png", "label": "PNG image"}
    if data[:3] == b"\xff\xd8\xff":
        return {"type": "jpeg", "label": "JPEG image"}
    if data[:4] == b"%PDF":
        return {"type": "pdf", "label": "PDF document"}
    if data[:4] == b"\xd0\xcf\x11\xe0":
        return {"type": "ole", "label": "OLE Compound (DOC/XLS/…)" }

    # High ratio printable base64?
    sample = data[: min(len(data), 4096)]
    try:
        text = sample.decode("ascii", errors="ignore")
        b64_chars = sum(1 for c in text if c.isalnum() or c in "+/=\n\r")
        if len(text) > 80 and b64_chars / max(len(text), 1) > 0.92 and re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text):
            return {"type": "base64", "label": "Base64-encoded blob"}
    except Exception:
        pass

    # Hex dump ascii
    try:
        text = sample.decode("ascii", errors="ignore").strip()
        if len(text) > 64 and re.fullmatch(r"[0-9a-fA-F\s]+", text[:2000] or "x"):
            hex_ratio = sum(c in "0123456789abcdefABCDEF" for c in text) / max(len(text), 1)
            if hex_ratio > 0.7:
                return {"type": "hextext", "label": "Hex-encoded text"}
    except Exception:
        pass

    ent = entropy(data[:65536])
    if ent > 7.5:
        return {"type": "encrypted_or_packed", "label": f"High-entropy blob (H≈{ent}) — packed/encrypted?"}
    if ent < 3.5:
        return {"type": "low_entropy", "label": f"Low-entropy data (H≈{ent})"}

    return {"type": "unknown", "label": f"Unknown binary (H≈{ent})"}


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    out = []
    for m in pat.finditer(data):
        try:
            out.append(m.group().decode("ascii"))
        except Exception:
            pass
    return out


def extract_utf16le_strings(data: bytes, min_len: int = 4) -> list[str]:
    # naive wide string scan
    out = []
    i = 0
    n = len(data)
    while i < n - 1:
        chars = []
        j = i
        while j + 1 < n:
            lo, hi = data[j], data[j + 1]
            if hi == 0 and 0x20 <= lo < 0x7f:
                chars.append(chr(lo))
                j += 2
            else:
                break
        if len(chars) >= min_len:
            out.append("".join(chars))
            i = j
        else:
            i += 2 if i % 2 == 0 else 1
    return out


def pe_imports_and_sections(data: bytes) -> dict[str, Any]:
    """Minimal PE parse: sections + import DLL names (best-effort)."""
    info: dict[str, Any] = {"valid": False, "sections": [], "imports": [], "exports_hint": [], "machine": None}
    if data[:2] != b"MZ" or len(data) < 0x40:
        return info
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return info
        coff = e_lfanew + 4
        machine, num_sections = struct.unpack_from("<HH", data, coff)
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        pe32plus = magic == 0x20B
        info["machine"] = f"0x{machine:04x}"
        info["pe32plus"] = pe32plus
        # data directories
        dd_off = opt + (112 if pe32plus else 96)
        # import directory RVA = DD[1]
        if dd_off + 16 <= len(data):
            import_rva, import_size = struct.unpack_from("<II", data, dd_off + 8)
        else:
            import_rva = import_size = 0
        # section table
        sec_off = opt + opt_size
        sections = []
        for i in range(num_sections):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            name = data[off : off + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            sections.append(
                {
                    "name": name,
                    "vsize": vsize,
                    "vaddr": vaddr,
                    "raw_size": raw_size,
                    "raw_ptr": raw_ptr,
                    "chars": chars,
                    "entropy": entropy(data[raw_ptr : raw_ptr + raw_size]) if raw_ptr and raw_size else 0,
                    "rx": bool(chars & 0x20000000),
                    "rw": bool(chars & 0x80000000),
                    "code": bool(chars & 0x00000020),
                }
            )
        info["sections"] = sections
        info["valid"] = True

        def rva_to_off(rva: int) -> int | None:
            for s in sections:
                if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["raw_size"]):
                    return s["raw_ptr"] + (rva - s["vaddr"])
            return None

        imports = []
        if import_rva:
            off = rva_to_off(import_rva)
            if off is not None:
                while off + 20 <= len(data):
                    (ilt_rva, ts, fwd, name_rva, iat_rva) = struct.unpack_from("<IIIII", data, off)
                    if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                        break
                    no = rva_to_off(name_rva) if name_rva else None
                    dll = ""
                    if no is not None:
                        end = data.find(b"\0", no)
                        dll = data[no:end].decode("ascii", errors="replace")
                    funcs: list[str] = []
                    # walk ILT/IAT lightly
                    thunk_rva = ilt_rva or iat_rva
                    to = rva_to_off(thunk_rva) if thunk_rva else None
                    if to is not None:
                        step = 8 if pe32plus else 4
                        for _ in range(64):
                            if to + step > len(data):
                                break
                            thunk = struct.unpack_from("<Q" if pe32plus else "<I", data, to)[0]
                            if thunk == 0:
                                break
                            ordinal_flag = 1 << (63 if pe32plus else 31)
                            if thunk & ordinal_flag:
                                funcs.append(f"ord_{thunk & 0xFFFF}")
                            else:
                                hint_rva = thunk & (0x7FFFFFFF if not pe32plus else 0x7FFFFFFFFFFFFFFF)
                                fo = rva_to_off(hint_rva)
                                if fo is not None and fo + 2 < len(data):
                                    fe = data.find(b"\0", fo + 2)
                                    funcs.append(data[fo + 2 : fe].decode("ascii", errors="replace"))
                            to += step
                    imports.append({"dll": dll, "funcs": funcs})
                    off += 20
        info["imports"] = imports
    except Exception as e:
        info["error"] = str(e)
    return info


def safe_work_dir(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    return base
