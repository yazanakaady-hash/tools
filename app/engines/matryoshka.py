"""Digital Matryoshka Analyzer — recursive multi-layer peel."""
from __future__ import annotations

import base64
import binascii
import gzip
import io
import re
import zipfile
from pathlib import Path
from typing import Any

from .common import detect_magic, entropy, hexdump_preview, md5, pe_imports_and_sections, sha256


MAX_DEPTH = 12
MAX_CHILDREN = 40
MAX_BYTES = 40 * 1024 * 1024


def _node(data: bytes, name: str, method: str, depth: int) -> dict[str, Any]:
    magic = detect_magic(data)
    return {
        "id": sha256(data)[:16],
        "name": name,
        "method": method,
        "depth": depth,
        "size": len(data),
        "sha256": sha256(data),
        "md5": md5(data),
        "entropy": entropy(data[: min(len(data), 256 * 1024)]),
        "magic": magic,
        "preview_hex": hexdump_preview(data),
        "children": [],
        "core": False,
        "notes": [],
    }


def _try_unzip(data: bytes) -> list[tuple[str, bytes]]:
    out = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist()[:MAX_CHILDREN]:
                if info.is_dir():
                    continue
                if info.file_size > MAX_BYTES:
                    continue
                try:
                    raw = zf.read(info)
                    out.append((info.filename, raw))
                except RuntimeError:
                    # encrypted zip member
                    out.append((info.filename + " [encrypted]", b""))
                except Exception:
                    continue
    except Exception:
        return []
    return out


def _try_gzip(data: bytes) -> bytes | None:
    try:
        return gzip.decompress(data)
    except Exception:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
                return g.read(MAX_BYTES)
        except Exception:
            return None


def _try_bzip2(data: bytes) -> bytes | None:
    try:
        import bz2

        return bz2.decompress(data)
    except Exception:
        return None


def _try_base64(data: bytes) -> bytes | None:
    try:
        text = data.decode("ascii", errors="ignore")
        # strip whitespace and common wrappers
        text = re.sub(r"\s+", "", text)
        text = text.strip().strip("'\"")
        if len(text) < 16:
            return None
        # pad
        pad = (-len(text)) % 4
        text = text + ("=" * pad)
        raw = base64.b64decode(text, validate=False)
        if len(raw) < 4:
            return None
        # must look "more structured" or different entropy
        if raw == data:
            return None
        return raw
    except Exception:
        return None


def _try_hex(data: bytes) -> bytes | None:
    try:
        text = data.decode("ascii", errors="ignore")
        text = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(text) < 32 or len(text) % 2:
            return None
        raw = binascii.unhexlify(text[: min(len(text), MAX_BYTES * 2)])
        if len(raw) < 4:
            return None
        return raw
    except Exception:
        return None


def _try_pe_overlay(data: bytes) -> list[tuple[str, bytes]]:
    """If PE has large overlay after last section, emit as child."""
    pe = pe_imports_and_sections(data)
    if not pe.get("valid") or not pe.get("sections"):
        return []
    last = max(pe["sections"], key=lambda s: s["raw_ptr"] + s["raw_size"])
    end = last["raw_ptr"] + last["raw_size"]
    if end < len(data) - 64:
        overlay = data[end:]
        if len(overlay) >= 16:
            return [("pe_overlay.bin", overlay)]
    return []


def _peel(data: bytes, name: str, method: str, depth: int, seen: set[str]) -> dict[str, Any]:
    node = _node(data, name, method, depth)
    h = node["sha256"]
    if h in seen:
        node["notes"].append("duplicate content (cycle)")
        node["core"] = True
        return node
    seen.add(h)

    if depth >= MAX_DEPTH:
        node["notes"].append("max depth reached")
        node["core"] = True
        return node

    if len(data) == 0:
        node["notes"].append("empty layer")
        node["core"] = True
        return node

    mtype = node["magic"]["type"]
    children_data: list[tuple[str, bytes, str]] = []

    if mtype == "zip":
        for fname, raw in _try_unzip(data):
            if raw:
                children_data.append((fname, raw, "zip_extract"))
            else:
                child = _node(b"", fname, "zip_encrypted", depth + 1)
                child["notes"].append("password-protected ZIP entry")
                child["core"] = True
                node["children"].append(child)
    elif mtype == "gzip":
        raw = _try_gzip(data)
        if raw is not None:
            children_data.append((name + ".ungz", raw, "gzip_decompress"))
    elif mtype == "bzip2":
        raw = _try_bzip2(data)
        if raw is not None:
            children_data.append((name + ".bz2out", raw, "bzip2_decompress"))
    elif mtype == "base64":
        raw = _try_base64(data)
        if raw is not None:
            children_data.append((name + ".b64dec", raw, "base64_decode"))
    elif mtype == "hextext":
        raw = _try_hex(data)
        if raw is not None:
            children_data.append((name + ".hexdec", raw, "hex_decode"))
    elif mtype in ("pe", "mz"):
        for fname, raw in _try_pe_overlay(data):
            children_data.append((fname, raw, "pe_overlay"))
        # also try if whole file is base64 mis-detected — skip
        pe = pe_imports_and_sections(data)
        node["pe"] = {
            "sections": pe.get("sections", []),
            "import_dlls": [i["dll"] for i in pe.get("imports", [])],
            "import_count": sum(len(i.get("funcs", [])) for i in pe.get("imports", [])),
        }
    elif mtype == "encrypted_or_packed":
        # attempt opportunistic decoders anyway
        for fn, label in ((_try_base64, "base64_decode"), (_try_gzip, "gzip_decompress"), (_try_hex, "hex_decode")):
            raw = fn(data)
            if raw and raw != data and abs(entropy(raw[:4096]) - node["entropy"]) > 0.3:
                children_data.append((name + "." + label, raw, label))
                break

    # Always try zip/gzip/base64 as soft probes if no children and not identified tightly
    if not children_data and mtype in ("unknown", "low_entropy", "encrypted_or_packed"):
        for probe, label, tag in (
            (_try_unzip, "zip_probe", "zip_extract"),
            (_try_gzip, "gzip_probe", "gzip_decompress"),
            (_try_base64, "b64_probe", "base64_decode"),
            (_try_hex, "hex_probe", "hex_decode"),
        ):
            if label.startswith("zip"):
                items = _try_unzip(data)
                if items:
                    for fname, raw in items:
                        if raw:
                            children_data.append((fname, raw, tag))
                    break
            else:
                raw = probe(data)  # type: ignore
                if raw and raw != data:
                    children_data.append((name + "." + label, raw, tag))
                    break

    if not children_data:
        # leaf = core payload candidate
        node["core"] = True
        if mtype in ("pe", "elf", "macho"):
            node["notes"].append("reached executable core")
        elif mtype == "encrypted_or_packed":
            node["notes"].append("could not peel further — possible final ciphertext/packer")
        else:
            node["notes"].append("leaf node")
        return node

    for cname, cdata, cmethod in children_data[:MAX_CHILDREN]:
        if len(cdata) > MAX_BYTES:
            ch = _node(cdata[:0], cname, cmethod, depth + 1)
            ch["notes"].append(f"skipped — size {len(cdata)} > limit")
            ch["size"] = len(cdata)
            node["children"].append(ch)
            continue
        node["children"].append(_peel(cdata, cname, cmethod, depth + 1, seen))

    # parent is not core if it has peelable children
    node["core"] = False
    return node


def _collect_cores(node: dict[str, Any], acc: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    acc = acc if acc is not None else []
    if node.get("core"):
        acc.append(
            {
                "name": node["name"],
                "sha256": node["sha256"],
                "size": node["size"],
                "magic": node["magic"],
                "entropy": node["entropy"],
                "depth": node["depth"],
                "method_chain_hint": node["method"],
                "notes": node.get("notes", []),
            }
        )
    for ch in node.get("children", []):
        _collect_cores(ch, acc)
    return acc


def _flatten_methods(node: dict[str, Any], chain: list[str] | None = None, acc: list[list[str]] | None = None):
    acc = acc if acc is not None else []
    chain = (chain or []) + [f'{node["method"]}:{node["magic"]["type"]}']
    if node.get("core"):
        acc.append(chain)
    for ch in node.get("children", []):
        _flatten_methods(ch, chain, acc)
    return acc


def analyze_matryoshka(data: bytes, filename: str = "sample.bin") -> dict[str, Any]:
    if len(data) > MAX_BYTES:
        return {"ok": False, "error": f"file too large (max {MAX_BYTES} bytes)"}
    root = _peel(data, filename, "input", 0, set())
    cores = _collect_cores(root)
    chains = _flatten_methods(root)
    return {
        "ok": True,
        "filename": filename,
        "root_sha256": root["sha256"],
        "tree": root,
        "cores": cores,
        "method_chains": chains,
        "stats": {
            "layers": _count_nodes(root),
            "max_depth": _max_depth(root),
            "core_count": len(cores),
        },
    }


def _count_nodes(n: dict) -> int:
    return 1 + sum(_count_nodes(c) for c in n.get("children", []))


def _max_depth(n: dict) -> int:
    if not n.get("children"):
        return n.get("depth", 0)
    return max(_max_depth(c) for c in n["children"])


def save_cores(tree: dict[str, Any], out_dir: Path) -> list[str]:
    """Optionally dump core blobs — not used by default for safety."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    return paths
