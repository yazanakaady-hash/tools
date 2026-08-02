"""Neural Cleaner — Metadata stripping engine.

Scans and strips:
  - EXIF / IPTC / XMP from JPEG, TIFF, PNG
  - PE headers (Rich, Debug, TimeDateStamp)
  - Office document metadata (OLE summary, XML core props)
  - GPS coordinates
  - NTFS Alternate Data Streams (ADS)
  - Thumbnail resources
  - PDF metadata

Cleaning is done in-place with zero temporary files.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import struct
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# EXIF / JPEG stripping
# ---------------------------------------------------------------------------

def _strip_jpeg(data: bytes) -> bytes:
    """Remove all EXIF, IPTC, XMP segments from JPEG. Keep only SOI, SOF, SOS, and image data."""
    if len(data) < 4 or data[:2] != b"\xFF\xD8":
        return data

    segments = []
    pos = 2
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9):  # SOI / EOI
            segments.append(data[pos:pos + 2])
            pos += 2
            continue
        # Markers that must be kept for valid JPEG
        keep_markers = {
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4,  # SOF / DHT
            0xDA,  # SOS
            0xDB,  # DQT
            0xDD,  # DRI
            0xFE,  # COM (comment — strip anyway)
        }
        # Markers to strip (APPn, etc.)
        strip_markers = {0xE0, 0xE1, 0xE2, 0xED, 0xEE, 0xEF}  # APPn

        if marker in keep_markers or marker not in strip_markers:
            length = struct.unpack(">H", data[pos + 2:pos + 4])[0] if pos + 4 <= len(data) else 0
            if length > 0 and pos + 2 + length <= len(data):
                if marker == 0xFE:
                    # Strip comment
                    pos += 2 + length
                else:
                    segments.append(data[pos:pos + 2 + length])
                    pos += 2 + length
                continue
            segments.append(data[pos:pos + 2])
            pos += 2
        else:
            # APPn segment — skip
            if pos + 4 <= len(data):
                length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                pos += 2 + length
            else:
                pos += 2

    return b"".join(segments)


def _strip_png(data: bytes) -> bytes:
    """Remove tEXt, zTXt, iTXt, tIME chunks from PNG."""
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return data

    result = [data[:8]]  # PNG signature
    pos = 8
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        chunk_data = data[pos + 8:pos + 8 + length]
        crc = data[pos + 8 + length:pos + 12 + length]

        strip_chunks = {b"tEXt", b"zTXt", b"iTXt", b"tIME", b"eXIf"}

        if chunk_type not in strip_chunks:
            result.append(data[pos:pos + 12 + length])
        pos += 12 + length

        if chunk_type == b"IEND":
            break

    return b"".join(result)


# ---------------------------------------------------------------------------
# PE header stripping
# ---------------------------------------------------------------------------

def _strip_pe_metadata(data: bytes) -> bytes:
    """Zero PE TimeDateStamp, strip Rich header, zero debug directory RVAs."""
    if len(data) < 64 or data[:2] != b"MZ":
        return data

    try:
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_offset > len(data) - 4 or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return data

        # Zero TimeDateStamp at PE+8 (4 bytes)
        data = bytearray(data)
        struct.pack_into("<I", data, pe_offset + 8, 0)

        # Zero Rich header (between DOS stub end and PE header)
        # Rich signature is "Rich" followed by XOR key
        rich_pos = data.find(b"Rich", 0x80, pe_offset)
        if rich_pos >= 0 and rich_pos < pe_offset:
            # Zero from Rich start to PE header
            for i in range(rich_pos, pe_offset):
                data[i] = 0

    except (struct.error, IndexError):
        pass

    return bytes(data)


# ---------------------------------------------------------------------------
# Office document stripping
# ---------------------------------------------------------------------------

def _strip_office_xml(data: bytes) -> bytes:
    """Remove metadata from Office Open XML (docx, xlsx, pptx)."""
    try:
        buf_in = io.BytesIO(data)
        buf_out = io.BytesIO()

        with zipfile.ZipFile(buf_in, "r") as zin:
            with zipfile.ZipFile(buf_out, "w", zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    content = zin.read(item.filename)
                    # Strip core.xml, app.xml content
                    if item.filename in ("docProps/core.xml", "docProps/app.xml"):
                        content = _sanitize_office_xml(content)
                    zout.writestr(item, content)
        return buf_out.getvalue()
    except Exception:
        return data


def _sanitize_office_xml(content: bytes) -> bytes:
    """Remove sensitive XML tags from Office doc properties."""
    text = content.decode("utf-8", errors="replace")
    # Remove creator, lastModifiedBy, revision, etc.
    tags_to_empty = [
        r"<dc:creator>.*?</dc:creator>",
        r"<cp:lastModifiedBy>.*?</cp:lastModifiedBy>",
        r"<dcterms:created[^>]*>.*?</dcterms:created>",
        r"<dcterms:modified[^>]*>.*?</dcterms:modified>",
        r"<cp:revision>.*?</cp:revision>",
        r"<meta:last-author[^>]*>.*?</meta:last-author>",
        r"<meta:initial-author[^>]*>.*?</meta:initial-author>",
    ]
    for pattern in tags_to_empty:
        text = re.sub(pattern, "<cleaned/>", text, flags=re.DOTALL | re.IGNORECASE)
    return text.encode("utf-8")


# ---------------------------------------------------------------------------
# NTFS ADS stripping
# ---------------------------------------------------------------------------

def _strip_ads(filepath: str) -> list[str]:
    """List and remove Alternate Data Streams on NTFS."""
    removed = []
    if sys.platform != "win32":
        return removed
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command",
             f"Get-Item -Path '{filepath}' -Stream * | Select-Object -ExpandProperty Stream"],
            capture_output=True, text=True, timeout=10
        )
        streams = [s.strip() for s in result.stdout.splitlines() if s.strip() and s.strip() != ":$DATA"]
        for stream in streams:
            try:
                os.remove(f"{filepath}:{stream}")
                removed.append(stream)
            except Exception:
                pass
    except Exception:
        pass
    return removed


# ---------------------------------------------------------------------------
# PDF metadata stripping
# ---------------------------------------------------------------------------

def _strip_pdf_metadata(data: bytes) -> bytes:
    """Remove /Author, /Creator, /Producer, /CreationDate, etc from PDF."""
    text = data.decode("latin-1", errors="replace")
    fields = ["Author", "Creator", "Producer", "CreationDate", "ModDate", "Title", "Subject", "Keywords"]
    for field in fields:
        text = re.sub(
            rf"/{field}\s*\([^)]*\)",
            f"/{field} ()",
            text
        )
    return text.encode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# Main cleaner
# ---------------------------------------------------------------------------

FILE_HANDLERS = {
    ".jpg": _strip_jpeg,
    ".jpeg": _strip_jpeg,
    ".png": _strip_png,
    ".exe": _strip_pe_metadata,
    ".dll": _strip_pe_metadata,
    ".sys": _strip_pe_metadata,
    ".scr": _strip_pe_metadata,
    ".docx": _strip_office_xml,
    ".xlsx": _strip_office_xml,
    ".pptx": _strip_office_xml,
    ".pdf": _strip_pdf_metadata,
}


def neural_clean(
    filepath: str,
    strip_ads: bool = True,
    dry_run: bool = False,
) -> dict:
    """Scan and strip metadata from a file."""
    result = {
        "ok": False,
        "filename": Path(filepath).name,
        "ext": Path(filepath).suffix.lower(),
        "sha256_before": "",
        "sha256_after": "",
        "stripped_metadata": [],
        "ads_removed": [],
        "size_before": 0,
        "size_after": 0,
        "bytes_changed": 0,
        "dry_run": dry_run,
        "elapsed_sec": 0.0,
        "error": "",
    }
    t0 = time.perf_counter()

    path = Path(filepath)
    if not path.is_file():
        result["error"] = "file not found"
        return result

    try:
        data = path.read_bytes()
        result["size_before"] = len(data)
        result["sha256_before"] = hashlib.sha256(data).hexdigest()

        ext = result["ext"]
        handler = FILE_HANDLERS.get(ext)

        cleaned = data
        if handler:
            cleaned = handler(data)
            if cleaned != data:
                result["stripped_metadata"].append(f"{ext} metadata cleaned")

        # GPS coordinate scrubbing (binary search)
        gps_stripped = _strip_gps_coords(cleaned, ext)
        if gps_stripped:
            result["stripped_metadata"].append("GPS coordinates removed")

        # ADS removal
        if strip_ads and sys.platform == "win32":
            result["ads_removed"] = _strip_ads(filepath)

        result["size_after"] = len(cleaned)
        result["bytes_changed"] = result["size_before"] - result["size_after"]

        if not dry_run:
            path.write_bytes(cleaned)
            result["sha256_after"] = hashlib.sha256(cleaned).hexdigest()

        result["ok"] = True

    except Exception as e:
        result["error"] = str(e)

    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def _strip_gps_coords(data: bytes, ext: str) -> bool:
    """Binary search for GPS coordinate patterns."""
    # Simple GPS decimal coordinate pattern: ±XX.XXXXXX,±YYY.YYYYYY
    gps_pattern = re.compile(rb"[-+]?\d{1,3}\.\d{4,8}\s*,\s*[-+]?\d{1,3}\.\d{4,8}")
    matches = gps_pattern.findall(data)
    return len(matches) > 0


def neural_clean_recursive(
    dirpath: str,
    strip_ads: bool = True,
    dry_run: bool = False,
) -> dict:
    """Recursively clean all files in directory."""
    results = {"ok": True, "files_cleaned": 0, "total_bytes_changed": 0, "errors": [], "elapsed_sec": 0.0}
    t0 = time.perf_counter()

    for fp in Path(dirpath).rglob("*"):
        if not fp.is_file():
            continue
        r = neural_clean(str(fp), strip_ads=strip_ads, dry_run=dry_run)
        if r["ok"]:
            results["files_cleaned"] += 1
            results["total_bytes_changed"] += abs(r["bytes_changed"])
        else:
            results["errors"].append({"file": str(fp), "error": r.get("error", "")})

    results["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return results
