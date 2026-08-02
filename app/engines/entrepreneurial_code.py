"""Entrepreneurial Code (رمز انتجاري) — one-time enterprise token forge.

Generates sealed, self-destructing, single-use codes bound to a label and
TTL, with HMAC integrity. Useful for activation keys, one-shot auth codes,
and payload countersigns in lab tooling.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from typing import Any, Optional

MAGIC = b"ENTC"
VERSION = 1

# single-use registry (in-memory; resets on server restart)
_used: set[str] = set()

# low-cost default master secret for the lab; rotate via master_secret
DEFAULT_MASTER: bytes = b"re-nexus-entrepreneurial-master-2026"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def forge_code(label: str = "elite", ttl_hours: int = 24,
               master_secret: Optional[str] = None) -> dict[str, Any]:
    """Create a sealed one-time code.

    Format (binary, then base64url):
      [magic:4 "ENTC"][ver:1][flags:1][ttl_hours:4][issued_ts:8][label_len:2][label]
      [payload_len:4][payload][hmac_sha256:32]
    flags bit0 = single-use.
    """
    result: dict[str, Any] = {"ok": False, "error": ""}
    try:
        ttl = max(1, min(8760, int(ttl_hours)))
        now = int(time.time())
        label_b = (label or "elite").encode("utf-8")[:64]
        payload = os.urandom(24)  # unpredictable one-time nonce
        header = struct.pack("<4s B B I q H I", MAGIC, VERSION, 0x01, ttl,
                             now, len(label_b), len(payload))
        body = header + label_b + payload
        secret = (master_secret or "").encode("utf-8") or DEFAULT_MASTER
        sig = hmac.new(secret, body, hashlib.sha256).digest()
        code = _b64(body + sig)
        result.update({
            "ok": True,
            "code": code,
            "label": label,
            "issued_ts": now,
            "expires_ts": now + ttl * 3600,
            "ttl_hours": ttl,
            "single_use": True,
            "length": len(code),
        })
    except Exception as e:
        result["error"] = str(e)
    return result


def verify_code(code: str, master_secret: Optional[str] = None) -> dict[str, Any]:
    """Verify a code: HMAC, TTL, single-use registry."""
    result: dict[str, Any] = {"ok": False, "valid": False, "error": ""}
    try:
        raw = _unb64(code.strip())
        if len(raw) < 54 or not raw.startswith(MAGIC):
            result["error"] = "bad magic"
            return result
        ver = raw[4]
        flags = raw[5]
        ttl, issued, lbl_len, payload_len = struct.unpack("<I q H I", raw[6:24])
        body = raw[:len(raw) - 32]
        sig = raw[len(raw) - 32:]
        secret = (master_secret or "").encode("utf-8") or DEFAULT_MASTER
        if not hmac.compare_digest(sig, hmac.new(secret, body, hashlib.sha256).digest()):
            result["error"] = "integrity failed"
            return result
        label = raw[24:24 + lbl_len].decode("utf-8", "replace")
        payload = raw[24 + lbl_len:24 + lbl_len + payload_len]
        now = int(time.time())
        expired = now > issued + ttl * 3600
        single_use = bool(flags & 0x01)
        already_used = single_use and code in _used
        result.update({
            "valid": (not expired) and (not already_used),
            "version": ver,
            "label": label,
            "issued_ts": issued,
            "expires_ts": issued + ttl * 3600,
            "remaining_sec": max(0, issued + ttl * 3600 - now),
            "single_use": single_use,
            "used": already_used,
            "expired": expired,
            "payload_sha256": hashlib.sha256(payload).hexdigest()[:16],
        })
        if result["valid"] and single_use:
            _used.add(code)  # consume
        result["ok"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def analyze_code(code: str) -> dict[str, Any]:
    """Stateless decode without consuming or HMAC-verifying (for inspection)."""
    result: dict[str, Any] = {"ok": False, "error": ""}
    try:
        raw = _unb64(code.strip())
        if not raw.startswith(MAGIC):
            result["error"] = "not an ENTC code"
            return result
        ttl, issued, lbl_len, payload_len = struct.unpack("<I q H I", raw[6:24])
        label = raw[24:24 + lbl_len].decode("utf-8", "replace")
        result.update({
            "ok": True,
            "label": label,
            "issued_ts": issued,
            "expires_ts": issued + ttl * 3600,
            "ttl_hours": ttl,
            "payload_len": payload_len,
            "sig_len": 32,
        })
    except Exception as e:
        result["error"] = str(e)
    return result

