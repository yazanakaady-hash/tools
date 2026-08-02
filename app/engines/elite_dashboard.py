"""ELITE Dashboard — 9 live system engines.

محرك البصمة الرقمية · ماسح المنافذ الداخلي · مراقب العمليات · مشفر الملفات
مدير المهام الخفي · سجل الأحداث التفاعلي · محرك الاختراق التخميني
مسرع الأداء · مستعرض الملفات السري
"""
from __future__ import annotations

import hashlib
import os
import platform
import socket
import struct
import subprocess
import sys
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Optional

try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    HAS_PSUTIL = False

# ═══════════════════════════════════════════════════════════════════
# 1. محرك البصمة الرقمية — Digital Fingerprint
# ═══════════════════════════════════════════════════════════════════

def _mac_addresses() -> list[str]:
    macs: list[str] = []
    if HAS_PSUTIL:
        try:
            for _, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == getattr(psutil, "AF_LINK", 17) and a.address and a.address not in ("00:00:00:00:00:00",):
                        macs.append(a.address)
        except Exception:
            pass
    if not macs:
        try:
            macs.append(":".join(f"{(uuid.getnode() >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6))))
        except Exception:
            macs = ["unknown"]
    return macs


def digital_fingerprint() -> dict[str, Any]:
    """Capture device fingerprint: MAC, hostname, user, OS, machine id."""
    result: dict[str, Any] = {"ok": True, "captured_at": time.time()}
    try:
        result["hostname"] = socket.gethostname()
    except Exception:
        result["hostname"] = "unknown"
    result["user"] = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    result["os"] = f"{platform.system()} {platform.release()} ({platform.machine()})"
    result["macs"] = _mac_addresses()
    try:
        result["machine_guid"] = str(uuid.UUID(int=uuid.getnode()))
    except Exception:
        result["machine_guid"] = ""
    result["python"] = sys.version.split()[0]
    result["cwd"] = str(Path.cwd())
    try:
        result["boot_time"] = int(psutil.boot_time()) if HAS_PSUTIL else 0
    except Exception:
        result["boot_time"] = 0
    raw = "|".join([result["hostname"], result["user"], result["os"],
                    result["macs"][0] if result["macs"] else ""])
    result["fingerprint_sha256"] = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
    return result


# ═══════════════════════════════════════════════════════════════════
# 2. ماسح المنافذ الداخلي — Internal Port Scanner
# ═══════════════════════════════════════════════════════════════════

COMMON_PORTS: list[int] = [21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                           1080, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 7000, 8000,
                           8080, 8443, 8787, 8888, 9000, 9090, 9200, 27017, 49152]


def _port_service(port: int) -> str:
    try:
        return socket.getservbyport(port) or ""
    except Exception:
        return ""


def scan_ports(host: str = "127.0.0.1", ports: Optional[list[int]] = None,
               timeout: float = 0.12) -> dict[str, Any]:
    """Scan open TCP ports on a local host."""
    result: dict[str, Any] = {"ok": True, "host": host, "open": [], "closed_count": 0, "elapsed_sec": 0.0}
    targets = ports or COMMON_PORTS
    t0 = time.perf_counter()
    open_ports: list[dict[str, Any]] = []
    for port in targets:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append({"port": port, "service": _port_service(port) or "unknown"})
        except (OSError, socket.timeout):
            continue
    result["open"] = open_ports
    result["closed_count"] = len(targets) - len(open_ports)
    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


# ═══════════════════════════════════════════════════════════════════
# 3. مراقب العمليات — Process Monitor
# ═══════════════════════════════════════════════════════════════════

def process_monitor(pid: Optional[int] = None, limit: int = 60) -> dict[str, Any]:
    """List active processes with CPU/RAM."""
    result: dict[str, Any] = {"ok": True, "processes": [], "count": 0, "pid": pid}
    if not HAS_PSUTIL:
        result["error"] = "psutil not available"
        result["ok"] = False
        return result
    try:
        procs = []
        if pid is not None:
            items = [psutil.Process(pid)]
        else:
            items = list(psutil.process_iter(["pid", "name", "username", "memory_info",
                                              "cpu_percent", "status", "create_time"]))
        for p in items:
            try:
                info = p.info
                rss = 0.0
                try:
                    mem = info.get("memory_info") or p.memory_info()
                    rss = round(mem.rss / 1048576, 2)
                except Exception:
                    pass
                procs.append({
                    "pid": info.get("pid", p.pid),
                    "name": info.get("name") or p.name(),
                    "user": info.get("username") or "",
                    "status": info.get("status") or "",
                    "cpu": round(float(info.get("cpu_percent") or 0.0), 2),
                    "rss_mb": rss,
                    "created": int(info.get("create_time") or 0),
                })
            except Exception:
                continue
        procs.sort(key=lambda x: (x["cpu"], x["rss_mb"]), reverse=True)
        result["processes"] = procs[:limit]
        result["count"] = len(procs)
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)
    return result


def kill_process(pid: int) -> dict[str, Any]:
    """Terminate a process by PID."""
    result: dict[str, Any] = {"ok": False, "pid": pid}
    if not HAS_PSUTIL:
        result["error"] = "psutil not available"
        return result
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.kill()
        result["ok"] = True
        result["name"] = name
    except Exception as e:
        result["error"] = str(e)
    return result


# ═══════════════════════════════════════════════════════════════════
# 4. مشفر الملفات — One-Click AES-256 Encryptor
# ═══════════════════════════════════════════════════════════════════

def encrypt_file(src: str, dst: str, password: str) -> dict[str, Any]:
    """Encrypt any file with AES-256-GCM in one call."""
    result: dict[str, Any] = {"ok": False, "src": src, "dst": dst, "size_in": 0,
                              "size_out": 0, "elapsed_sec": 0.0, "error": ""}
    t0 = time.perf_counter()
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        path = Path(src)
        if not path.is_file():
            result["error"] = "file not found"
            return result
        data = path.read_bytes()
        result["size_in"] = len(data)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=300_000)
        key = kdf.derive(password.encode("utf-8"))
        nonce = os.urandom(12)
        blob = AESGCM(key).encrypt(nonce, data, None)
        out = Path(dst)
        out.write_bytes(b"RENS" + struct.pack("<H 16s 12s", 1, salt, nonce) + blob)
        result["size_out"] = out.stat().st_size
        result["sha256"] = hashlib.sha256(blob).hexdigest()[:16]
        result["ok"] = True
    except Exception as e:
        result["error"] = str(e)
    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def decrypt_file(src: str, dst: str, password: str) -> dict[str, Any]:
    """Decrypt a file created by encrypt_file()."""
    result: dict[str, Any] = {"ok": False, "src": src, "dst": dst, "size_out": 0, "error": ""}
    t0 = time.perf_counter()
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        path = Path(src)
        if not path.is_file():
            result["error"] = "file not found"
            return result
        data = path.read_bytes()
        if not data.startswith(b"RENS") or len(data) < 38:
            result["error"] = "not a RENS encrypted file"
            return result
        salt, nonce, blob = data[6:22], data[22:34], data[34:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=300_000)
        key = kdf.derive(password.encode("utf-8"))
        plain = AESGCM(key).decrypt(nonce, blob, None)
        out = Path(dst)
        out.write_bytes(plain)
        result["size_out"] = len(plain)
        result["sha256"] = hashlib.sha256(plain).hexdigest()[:16]
        result["ok"] = True
    except Exception as e:
        result["error"] = str(e)
    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


# ═══════════════════════════════════════════════════════════════════
# 5. مدير المهام الخفي — Stealth Task Manager
# ═══════════════════════════════════════════════════════════════════

def stealth_tasks(limit: int = 25) -> dict[str, Any]:
    """Background monitor of CPU/RAM load + top processes."""
    result: dict[str, Any] = {"ok": True, "ts": time.time()}
    if not HAS_PSUTIL:
        result["ok"] = False
        result["error"] = "psutil not available"
        return result
    try:
        cpu = float(psutil.cpu_percent(interval=0.1))
        vm = psutil.virtual_memory()
        result["cpu_percent"] = cpu
        result["ram_percent"] = float(vm.percent)
        result["ram_used_mb"] = round(vm.used / 1048576, 1)
        result["ram_total_mb"] = round(vm.total / 1048576, 1)
        try:
            io = psutil.net_io_counters()
            result["net_mb"] = round((io.bytes_sent + io.bytes_recv) / 1048576, 1)
        except Exception:
            result["net_mb"] = 0.0
        result["top"] = process_monitor(limit=limit).get("processes", [])
    except Exception as e:
        result["error"] = str(e)
    return result


# ═══════════════════════════════════════════════════════════════════
# 6. سجل الأحداث التفاعلي — Interactive Event Log (ring buffer)
# ═══════════════════════════════════════════════════════════════════

MAX_EVENTS = 400
_events: deque = deque(maxlen=MAX_EVENTS)


def log_event(kind: str, detail: str, meta: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Append a server-side event (visits, commands, engine runs)."""
    ev = {"ts": time.time(), "kind": kind, "detail": detail[:200], "meta": meta or {}}
    _events.append(ev)
    return ev


def event_log(limit: int = 200) -> dict[str, Any]:
    """Return recent events, newest first."""
    items = list(_events)[-limit:][::-1]
    return {"ok": True, "count": len(items), "events": items}


def _reset_events() -> None:
    _events.clear()


# ═══════════════════════════════════════════════════════════════════
# 7. محرك الاختراق التخميني — Speculative Brute Engine (educational)
# ═══════════════════════════════════════════════════════════════════

WEAK_PASSWORDS: list[str] = ["admin", "password", "123456", "12345678", "qwerty", "abc123",
                             "letmein", "welcome", "monkey", "dragon", "1234", "pass",
                             "elite", "yazan", "secret", "root", "toor", "0000"]


def speculative_brute(data: bytes, candidates: Optional[list[str]] = None) -> dict[str, Any]:
    """Try weak passwords against an encrypted blob (RENS / KMKZ).

    Educational weak-password audit only — local, offline, tiny dictionary.
    """
    result: dict[str, Any] = {"ok": True, "tried": 0, "hit": None, "elapsed_sec": 0.0}
    if not data:
        result["ok"] = False
        result["error"] = "empty data"
        return result
    wordlist = list(dict.fromkeys([w for w in (candidates or WEAK_PASSWORDS) if w]))
    t0 = time.perf_counter()
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        for pw in wordlist:
            result["tried"] += 1
            try:
                if data.startswith(b"RENS"):
                    salt, nonce, ct = data[6:22], data[22:34], data[34:]
                    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=300_000)
                    AESGCM(kdf.derive(pw.encode())).decrypt(nonce, ct, None)
                    result["hit"] = pw
                    break
                if data.startswith(b"KMKZ"):
                    salt, nonce, ct = data[34:50], data[50:62], data[62:]
                    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
                    AESGCM(kdf.derive(pw.encode())).decrypt(nonce, ct, None)
                    result["hit"] = pw
                    break
                break  # unknown format — nothing to brute
            except Exception:
                continue
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)
    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    if not result.get("hit"):
        result["weak_passwords"] = wordlist
    return result


# ═══════════════════════════════════════════════════════════════════
# 8. مسرع الأداء — Performance Accelerator
# ═══════════════════════════════════════════════════════════════════

def accelerate(dry_run: bool = False) -> dict[str, Any]:
    """Tune local performance knobs (safe, reversible, lab-only)."""
    result: dict[str, Any] = {"ok": True, "dry_run": dry_run, "applied": [], "suggestions": []}
    try:
        if not dry_run and HAS_PSUTIL:
            try:
                psutil.Process(os.getpid()).nice(psutil.HIGH_PRIORITY_CLASS)
                result["applied"].append("server priority -> HIGH")
            except Exception:
                result["suggestions"].append("raise process priority (needs admin)")
        result["suggestions"].append(
            "enable High performance power plan (powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c)")
        if sys.platform == "win32":
            result["suggestions"].append("netsh int tcp set global autotuninglevel=normal")
        result["suggestions"].append("ipconfig /flushdns")
        if not dry_run:
            try:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
                result["applied"].append("DNS cache flushed")
            except Exception:
                pass
        result["applied_count"] = len(result["applied"])
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)
    return result


# ═══════════════════════════════════════════════════════════════════
# 9. مستعرض الملفات السري — Secret File Browser
# ═══════════════════════════════════════════════════════════════════

def secret_browser(path: Optional[str] = None, max_entries: int = 80) -> dict[str, Any]:
    """Browse folders from inside the panel (safe, bounded)."""
    result: dict[str, Any] = {"ok": True, "path": "", "entries": [], "count": 0, "error": ""}
    try:
        base = Path(path) if path else Path.cwd()
        base = base.resolve()
        if not base.is_dir():
            result["ok"] = False
            result["error"] = "directory not found"
            return result
        result["path"] = str(base)
        entries = []
        for child in sorted(base.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
            try:
                st = child.stat()
                entries.append({
                    "name": child.name,
                    "type": "dir" if child.is_dir() else "file",
                    "size": st.st_size if child.is_file() else 0,
                    "modified": int(st.st_mtime),
                    "hidden": child.name.startswith("."),
                })
            except OSError:
                continue
            if len(entries) >= max_entries:
                break
        result["entries"] = entries
        result["count"] = len(entries)
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)
    return result

