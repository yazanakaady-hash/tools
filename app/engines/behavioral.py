"""behavioral — البصمة السلوكية (Behavioral Fingerprint).

تنفيذ الملف المدروس في عملية فرعية معزولة زمنياً ومراقبة سلوكه الحقيقي:
الملفات التي يلمسها، اتصالات الشبكة، العمليات الفرعية، قمم الذاكرة،
الخروج المبكر، مع استدلالات API ثابتة من سلاسل الملف، ثم إصدار
"تقرير سلوك الملف" بدرجة عدوانية (0–100).

تنبيه أمني: هذا المحرك ينفّذ الملف على الجهاز المضيف فعلياً —
استخدمه في بيئة تحليل معزولة (VM) ولا تعرضه لشبكة خارجية.
تتبع مفاتيح الريجستري يتطلب Procmon أو ETW خارجياً (نُبلّغ عنه فقط).
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .common import extract_ascii_strings

_API_HINTS: list[tuple[str, int]] = [
    # (اسم إن كان جزءاً من استدعاء، الوزن)
    ("IsDebuggerPresent", 6), ("NtQueryInformationProcess", 6),
    ("WriteProcessMemory", 6), ("CreateRemoteThread", 7),
    ("VirtualAllocEx", 6), ("SetWindowsHookEx", 6),
    ("URLDownloadToFile", 8), ("WinExec", 6), ("ShellExecute", 5),
    ("CreateProcess", 5), ("RegCreateKey", 6), ("RegSetValue", 6),
    ("RegOpenKey", 3), ("socket", 5), ("connect", 4), ("send", 3),
    ("recv", 3), ("bind", 3), ("listen", 3), ("LoadLibrary", 2),
    ("GetProcAddress", 2), ("CryptEncrypt", 6), ("VirtualAlloc", 3),
    ("GetTempPath", 3), ("MoveFile", 4), ("DeleteFile", 4),
    ("OpenMutex", 4), ("AdjustTokenPrivileges", 7), ("LookupPrivilegeValue", 5),
]

_EARLY_EXIT_SEC = 1.0          # خروج قبل هذا الحد = مريب
_MAX_EVENTS_PER_KIND = 200     # سقف الأحداث لكل فئة (منع انفجار الذاكرة)
_MAX_OUTPUT = 12 * 1024        # ذيل stdout/stderr المحتفظ به


def _safe_name(p: Any) -> str:
    try:
        return str(Path(str(p or "")).resolve())
    except Exception:
        return str(p or "")


def behavioral_fingerprint(
    target: str,
    args: list[str] | None = None,
    timeout: float = 8.0,
    interval: float = 0.25,
) -> dict[str, Any]:
    """تنفيذ الملف وبناء تقريره السلوكي.

    Parameters
    ----------
    target : str — مسار الملف القابل للتنفيذ (أو البرنامج النصي).
    args : list[str]|None — وسائط إضافية.
    timeout : float — مهلة التنفيذ بالثواني (يُقتل عند تجاوزها).
    interval : float — فترة أخذ العينات عبر psutil.

    Returns
    -------
    dict — تقرير سلوك الملف: أحداث، درجة، حكم، ومؤشرات API.
    """
    result: dict[str, Any] = {
        "ok": False,
        "target": "",
        "error": "",
        "verdict": "غير محسوب",
        "score": 0,
        "severity": "unknown",
        "timeline": [],
        "touched_files": [],
        "network_connections": [],
        "spawned_children": [],
        "memory_peak_bytes": 0,
        "cpu_burst_percent": 0,
        "exit_code": None,
        "early_exit": False,
        "timed_out": False,
        "killed": False,
        "api_hints": [],
        "notes": [],
        "elapsed_sec": 0.0,
    }

    path = Path(target)
    if not path.is_file():
        result["error"] = "ملف غير موجود: " + str(target) or target
        return result
    try:
        tr = path.resolve()
    except OSError as ex:
        result["error"] = f"مسار غير صالح: {ex}"
        return result
    result["target"] = str(tr)
    result["size"] = tr.stat().st_size if Path(str(tr)).exists() else 0

    t0 = time.perf_counter()
    cmd = [str(tr)]
    low = str(tr).lower()
    if low.endswith((".cmd", ".bat")):
        cmd = ["cmd", "/c", str(tr)]
    elif low.endswith(".ps1"):
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(tr)]
    cmd += list(args or [])

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(tr.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as ex:
        result["error"] = f"تعذّر الإطلاق: {ex}"
        return result

    pid = proc.pid
    ps = None
    try:
        import psutil  # lazy
        ps = psutil.Process(pid)
    except Exception:
        ps = None

    seen_files: set[str] = set()
    seen_conns: set[str] = set()
    seen_children: set[str] = set()
    peak_rss = 0
    peak_cpu = 0.0
    deadline = time.monotonic() + max(1.0, timeout)
    samplings = 0
    first_seen = None

    def sample() -> None:
        nonlocal peak_rss, peak_cpu, samplings, first_seen
        if ps is None:
            return
        try:
            samplings += 1
            if first_seen is None:
                first_seen = time.monotonic()
            rss = ps.memory_info().rss if hasattr(ps.memory_info(), "rss") else 0
            peak_rss = max(peak_rss, rss or 0)
            cpu = ps.cpu_percent(interval=None)
            peak_cpu = max(peak_cpu, cpu or 0.0)
            for f in ps.open_files():
                fp = _safe_name(f.path)
                if fp not in seen_files:
                    seen_files.add(fp)
                    result["touched_files"].append({"path": fp, "mode": getattr(f, "mode", "r")})
                    if len(result["touched_files"]) > _MAX_EVENTS_PER_KIND:
                        break
            for c in ps.net_connections(kind="inet"):
                laddr = c.laddr
                raddr = c.raddr
                conn = {
                    "fd": c.fd,
                    "family": str(c.family.name),
                    "type": str(c.type.name),
                    "status": c.status,
                    "laddr": f"{laddr.ip}:{laddr.port}" if laddr else "",
                    "raddr": f"{raddr.ip}:{raddr.port}" if raddr else "",
                }
                key = f"{conn['laddr']}-{conn['raddr']}-{conn['status']}"
                if key not in seen_conns:
                    seen_conns.add(key)
                    if conn["raddr"] or conn["status"] in ("ESTABLISHED", "SYN_SENT", "LISTEN"):
                        result["network_connections"].append(conn)
                        if len(result["network_connections"]) > _MAX_EVENTS_PER_KIND:
                            break
            for ch in ps.children(recursive=True):
                ck = str(ch.pid)
                if ck not in seen_children:
                    seen_children.add(ck)
                    try:
                        nm = ch.name()
                    except Exception:
                        nm = "?"
                    result["spawned_children"].append({"pid": ch.pid, "name": nm})
                    if len(result["spawned_children"]) > _MAX_EVENTS_PER_KIND:
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception:
            pass

    # حلقة المراقبة
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        sample()
        time.sleep(interval)
    if proc.poll() is None:
        result["timed_out"] = True
        result["killed"] = True
        # إيقاف شجرة العمليات
        if ps is not None:
            try:
                for ch in ps.children(recursive=True):
                    try:
                        ch.kill()
                    except Exception:
                        pass
            except Exception:
                pass
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    else:
        sample()

    try:
        out_b, err_b = proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        out_b, err_b = b"", b""
    result["exit_code"] = proc.returncode
    result["stdout_tail"] = (out_b or b"")[-_MAX_OUTPUT:].decode("utf-8", "replace")
    result["stderr_tail"] = (err_b or b"")[-_MAX_OUTPUT:].decode("utf-8", "replace")
    result["elapsed_sec"] = round(time.perf_counter() - t0, 3)

    if proc.returncode is not None and result["elapsed_sec"] <= _EARLY_EXIT_SEC:
        result["early_exit"] = True

    # ── الصياغة النهائية: الدرجة والحكم ──
    score = 0
    score += min(14, len(result["touched_files"]) * 2)
    score += min(24, len(result["network_connections"]) * 4)
    score += min(20, len(result["spawned_children"]) * 5)
    score += min(10, (peak_rss // (256 * 1024)))          # كل 256KB قمة ذاكرة
    score += 8 if result["early_exit"] else 0
    score += 12 if result["timed_out"] else 0            # رفض الإنهاء = تهرب

    api_hits = []
    api_score = 0
    try:
        strings = extract_ascii_strings(tr.read_bytes(), min_len=4)
    except OSError:
        strings = []
    for s in strings:
        for api, w in _API_HINTS:
            hay = s.lower()
            probe = api.lower()
            # تطابق مع تذييلات الاستدعاء الشائعة (A/W/Ex)
            if probe in hay or probe + "a" in hay or probe + "w" in hay or probe + "ex" in hay:
                api_score += w
                if api not in [h[0] for h in api_hits]:
                    api_hits.append((api, w))
                break
    result["api_hints"] = api_hits[:30]
    api_score = min(28, api_score)
    score = min(100, score + api_score)

    result["score"] = score
    result["memory_peak_bytes"] = peak_rss
    result["cpu_burst_percent"] = round(peak_cpu, 1)

    if score >= 75:
        result["verdict"] = "سلوك خطير — يُنصح بعزل الملف وعدم تشغيله"
        result["severity"] = "critical"
    elif score >= 50:
        result["verdict"] = "سلوك مشبوه — حلّل الحمولة قبل التنفيذ"
        result["severity"] = "high"
    elif score >= 25:
        result["verdict"] = "سلوك متوسط — مؤشرات مختلطة"
        result["severity"] = "medium"
    else:
        result["verdict"] = "سلوك هادئ نسبياً"
        result["severity"] = "low"

    result["notes"].append(
        "تتبع الريجستري غير مضمّن: استخدم Procmon/ETW لهذا البُعد."
    )
    if ps is None:
        result["notes"].append("psutil غير متاح — المراقبة محدودة (بدون ملفات/شبكة/أطفال).")
    result["ok"] = True
    return result
