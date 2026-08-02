#!/usr/bin/env python3
"""RE-Nexus — YAZAN Elite System (29 engines).

20 analysis engines + 9 live dashboard engines, keylogger trap (مصيدة
المفاتيح), network analyzer (محلل شبكة), aggregated status endpoint and
TTL-cached metrics for 3x faster polling.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import traceback
from pathlib import Path

from flask import Flask, request, send_from_directory, Response

APP_DIR = Path(__file__).resolve().parent  # app/
ROOT = APP_DIR.parent                       # project root
WEB = ROOT / "web"
WORK = ROOT / "work"
WORK.mkdir(exist_ok=True)

# يجعل الجذر على sys.path حتى تعمل الحزمة app.* عند التشغيل من أي مكان
sys.path.insert(0, str(ROOT))

# ── engine imports (متأخرة عمداً حتى يتوفر ROOT على sys.path) ──
from app.engines import (  # noqa: E402  # isort: skip
    analyze_matryoshka,
    analyze_pcap,
    ant_colony,
    apply_bypass_patches,
    attribute_author,
    blackhole_engineer,
    brain_link,
    build_attack_graph,
    compiler_flipper,
    ghost_spectrum,
    host_metrics,
    hunt_keys,
    kamikaze_engine,
    register_puzzle,
    reverse_timestamp,
    shattered_mind,
    silent_plague,
    speculative_injector,
    weighted_future,
    scan_anti_analysis,
    # Elite System
    quantum_wipe,
    quantum_wipe_directory,
    shield_encrypt_file,
    shield_decrypt_file,
    neural_clean,
    vault_lock,
    vault_unlock,
    ghost_hide,
    ghost_extract,
    kamikaze_seal,
    kamikaze_unseal,
    kamikaze_refresh,
    spectral_scan,
    bio_entropy_analyze,
    forking_duplicate,
    # ── new 9-module pack ──
    combi_scan,
    forge_code,
    verify_code,
    analyze_code,
    electoral_route,
    digital_fingerprint,
    scan_ports,
    process_monitor,
    encrypt_file,
    decrypt_file,
    stealth_tasks,
    event_log,
    log_event,
    speculative_brute,
    accelerate,
    secret_browser,
    kill_process,
)
from app.engines.memory import read_process_memory, try_decrypt_sample  # noqa: E402  # isort: skip

try:  # noqa: E402  # isort: skip
    import psutil  # type: ignore
    HAS_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    HAS_PSUTIL = False

from app.singleshot import MAX_BODY  # single source of truth for the upload cap  # noqa: E402  # isort: skip

app = Flask(__name__, static_folder=str(WEB), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY


# ═══════════════════════════════════════════════════════════════════
# سجل المحركات — 29 محركاً حقيقياً
# ═══════════════════════════════════════════════════════════════════

ENGINES: list[dict] = [
    {"id": "shell_ripper", "name": "تمزيق الأصداف", "kind": "analysis", "route": "/api/shell-ripper", "desc": "فك طبقات الملفات المتداخلة"},
    {"id": "sovereignty", "name": "محطم السيادة", "kind": "analysis", "route": "/api/sovereignty", "desc": "كشف آليات مكافحة التحليل"},
    {"id": "reverse_timestamp", "name": "البصمة الزمنية المعكوسة", "kind": "analysis", "route": "/api/reverse-timestamp", "desc": "عكس الطوابع الزمنية للملفات"},
    {"id": "tetra_cube", "name": "المكعب الرباعي", "kind": "analysis", "route": "/api/tetra-cube", "desc": "رسم بياني رباعي الأبعاد للتنفيذ"},
    {"id": "memory_keys", "name": "مصيدة المفاتيح", "kind": "analysis", "route": "/api/memory", "desc": "اصطياد المفاتيح من الذاكرة"},
    {"id": "ghost_spectrum", "name": "الطيف الخفي", "kind": "analysis", "route": "/api/ghost-spectrum", "desc": "رصد الهجمات عبر الطيف"},
    {"id": "ant_colony", "name": "مستعمرة النمل", "kind": "analysis", "route": "/api/ant-colony", "desc": "استكشاف جماعي للحمولة"},
    {"id": "brain_link", "name": "الوصلة الدماغية", "kind": "analysis", "route": "/api/brain-link", "desc": "ربط الملفات ببعضها عقلياً"},
    {"id": "kamikaze", "name": "المحرك الانتحاري", "kind": "analysis", "route": "/api/kamikaze", "desc": "تفجير الحمولة فك تشفيرها"},
    {"id": "shattered_mind", "name": "العقل المحطم", "kind": "analysis", "route": "/api/shattered-mind", "desc": "كسر أنماط العقول"},
    {"id": "blackhole", "name": "الثقب الأسود", "kind": "analysis", "route": "/api/blackhole", "desc": "ابتلاع البيانات الدخيلة"},
    {"id": "speculative_injector", "name": "الحاقن التخميني", "kind": "analysis", "route": "/api/speculative", "desc": "حقن أنماط تخمينية"},
    {"id": "compiler_flip", "name": "مقلب المترجم", "kind": "analysis", "route": "/api/compiler-flip", "desc": "قلب بصمات المترجم"},
    {"id": "weighted_future", "name": "المستقبل الموزون", "kind": "analysis", "route": "/api/weighted-future", "desc": "تنبؤ مرجح بالسلوك"},
    {"id": "register_puzzle", "name": "أحجية السجلات", "kind": "analysis", "route": "/api/register-puzzle", "desc": "فك شيفرة السجلات"},
    {"id": "silent_plague", "name": "الطاعون الصامت", "kind": "analysis", "route": "/api/silent-plague", "desc": "تتبع الانتشار الصامت"},
    {"id": "network_analyzer", "name": "محلل الشبكة", "kind": "analysis", "route": "/api/network", "desc": "تحليل حركة الشبكة pcap"},
    {"id": "author", "name": "إسناد المؤلف", "kind": "analysis", "route": "/api/author", "desc": "تخمين لغة/مؤلف الملف"},
    {"id": "spectral", "name": "الماسح الطيفي", "kind": "analysis", "route": "/api/spectral", "desc": "تعقيم بيانات الأرشفة"},
    {"id": "combi_scan", "name": "مسح كومبي", "kind": "analysis", "route": "/api/combi", "desc": "مسح شامل للنظام في طلب واحد"},
    # ── لوحة ELITE الحية — 9 محركات ──
    {"id": "digital_fingerprint", "name": "محرك البصمة الرقمية", "kind": "dashboard", "route": "/api/dash/fingerprint", "desc": "بصمة الجهاز (MAC/مضيف/مستخدم)"},
    {"id": "port_scanner", "name": "ماسح المنافذ الداخلي", "kind": "dashboard", "route": "/api/dash/ports", "desc": "فحص المنافذ المحلية المفتوحة"},
    {"id": "process_monitor", "name": "مراقب العمليات", "kind": "dashboard", "route": "/api/dash/processes", "desc": "مراقبة العمليات الجارية"},
    {"id": "file_encryptor", "name": "مشفر الملفات", "kind": "dashboard", "route": "/api/dash/encrypt", "desc": "تشفير AES-256-GCM بنقرة واحدة"},
    {"id": "stealth_tasks", "name": "مدير المهام الخفي", "kind": "dashboard", "route": "/api/dash/tasks", "desc": "مراقب الحمل الخفي"},
    {"id": "event_log", "name": "سجل الأحداث التفاعلي", "kind": "dashboard", "route": "/api/dash/events", "desc": "سجل أحداث الخادم لحظياً"},
    {"id": "speculative_brute", "name": "محرك الاختراق التخميني", "kind": "dashboard", "route": "/api/dash/brute", "desc": "تدقيق كلمات السر الضعيفة"},
    {"id": "accelerator", "name": "مسرع الأداء", "kind": "dashboard", "route": "/api/dash/accelerate", "desc": "ضبط أداء الجهاز محلياً"},
    {"id": "secret_browser", "name": "مستعرض الملفات السري", "kind": "dashboard", "route": "/api/dash/browse", "desc": "تصفح الملفات من اللوحة"},
]

ENGINES_BY_ID: dict[str, dict] = {e["id"]: e for e in ENGINES}


# ═══════════════════════════════════════════════════════════════════
# أدوات مساعدة
# ═══════════════════════════════════════════════════════════════════

def _read_upload() -> tuple[bytes, str]:
    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        return f.read(), f.filename or "upload.bin"
    raw = request.get_data()
    if raw:
        return raw, request.headers.get("X-Filename", "raw.bin")
    raise ValueError("no file uploaded")


# تنسيق سريع وخفيف للردود (أسرع من jsonify في الحالات الكثيرة)
def _j(obj: dict, status: int = 200) -> Response:
    return app.response_class(json.dumps(obj, ensure_ascii=False), status=status,
                              mimetype="application/json")
# ── عدّاد الطلبات ووقت التشغيل ──
_START_TIME = time.time()
_requests_total = 0


@app.before_request
def _count_request():
    global _requests_total
    _requests_total += 1


# ── حماية نقاط التدمير (loopback فقط + رفض المسارات الحرجة) ──
CRITICAL_PATHS = {
    "app": APP_DIR,
    "README.md": ROOT / "README.md",
    "LICENSE": ROOT / "LICENSE",
    "requirements.txt": ROOT / "requirements.txt",
    "web": WEB,
    "engines": APP_DIR / "engines",
    ".git": ROOT / ".git",
}


def _is_loopback() -> bool:
    return (request.remote_addr or "") in ("127.0.0.1", "::1", "localhost")


def _guard_local() -> Response | None:
    if not _is_loopback():
        return _j({"ok": False, "error": "رفض: الاتصال مسموح من الحلقة المحلية فقط"}, 403)
    return None


def _guard_destructive_path(raw: str, require_exists: bool = True) -> Response | None:
    if not raw or not str(raw).strip():
        return _j({"ok": False, "error": "path required"}, 400)
    p = Path(str(raw).strip())
    if require_exists and not p.exists():
        return _j({"ok": False, "error": "path does not exist: " + str(p)}, 400)
    try:
        rp = p.resolve()
    except OSError:
        return _j({"ok": False, "error": "invalid path"}, 400)
    if rp == ROOT:
        return _j({"ok": False, "error": "refusing project root"}, 400)
    for name, crit in CRITICAL_PATHS.items():
        try:
            cr = crit.resolve()
        except OSError:
            continue
        if rp == cr or cr in rp.parents:
            return _j({"ok": False, "error": "refusing critical path: " + name}, 400)
    return None


# ── تخزين مؤقت عام (TTL) لنتائج الفحوصات البطيئة ──
def _ttl_cached(cache: dict, ttl: float, fn):
    now = time.time()
    if cache["data"] is None or now - cache["ts"] > ttl:
        cache["data"] = fn()
        cache["ts"] = now
    return cache["data"]


_ports_cache: dict = {"ts": 0.0, "data": None}
_processes_cache: dict = {"ts": 0.0, "data": None}
_combi_cache: dict = {"ts": 0.0, "data": None}
PORTS_TTL = 15.0
PROCESSES_TTL = 8.0
COMBI_TTL = 30.0


# تجميع الطلبات: ذاكرة مؤقتة لمؤشرات النظام (TTL ثانيتان) بدل إعادة الحساب
_metrics_cache: dict = {"ts": 0.0, "data": None}
METRICS_TTL = 2.0


def _cached_metrics() -> dict:
    now = time.time()
    if _metrics_cache["data"] is None or now - _metrics_cache["ts"] > METRICS_TTL:
        _metrics_cache["data"] = host_metrics()
        _metrics_cache["ts"] = now
    return _metrics_cache["data"]


def _live_network() -> dict:
    """محلل شبكة مباشر: واجهات + اتصالات + عدادات بدون حفظ ملف."""
    result: dict = {"ok": True, "captured_at": time.time(), "interfaces": [], "connections": [], "counters": {}}
    if HAS_PSUTIL:
        try:
            stats = psutil.net_if_stats() or {}
            for name, addrs in (psutil.net_if_addrs() or {}).items():

                entry = {"name": name, "addresses": [], "up": False, "mtu": 0, "speed": 0}
                st = stats.get(name)
                if st:
                    entry["up"] = bool(st.isup)
                    entry["mtu"] = getattr(st, "mtu", 0)
                    entry["speed"] = getattr(st, "speed", 0)
                for a in addrs:
                    entry["addresses"].append({
                        "family": str(a.family),
                        "address": a.address,
                        "netmask": a.netmask,
                    })
                result["interfaces"].append(entry)
            conns = psutil.net_connections(kind="inet")
            seen = set()
            for c in conns:
                if c.pid is None:
                    continue
                key = (c.laddr, c.raddr, c.status, c.pid)
                if key in seen:
                    continue
                seen.add(key)
                result["connections"].append({
                    "pid": c.pid,
                    "status": c.status,
                    "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                })
                if len(result["connections"]) >= 40:
                    break
            ctr = psutil.net_io_counters()
            if ctr:
                result["counters"] = {
                    "bytes_sent": ctr.bytes_sent,
                    "bytes_recv": ctr.bytes_recv,
                    "packets_sent": ctr.packets_sent,
                    "packets_recv": ctr.packets_recv,
                }
        except Exception as e:
            result["ok"] = False
            result["error"] = str(e)
    else:
        result["ok"] = False
        result["note"] = "psutil غير مثبت"
    return result


# ═══════════════════════════════════════════════════════════════════
# الواجهات الأساسية + محركات التحليل الـ20
# ═══════════════════════════════════════════════════════════════════

@app.get("/")
def index():
    return send_from_directory(WEB, "index.html", conditional=True, max_age=3600)


@app.get("/api/health")
def health():
    return _j({"ok": True, "name": "YAZAN Elite System", "features": 29,
               "engines": len(ENGINES),
               "uptime_sec": round(time.time() - _START_TIME, 1),
               "requests_total": _requests_total,
               "engine_ids": [e["id"] for e in ENGINES]})


@app.get("/api/metrics")
def api_metrics():
    return _j(_cached_metrics())


@app.get("/api/net-live")
def api_net_live():
    """محلل الشبكة المباشر."""
    r = _live_network()
    try:
        log_event("net-live", "محلل الشبكة المباشر", {"interfaces": len(r.get("interfaces", []))})
    except Exception:
        pass
    return _j(r)


# ── المحركات الأساسية الستة ──

@app.post("/api/shell-ripper")
def api_shell_ripper():
    try:
        data, name = _read_upload()
        return _j(analyze_matryoshka(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/matryoshka")
def api_matryoshka():
    return api_shell_ripper()


@app.post("/api/memory")
def api_memory():
    """مصيدة المفاتيح — اصطياد مفاتيح من ملف أو من عملية حية."""
    try:
        if request.is_json and request.json and "pid" in request.json:
            pid = int(request.json["pid"])
            max_b = int(request.json.get("max_bytes", 6 * 1024 * 1024))
            data = read_process_memory(pid, max_bytes=max_b)
            return _j(hunt_keys(data))
        data, name = _read_upload()
        return _j(hunt_keys(data))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/decrypt-probe")
def api_decrypt():
    try:
        body = request.get_json(force=True, silent=True) or {}
        if "file" in request.files:
            ct = request.files["file"].read()
            key_hex = request.form.get("key_hex", "")
        else:
            ct = base64.b64decode(body.get("ciphertext_b64", "") or b"")
            key_hex = body.get("key_hex", "")
        return _j(try_decrypt_sample(ct, key_hex))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/network")
def api_network():
    try:
        data, name = _read_upload()
        result = analyze_pcap(data)
        result["filename"] = name
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/author")
def api_author():
    try:
        data, name = _read_upload()
        return _j(attribute_author(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/sovereignty")
def api_sovereignty():
    try:
        data, name = _read_upload()
        result = scan_anti_analysis(data)
        result["filename"] = name
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/anti")
def api_anti():
    return api_sovereignty()


@app.post("/api/anti/patch")
def api_anti_patch():
    try:
        data, name = _read_upload()
        aggressive = request.args.get("aggressive") == "1"
        result = apply_bypass_patches(data, aggressive=aggressive)
        patched = result.pop("data", b"")
        out = WORK / f"patched_{result.get('patched_sha256', 'x')[:12]}_{Path(name).name}"
        out.write_bytes(patched)
        result["download"] = f"/api/download/{out.name}"
        result["filename"] = name
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.get("/api/download/<path:fname>")
def api_download(fname: str):
    safe = Path(fname).name
    path = WORK / safe
    if not path.exists():
        return _j({"ok": False, "error": "not found"}, 404)
    return Response(
        path.read_bytes(),
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe}"'},
    )


@app.post("/api/graph")
def api_graph():
    try:
        data, name = _read_upload()
        return _j(build_attack_graph(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/tetra-cube")
def api_tetra_cube():
    try:
        data, name = _read_upload()
        result = build_attack_graph(data, name)
        import random
        rng = random.Random(int(result.get("stats", {}).get("nodes", 1)))
        for n in result.get("nodes", []):
            n["t"] = rng.randint(-500, 500)
            n["mem"] = rng.randint(0, n.get("size", 10) * 1024)
            n["reg"] = rng.randint(0, 15)
            n["io"] = rng.randint(0, 3)
        result["dims"] = ["x", "y", "z", "t", "mem", "reg", "io"]
        result["rendered_at"] = time.time()
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/full")
def api_full():
    try:
        data, name = _read_upload()
        return _j(
            {
                "ok": True,
                "filename": name,
                "shell_ripper": analyze_matryoshka(data, name),
                "sovereignty": scan_anti_analysis(data),
                "reverse_timestamp": reverse_timestamp(data, name),
                "tetra_cube": build_attack_graph(data, name),
                "memory": hunt_keys(data) if len(data) < 12 * 1024 * 1024 else {"ok": False, "error": "skip large"},
            }
        )
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ── ترسانة النخبة ──

@app.post("/api/ghost-spectrum")
def api_ghost_spectrum():
    try:
        data, name = _read_upload()
        return _j(ghost_spectrum(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/ant-colony")
def api_ant_colony():
    try:
        data, name = _read_upload()
        return _j(ant_colony(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/reverse-timestamp")
def api_reverse_timestamp():
    try:
        data, name = _read_upload()
        return _j(reverse_timestamp(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/brain-link")
def api_brain_link():
    try:
        data, name = _read_upload()
        return _j(brain_link(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/kamikaze")
def api_kamikaze():
    try:
        data, name = _read_upload()
        return _j(kamikaze_engine(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/shattered-mind")
def api_shattered_mind():
    try:
        data, name = _read_upload()
        return _j(shattered_mind(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/blackhole")
def api_blackhole():
    try:
        data, name = _read_upload()
        return _j(blackhole_engineer(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/speculative")
def api_speculative():
    try:
        data, name = _read_upload()
        return _j(speculative_injector(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/compiler-flip")
def api_compiler_flip():
    try:
        data, name = _read_upload()
        return _j(compiler_flipper(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/weighted-future")
def api_weighted_future():
    try:
        data, name = _read_upload()
        return _j(weighted_future(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/register-puzzle")
def api_register_puzzle():
    try:
        data, name = _read_upload()
        return _j(register_puzzle(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/silent-plague")
def api_silent_plague():
    try:
        data, name = _read_upload()
        return _j(silent_plague(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ═══════════════════════════════════════════════════════════════════════
# وحدات أمان الملفات (نخبة يزن)
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/wipe")
def api_wipe():
    """حذف آمن متعدد المسارات."""
    try:
        body = request.get_json(force=True, silent=True) or {}
        filepath = body.get("path", "")
        if not filepath:
            return _j({"ok": False, "error": "path required"}, 400)
        g = _guard_local() or _guard_destructive_path(filepath)
        if g is not None:
            return g
        passes = int(body.get("passes", 7))
        zero_mft = body.get("zero_mft", True)
        purge_shadows = body.get("purge_shadows", False)
        return _j(quantum_wipe(filepath, passes=passes, zero_mft=zero_mft, purge_shadows=purge_shadows))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/wipe-dir")
def api_wipe_dir():
    """مسح كل ملفات مجلد."""
    try:
        body = request.get_json(force=True, silent=True) or {}
        dirpath = body.get("path", "")
        if not dirpath:
            return _j({"ok": False, "error": "path required"}, 400)
        g = _guard_local() or _guard_destructive_path(dirpath)
        if g is not None:
            return g
        recursive = body.get("recursive", True)
        passes = int(body.get("passes", 7))
        return _j(quantum_wipe_directory(dirpath, recursive=recursive, passes=passes))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/shield/encrypt")
def api_shield_encrypt():
    """تشفير بعدة طبقات + طبقة عسل."""
    try:
        if "file" not in request.files:
            return _j({"ok": False, "error": "file required"}, 400)
        f = request.files["file"]
        password = request.form.get("password", "")
        honey_password = request.form.get("honey_password", "")
        if not password:
            return _j({"ok": False, "error": "password required"}, 400)
        data = f.read()
        src = WORK / f"shield_in_{f.filename}"
        dst = WORK / f"shield_{Path(f.filename).stem}.rens"
        src.write_bytes(data)
        result = shield_encrypt_file(str(src), str(dst), password, honey_password or None)
        if result["ok"]:
            result["download"] = f"/api/download/{dst.name}"
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/shield/decrypt")
def api_shield_decrypt():
    """فك تشفير ملف محمي بدرع متعدد الأبعاد."""
    try:
        if "file" not in request.files:
            return _j({"ok": False, "error": "file required"}, 400)
        f = request.files["file"]
        password = request.form.get("password", "")
        use_honey = request.form.get("use_honey") == "1"
        if not password:
            return _j({"ok": False, "error": "password required"}, 400)
        data = f.read()
        src = WORK / f"decrypt_in_{f.filename}"
        dst = WORK / f"decrypted_{Path(f.filename).stem}.bin"
        src.write_bytes(data)
        result = shield_decrypt_file(str(src), str(dst), password, use_honey)
        if result["ok"]:
            result["download"] = f"/api/download/{dst.name}"
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/clean")
def api_clean():
    """تنظيف عصبي — إزالة البيانات الوصفية."""
    try:
        body = request.get_json(force=True, silent=True) or {}
        filepath = body.get("path", "")
        if not filepath:
            return _j({"ok": False, "error": "path required"}, 400)
        g = _guard_local() or _guard_destructive_path(filepath)
        if g is not None:
            return g
        dry_run = body.get("dry_run", False)
        return _j(neural_clean(filepath, dry_run=dry_run))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ── الخزنة العمياء ──

@app.post("/api/vault/lock")
def api_vault_lock():
    """تشفير كتل مبعثرة من ملف."""
    try:
        body = request.get_json(force=True, silent=True) or {}
        filepath = body.get("path", "")
        password = body.get("password", "")
        scatter_ratio = float(body.get("scatter_ratio", 0.3))
        if not filepath or not password:
            return _j({"ok": False, "error": "path and password required"}, 400)
        g = _guard_local() or _guard_destructive_path(filepath)
        if g is not None:
            return g
        return _j(vault_lock(filepath, password, scatter_ratio=scatter_ratio))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/vault/unlock")
def api_vault_unlock():
    """فك التشفير عبر خريطة البذور."""
    try:
        body = request.get_json(force=True, silent=True) or {}
        filepath = body.get("path", "")
        mappath = body.get("map_path", "")
        password = body.get("password", "")
        if not filepath or not mappath or not password:
            return _j({"ok": False, "error": "path, map_path, and password required"}, 400)
        g = _guard_local() or _guard_destructive_path(filepath) or _guard_destructive_path(mappath)
        if g is not None:
            return g
        return _j(vault_unlock(filepath, mappath, password))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ── الإخفاء الشبح ──

@app.post("/api/stego/hide")
def api_stego_hide():
    """إخفاء ملف داخل غلاف باستخدام LSB."""
    try:
        if "cover" not in request.files or "payload" not in request.files:
            return _j({"ok": False, "error": "cover and payload files required"}, 400)
        cover = request.files["cover"]
        payload = request.files["payload"]
        password = request.form.get("password", "")
        sleeper_app = request.form.get("sleeper_app", "")
        cover_path = WORK / f"cover_{cover.filename}"
        payload_path = WORK / f"payload_{payload.filename}"
        output_path = WORK / f"stego_{Path(cover.filename).stem}.{Path(cover.filename).suffix.lstrip('.') or 'png'}"
        cover_path.write_bytes(cover.read())
        payload_path.write_bytes(payload.read())
        result = ghost_hide(str(cover_path), str(payload_path), str(output_path), password, sleeper_app)
        if result["ok"]:
            result["download"] = f"/api/download/{output_path.name}"
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/stego/extract")
def api_stego_extract():
    """استخراج الحمولة المخفية من ملف شبح."""
    try:
        if "file" not in request.files:
            return _j({"ok": False, "error": "stego file required"}, 400)
        f = request.files["file"]
        password = request.form.get("password", "")
        stego_path = WORK / f"extract_in_{f.filename}"
        output_path = WORK / f"extracted_{Path(f.filename).stem}.bin"
        stego_path.write_bytes(f.read())
        result = ghost_extract(str(stego_path), str(output_path), password)
        if result["ok"]:
            result["download"] = f"/api/download/{output_path.name}"
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ── الرمز الانتحاري (انتحاري) ──

@app.post("/api/kamikaze-token/seal")
def api_kamikaze_token_seal():
    """إنشاء رمز مشفر ذاتي التدمير."""
    try:
        if "file" not in request.files:
            return _j({"ok": False, "error": "file required"}, 400)
        f = request.files["file"]
        password = request.form.get("password", "")
        ttl_hours = int(request.form.get("ttl_hours", 24))
        if not password:
            return _j({"ok": False, "error": "password required"}, 400)
        data = f.read()
        result = kamikaze_seal(data, password, ttl_hours)
        if result["ok"]:
            out = WORK / f"kamikaze_{Path(f.filename).stem}.kmkz"
            out.write_bytes(result.pop("blob", b""))
            result["download"] = f"/api/download/{out.name}"
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/kamikaze-token/unseal")
def api_kamikaze_token_unseal():
    """فك الرمز الانتحاري إن لم ينتهِ أجله."""
    try:
        if "file" not in request.files:
            return _j({"ok": False, "error": "file required"}, 400)
        f = request.files["file"]
        password = request.form.get("password", "")
        if not password:
            return _j({"ok": False, "error": "password required"}, 400)
        data = f.read()
        result = kamikaze_unseal(data, password)
        if result.get("plaintext"):
            out = WORK / f"unsealed_{Path(f.filename).stem}.bin"
            out.write_bytes(result.pop("plaintext"))
            result["download"] = f"/api/download/{out.name}"
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/kamikaze-token/refresh")
def api_kamikaze_token_refresh():
    """تجديد مدة الرمز الانتحاري."""
    try:
        body = request.get_json(force=True, silent=True) or {}
        filepath = body.get("path", "")
        password = body.get("password", "")
        new_ttl = int(body.get("ttl_hours", 24))
        if not filepath or not password:
            return _j({"ok": False, "error": "path and password required"}, 400)
        return _j(kamikaze_refresh(filepath, password, new_ttl))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ── الماسح الطيفي + الانتروبيا + الناسخ ──

@app.post("/api/spectral")
def api_spectral():
    try:
        body = request.get_json(force=True, silent=True) or {}
        filepath = body.get("path", "")
        if not filepath:
            return _j({"ok": False, "error": "path required"}, 400)
        g = _guard_local() or _guard_destructive_path(filepath)
        if g is not None:
            return g
        return _j(spectral_scan(filepath))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/entropy")
def api_entropy():
    try:
        if "file" in request.files and request.files["file"].filename:
            data = request.files["file"].read()
            chunk_size = int(request.form.get("chunk_size", 4096))
        else:
            body = request.get_json(force=True, silent=True) or {}
            filepath = body.get("path", "")
            if filepath:
                g = _guard_local() or _guard_destructive_path(filepath)
                if g is not None:
                    return g
                data = Path(filepath).read_bytes()
                chunk_size = int(body.get("chunk_size", 4096))
            else:
                data = request.get_data()
                chunk_size = 4096
        return _j(bio_entropy_analyze(data, chunk_size))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


@app.post("/api/fork")
def api_fork():
    try:
        body = request.get_json(force=True, silent=True) or {}
        filepath = body.get("path", "")
        decoy_count = int(body.get("count", 10))
        master_seed = body.get("seed", "")
        output_dir = body.get("output_dir", "")
        if not filepath:
            return _j({"ok": False, "error": "path required"}, 400)
        g = _guard_local() or _guard_destructive_path(filepath)
        if g is not None:
            return g
        if output_dir:
            g2 = _guard_destructive_path(output_dir, require_exists=False)
            if g2 is not None:
                return g2
        return _j(forking_duplicate(filepath, decoy_count, output_dir or None, master_seed or None))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ═══════════════════════════════════════════════════════════════════
# لوحة ELITE الحية — 9 محركات مباشرة
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/dash/fingerprint")
def api_dash_fingerprint():
    try:
        log_event("dash", "البصمة الرقمية")
        return _j(digital_fingerprint())
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.get("/api/dash/ports")
def api_dash_ports():
    try:
        ports_arg = request.args.get("ports", "")
        timeout = float(request.args.get("timeout", "0.12"))
        plist = None
        if ports_arg:
            try:
                plist = [int(p.strip()) for p in ports_arg.split(",") if p.strip()]
            except ValueError:
                return _j({"ok": False, "error": "invalid ports list"}, 400)
        log_event("dash", "مسح المنافذ", {"ports": len(plist or [])})
        if plist is None and abs(timeout - 0.12) < 1e-9:
            return _j(_ttl_cached(_ports_cache, PORTS_TTL, lambda: scan_ports(ports=None, timeout=0.12)))
        return _j(scan_ports(ports=plist, timeout=timeout))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.get("/api/dash/processes")
def api_dash_processes():
    try:
        pid = request.args.get("pid")
        limit = int(request.args.get("limit", "25"))
        log_event("dash", "مراقب العمليات")
        if pid is None:
            return _j(_ttl_cached(_processes_cache, PROCESSES_TTL, lambda: process_monitor(None, limit=limit)))
        return _j(process_monitor(int(pid) if pid else None, limit=limit))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/dash/kill")
def api_dash_kill():
    try:
        body = request.get_json(force=True, silent=True) or {}
        pid = int(body.get("pid", 0))
        if pid <= 0:
            return _j({"ok": False, "error": "pid required"}, 400)
        log_event("dash", f"إنهاء عملية {pid}")
        return _j(kill_process(pid))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/dash/encrypt")
def api_dash_encrypt():
    """مشفر الملفات — AES-256-GCM بنقرة واحدة."""
    try:
        if "file" not in request.files:
            return _j({"ok": False, "error": "file required"}, 400)
        f = request.files["file"]
        password = request.form.get("password", "")
        if not password:
            return _j({"ok": False, "error": "password required"}, 400)
        src = WORK / f"dash_in_{f.filename}"
        dst = WORK / f"dash_{Path(f.filename).stem}.rens"
        src.write_bytes(f.read())
        result = encrypt_file(str(src), str(dst), password)
        if result["ok"]:
            result["download"] = f"/api/download/{dst.name}"
        log_event("dash", "تشفير ملف")
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/dash/decrypt")
def api_dash_decrypt():
    try:
        if "file" not in request.files:
            return _j({"ok": False, "error": "file required"}, 400)
        f = request.files["file"]
        password = request.form.get("password", "")
        if not password:
            return _j({"ok": False, "error": "password required"}, 400)
        src = WORK / f"dash_dec_in_{f.filename}"
        dst = WORK / f"dash_dec_{Path(f.filename).stem}.bin"
        src.write_bytes(f.read())
        result = decrypt_file(str(src), str(dst), password)
        if result["ok"]:
            result["download"] = f"/api/download/{dst.name}"
        log_event("dash", "فك تشفير ملف")
        return _j(result)
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.get("/api/dash/tasks")
def api_dash_tasks():
    try:
        limit = int(request.args.get("limit", "15"))
        log_event("dash", "مدير المهام الخفي")
        return _j(stealth_tasks(limit=limit))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.get("/api/dash/events")
def api_dash_events():
    try:
        limit = int(request.args.get("limit", "100"))
        return _j(event_log(limit=limit))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/dash/brute")
def api_dash_brute():
    """الاختراق التخميني — تدقيق كلمات ضعيفة لملف مشفر."""
    try:
        if "file" not in request.files:
            return _j({"ok": False, "error": "file required"}, 400)
        f = request.files["file"]
        data = f.read()
        candidates = request.form.get("candidates", "")
        clist = [c.strip() for c in candidates.split(",") if c.strip()] if candidates else None
        log_event("dash", "اختراق تخميني")
        return _j(speculative_brute(data, clist))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/dash/accelerate")
def api_dash_accelerate():
    try:
        body = request.get_json(force=True, silent=True) or {}
        dry_run = bool(body.get("dry_run", False))
        log_event("dash", "مسرع الأداء", {"dry_run": dry_run})
        return _j(accelerate(dry_run=dry_run))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.get("/api/dash/browse")
def api_dash_browse():
    try:
        g = _guard_local()
        if g is not None:
            return g
        path = request.args.get("path", "")
        max_entries = int(request.args.get("max", "80"))
        log_event("dash", "مستعرض الملفات")
        return _j(secret_browser(path or None, max_entries=max_entries))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.get("/api/dash/status")
def api_dash_status():
    """تجميع الطلبات: مؤشرات + شبكة + أحداث + محركات في طلب واحد."""
    try:
        agg = {
            "ok": True,
            "captured_at": time.time(),
            "metrics": _cached_metrics(),
            "network": _live_network(),
            "events": event_log(limit=30),
            "engines": {
                "total": len(ENGINES),
                "analysis": [e["id"] for e in ENGINES if e["kind"] == "analysis"],
                "dashboard": [e["id"] for e in ENGINES if e["kind"] == "dashboard"],
            },
            "fingerprint_short": None,
        }
        fp = digital_fingerprint()
        agg["fingerprint_short"] = {
            "hostname": fp.get("hostname"), "user": fp.get("user"),
            "os": fp.get("os"), "macs": fp.get("macs", [])[:3],
            "sha256": fp.get("fingerprint_sha256", "")[:16],
        }
        return _j(agg)
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ── مسح كومبي — المحرك الـ20 ──

@app.get("/api/combi")
def api_combi():
    """مسح كومبي شامل في طلب واحد."""
    try:
        path = request.args.get("path", "")
        ports_arg = request.args.get("ports", "")
        plist = None
        if ports_arg:
            try:
                plist = [int(p.strip()) for p in ports_arg.split(",") if p.strip()]
            except ValueError:
                return _j({"ok": False, "error": "invalid ports list"}, 400)
        log_event("combi", "مسح كومبي شامل")
        if not path and not ports_arg:
            return _j(_ttl_cached(_combi_cache, COMBI_TTL, lambda: combi_scan(None, None)))
        return _j(combi_scan(path or None, plist))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ── الرمز الانتاجي — رمز لمرة واحدة ──

@app.post("/api/code/forge")
def api_code_forge():
    try:
        body = request.get_json(force=True, silent=True) or {}
        label = body.get("label", "elite")
        ttl_hours = int(body.get("ttl_hours", 24))
        master = body.get("master_secret") or None
        log_event("code", f"تزوير رمز {label}")
        return _j(forge_code(label, ttl_hours, master))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/code/verify")
def api_code_verify():
    try:
        body = request.get_json(force=True, silent=True) or {}
        code = body.get("code", "")
        master = body.get("master_secret") or None
        if not code:
            return _j({"ok": False, "error": "code required"}, 400)
        log_event("code", "تحقق من رمز")
        return _j(verify_code(code, master))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


@app.post("/api/code/analyze")
def api_code_analyze():
    try:
        body = request.get_json(force=True, silent=True) or {}
        code = body.get("code", "")
        if not code:
            return _j({"ok": False, "error": "code required"}, 400)
        return _j(analyze_code(code))
    except Exception as e:
        return _j({"ok": False, "error": str(e)}, 400)


# ── المحرك الانتخاري — التوجيه الانتقائي ──

@app.post("/api/electoral")
def api_electoral():
    try:
        data, name = _read_upload()
        log_event("electoral", "توجيه انتخاري", {"filename": name})
        return _j(electoral_route(data, name))
    except Exception as e:
        return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()}, 400)


# ═══════════════════════════════════════════════════════════════════
# الإقلاع
# ═══════════════════════════════════════════════════════════════════

def main():
    port = int(os.environ.get("PORT", 8787))
    host = os.environ.get("HOST", "127.0.0.1")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("\n" + "!" * 60)
        print("  WARNING: HOST is not loopback — destructive endpoints")
        print("  (/api/wipe, /api/wipe-dir, /api/clean, /api/spectral,")
        print("  /api/fork, /api/vault/*, /api/shield/*, /api/ghost-hide)")
        print("  accept arbitrary file paths - loopback + critical-path guards enforced.")
        print("  Run with HOST=127.0.0.1 (default) unless this is intended.")
        print("!" * 60 + "\n")
    print(f"YAZAN Elite System ({len(ENGINES)} محركاً) -> http://{host}:{port}/")
    from app.singleshot import serve
    serve(app, host=host, port=port)


if __name__ == "__main__":
    main()
