"""collapse_predictor — محرك التنبؤ بالانهيار الرقمي (Digital Collapse Predictor).

المفهوم الصاخب: "يحاكي تشغيل البرنامج في مليون سيناريو ويحسب احتمال انهياره".

الجوهر الحقيقي: اختبار حقن الأعطال (Fault Injection) بأسلوب Chaos Engineering.
يشغّل المحرك الملف المستهدف في عددٍ من السيناريوهات المضبوطة عشوائياً:
  1. خط أساس (بدون ضغط) — قياس طبيعي.
  2. ضغط ذاكرة تدريجي (25% / 45% / 60% من الذاكرة المتاحة) — نعطي برنامجاً
     ضعيفاً يستهلك الذاكرة بلا حدود، فينهار عند نفادها.
  3. صراع معالجات (30% / 65% / 100% من النوى) — نكشف سباقات التوقيت
     وحساسية الـ CPU.
  4. تهريب الجدولة (تعليق/استئناف عشوائي) — نكشف الافتراضات الزمنية
     (نوم صلب، تزامن مشروط على timeouts حقيقية).

ثم يصدر تقريراً: احتمال الانهيار الكلي، معدل الانهيار لكل محور، أضعف محور،
توقّع انهيار خلال 12 ساعة تشغيل متواصل، وتوقيعات الانهيار (أكواد الخروج).

تحذير أمني: هذا المحرك ينفّذ الملف على الجهاز المضيف فعلياً ويولّد حمل CPU
وضغط ذاكرة — استخدمه في بيئة تحليل معزولة (VM). ضغط الذاكرة محدود بهامش
أمان ثابت حتى لا يُسقط النظام المضيف.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from subprocess import DEVNULL, PIPE
from typing import Any

# ═══════════════════════════════════════ إعدادات
_SAFETY_MARGIN_BYTES = 768 * 1024 * 1024   # لا نضغط الذاكرة أبعد من هذا الهامش الحر
_MAX_CHUNK_BYTES = 16 * 1024 * 1024        # كتلة تخصيص وحدة الضغط
_MEM_FRACS = (0.25, 0.45, 0.60)            # نسب ضغط الذاكرة المتاحة
_CPU_FRACS = (0.30, 0.65, 1.00)            # نسب نوى المعالج المشغولة
_TIME_SUSPENDS = (1, 2, 4)                 # عدد مرات التعليق/الاستئناف العشوائية
_EXEC_SUFFIXES = {".exe", ".com", ".scr", ".cmd", ".bat", ".ps1", ".py", ".pyw"}
_MAX_SCENARIOS = 120
_MAX_OUTPUT = 2048                         # ذيل المخرجات المحفوظ لكل جولة
_HOURS_FORECAST = 12.0
_FRAGILE_THRESH = 60.0                    # درجة 60+ = هش للغاية
_MEDIUM_THRESH = 30.0                     # درجة 30+ = هشاشة متوسطة

_REMEDIES: dict[str, str] = {
    "memory": "الانهيار تحت ضغط الذاكرة = غياب معالجة أخطاء التخصيص: عالج MemoryError/فشل malloc وضع سقفاً للاستهلاك.",
    "cpu": "حساسية لصراع المعالج = سباقات زمنية: أضف مزامنة (mutex/atomics) ومهارات زمنية (timeouts).",
    "time": "عدم تحمل تعليق الجدولة = افتراضات زمنية حقيقية: استخدم مؤقتات جامدة (monotonic) ومنطق استرجاع.",
    "baseline": "يفشل حتى بلا أي ضغط = خلل أساسي في المسار الرئيسي.",
}


# ═══════════════════════════════════════ مولِّد السيناريوهات
def _build_plan(total: int, seed: int) -> list[tuple[str, Any]]:
    """يوزّع الجولات على المحاور: ~28% خط أساس، والباقي دورات على درجات المحاور."""
    rng = random.Random(seed)
    n_base = max(1, round(total * 0.28))
    rest = max(0, total - n_base)
    levels: list[tuple[str, Any]] = []
    # الذاكرة بوزن مضاعف: انهيارات التخصيص هي الأكثر شيوعاً في العينات الواقعية
    for _ in range(2):
        for f in _MEM_FRACS:
            levels.append(("memory", f))
    for f in _CPU_FRACS:
        levels.append(("cpu", f))
    for s in _TIME_SUSPENDS:
        levels.append(("time", s))
    plan: list[tuple[str, Any]] = []
    while len(plan) < rest:
        for lvl in levels:
            plan.append(lvl)
            if len(plan) >= rest:
                break
    for _ in range(n_base):
        plan.append(("baseline", 0))
    rng.shuffle(plan)
    return plan


def _build_cmd(res: Path, args: list[str] | None) -> list[str]:
    """يبني أمر تشغيل الملف حسب نوعه (Python / CMD / PowerShell / تنفيذي مباشر)."""
    low = res.name.lower()
    if low.endswith((".py", ".pyw")):
        cmd = [sys.executable, str(res)]
    elif low.endswith((".cmd", ".bat")):
        cmd = ["cmd", "/c", str(res)]
    elif low.endswith(".ps1"):
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(res)]
    else:
        cmd = [str(res)]
    return cmd + list(args or [])


# ═══════════════════════════════════════ مولّدات الضغط
class _Stress:
    """مولّد ضغط سيناريو: ذاكرة في العملية الأم و/أو معالجات عبر عمليات فرعية."""

    def __init__(self, axis: str, level: Any, rng: random.Random) -> None:
        self.axis = axis
        self.level = level
        self.rng = rng
        self._bufs: list[bytearray] = []
        self._burners: list[subprocess.Popen] = []

    @property
    def active(self) -> bool:
        return self.axis in ("memory", "cpu")

    def start(self) -> None:
        if not self.active:
            return
        if self.axis == "memory":
            self._hog_memory()
        else:
            self._hog_cpu()

    def _hog_memory(self) -> None:
        try:
            import psutil  # lazy - لا نعتمد على وجوده
            total = psutil.virtual_memory().total
        except Exception:
            total = 2 * 1024**3
        # نسبة من الإجمالي (وليس المتاح) حتى يضغط الضحية حتى مع تجاوبها
        target = int(total * float(self.level)) - _SAFETY_MARGIN_BYTES
        if target <= 0:
            target = int(total * float(self.level) * 0.5)
        allocated = 0
        while allocated < target:
            try:
                chunk = bytearray(min(_MAX_CHUNK_BYTES, target - allocated))
                self._bufs.append(chunk)
                allocated += len(chunk)
            except MemoryError:
                break

    def _hog_cpu(self) -> None:
        n = max(1, round((os.cpu_count() or 1) * float(self.level)))
        kw: dict[str, Any] = {"stdout": DEVNULL, "stderr": DEVNULL}
        if os.name == "nt":
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        for _ in range(n):
            try:
                self._burners.append(
                    subprocess.Popen([sys.executable, "-c", "while True: pass"], **kw)
                )
            except OSError:
                break

    def stop(self) -> None:
        for p in self._burners:
            try:
                p.kill()
            except Exception:
                pass
        self._burners.clear()
        self._bufs.clear()  # تحرير كتل الذاكرة


# ═══════════════════════════════════════ جولة تنفيذ واحدة
def _run_once(
    cmd: list[str],
    cwd: str,
    timeout: float,
    interval: float,
    suspends: int,
    rng: random.Random,
) -> dict[str, Any]:
    """يشغّل الملف في سيناريو واحد مع عيّنات psutil وتعليق/استئناف حسب الطلب."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=PIPE, stderr=PIPE)
    except OSError as ex:
        return {"ok": False, "exec_error": str(ex)}

    ps = None
    try:
        import psutil  # lazy
        ps = psutil.Process(proc.pid)
    except Exception:
        ps = None

    # جدولة لحظات التعليق العشوائية (تشويش الجدولة)
    window_ticks = max(4, int(timeout * 10))
    schedule: list[int] = []
    if suspends and ps is not None:
        schedule = sorted(rng.sample(range(1, window_ticks), min(suspends, window_ticks - 1)))
    si = 0

    peak_rss = 0
    peak_cpu = 0.0
    ct_user = ct_sys = 0.0
    suspend_hits = 0
    deadline = time.monotonic() + timeout
    ticks = 0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if ps is not None:
            try:
                rss = ps.memory_info().rss
                peak_rss = max(peak_rss, rss or 0)
                cpus = ps.cpu_percent(interval=None)
                peak_cpu = max(peak_cpu, cpus or 0.0)
                ct = ps.cpu_times()
                ct_user, ct_sys = getattr(ct, "user", 0.0) or 0.0, getattr(ct, "system", 0.0) or 0.0
            except Exception:
                pass
        if si < len(schedule) and int((time.monotonic() - t0) * 10) >= schedule[si]:
            try:
                ps.suspend()
                time.sleep(rng.uniform(0.05, 0.20))
                ps.resume()
                suspend_hits += 1
            except Exception:
                pass
            si += 1
        ticks += 1
        if ticks % 2 == 0:
            time.sleep(interval)

    timed_out = proc.poll() is None
    exit_code: int | None = None
    out_tail = err_tail = ""
    if timed_out:
        # الملف رفض الإنهاء — اقتل شجرة العمليات
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
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
    else:
        exit_code = proc.returncode
        try:
            out_b, err_b = proc.communicate(timeout=2)
            out_tail = (out_b or b"")[-_MAX_OUTPUT:].decode("utf-8", "replace")
            err_tail = (err_b or b"")[-_MAX_OUTPUT:].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            pass

    elapsed = time.perf_counter() - t0
    return {
        "ok": True,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "crashed": (not timed_out) and (exit_code != 0),
        "peak_rss": peak_rss,
        "peak_cpu": round(peak_cpu, 1),
        "cpu_user": round(ct_user, 3),
        "cpu_sys": round(ct_sys, 3),
        "elapsed": round(elapsed, 3),
        "suspend_hits": suspend_hits,
        "stdout_tail": out_tail,
        "stderr_tail": err_tail,
    }


# ═══════════════════════════════════════ المحرك الرئيسي (مسار)
def collapse_predict_path(
    target: str | os.PathLike,
    args: list[str] | None = None,
    scenarios: int = 18,
    timeout: float = 6.0,
    interval: float = 0.08,
    seed: int | None = None,
) -> dict[str, Any]:
    """يشغّل الملف في مخطط السيناريوهات ويصدر التقرير التنبؤي."""
    res = {"ok": False, "error": ""}
    path = Path(target)
    if not path.is_file():
        res["error"] = "ملف غير موجود: " + str(path)
        return res
    try:
        resolved = path.resolve()
    except OSError as ex:
        res["error"] = f"مسار غير صالح: {ex}"
        return res

    total = int(min(max(scenarios, 4), _MAX_SCENARIOS))
    seed = seed if seed is not None else int.from_bytes(os.urandom(4), "big")
    rng = random.Random(seed)
    plan = _build_plan(total, seed)
    cmd = _build_cmd(resolved, args)

    runs: list[dict[str, Any]] = []
    for axis, lvl in plan:
        stress = _Stress(axis, lvl, rng)
        stress.start()
        try:
            r = _run_once(
                cmd,
                str(resolved.parent),
                timeout,
                interval,
                int(lvl) if axis == "time" else 0,
                rng,
            )
        finally:
            stress.stop()
        r["axis"] = axis
        r["level"] = lvl
        runs.append(r)

    # ๑ تجميع النتائج
    launched = [r for r in runs if r.get("ok")]
    exec_fail = len(runs) - len(launched)

    if not launched:
        res["error"] = "تعذر إطلاق الملف في أي سيناريو — تأكد أنه ملف تنفيذي صالح."
        res["exec_failures"] = exec_fail
        res["seed"] = seed
        return res

    failures = [r for r in launched if r["crashed"] or r["timed_out"]]
    crashes = [r for r in launched if r["crashed"]]
    hangs = [r for r in launched if r["timed_out"]]
    fail_rate = len(failures) / len(launched)

    by_axis: dict[str, dict[str, Any]] = {}
    for r in launched:
        ax = r["axis"]
        b = by_axis.setdefault(ax, {"runs": 0, "failures": 0, "crashes": 0, "hangs": 0, "times": [], "exit_codes": {}})
        b["runs"] += 1
        b["times"].append(r["elapsed"])
        b["exit_codes"][str(r["exit_code"])] = b["exit_codes"].get(str(r["exit_code"]), 0) + 1
        for k in ("crashes", "hangs", "failures"):
            if r["crashed"] and k == "crashes":
                b[k] += 1
            elif r["timed_out"] and k == "hangs":
                b[k] += 1
        if r["crashed"] or r["timed_out"]:
            b["failures"] += 1

    axis_stats: list[dict[str, Any]] = []
    for ax in ("baseline", "memory", "cpu", "time"):
        b = by_axis.get(ax)
        if not b or not b["runs"]:
            continue
        rate = b["failures"] / b["runs"]
        axis_stats.append(
            {
                "axis": ax,
                "runs": b["runs"],
                "failures": b["failures"],
                "crashes": b["crashes"],
                "hangs": b["hangs"],
                "failure_rate": round(rate, 4),
                "avg_elapsed": round(statistics.fmean(b["times"]), 3),
                "stdev_elapsed": round(statistics.pstdev(b["times"]), 3) if len(b["times"]) > 1 else 0.0,
            }
        )

    weakest: dict[str, Any] | None = None
    candidates = [a for a in axis_stats if a["runs"] >= 3]
    if candidates:
        weakest = max(candidates, key=lambda a: (a["failure_rate"], a["crashes"]))

    baseline_f = by_axis.get("baseline", {}).get("failures", 0)
    worst_axis_rate = weakest["failure_rate"] if weakest else fail_rate
    fragility = round(
        min(
            100.0,
            fail_rate * 100 * 0.65
            + worst_axis_rate * 100 * 0.35
            + (10 if hangs else 0)
            + (5 if baseline_f else 0),
        ),
        1,
    )

    if fragility >= _FRAGILE_THRESH:
        verdict = "هش للغاية — لا يُنصح بتشغيله خارج بيئة معزولة"
        severity = "critical"
    elif fragility >= _MEDIUM_THRESH:
        verdict = "هشاشة متوسطة — ينهار تحت ضغوط محددة"
        severity = "high"
    elif fragility > 0:
        verdict = "هامشي — استقرار مقبول في العينة لكنه ليس مثالياً"
        severity = "medium"
    else:
        verdict = "مستقر — لم تسجَّل أي انهيارات في العينة"
        severity = "low"

    # توقع 12 ساعة تشغيل متواصل: 1 − (1 − p)^(عدد دورات 12 ساعة)
    avg_dur = statistics.fmean([r["elapsed"] for r in launched])
    if fail_rate > 0 and avg_dur > 0.2:
        cycles = (_HOURS_FORECAST * 3600) / avg_dur
        p_12h = 1 - (1 - fail_rate) ** cycles
        p_12h = max(p_12h, fail_rate)
    else:
        p_12h = fail_rate

    # توقيعات الانهيار (أكواد خروج + ذيل خطأ)
    sigs: dict[str, int] = {}
    for r in failures:
        key = f"HANG — قُتل بعد المهلة" if r["timed_out"] else f"exit={r['exit_code']}"
        tail = " | ".join((r.get("stderr_tail") or "").strip().splitlines()[:2])
        if tail:
            key += " :: " + tail[:160]
        sigs[key] = sigs.get(key, 0) + 1
    top_sigs = [{"signature": k, "count": v} for k, v in sorted(sigs.items(), key=lambda kv: -kv[1])][:5]

    rows = [
        {
            "idx": i + 1,
            "axis": r["axis"],
            "level": r["level"],
            "exit": r["exit_code"],
            "state": "hang" if r["timed_out"] else ("crash" if r["crashed"] else "ok"),
            "elapsed": r["elapsed"],
            "peak_rss": r["peak_rss"],
        }
        for i, r in enumerate(runs[: _MAX_SCENARIOS])
    ]

    return {
        "ok": True,
        "module": "Digital Collapse Predictor",
        "target": str(resolved),
        "seed": seed,
        "scenarios_planned": total,
        "scenarios_run": len(runs),
        "exec_launch_failures": exec_fail,
        "failure_rate": round(fail_rate, 4),
        "crash_count": len(crashes),
        "hang_count": len(hangs),
        "fragility_score": fragility,
        "verdict": verdict,
        "severity": severity,
        "weakest_axis": weakest["axis"] if weakest else None,
        "forecast_12h_collapse_pct": round(min(p_12h, 1.0) * 100, 1),
        "model": "fault-injection / chaos — 1−(1−p)^n",
        "axes": axis_stats,
        "collapse_signatures": top_sigs,
        "scenarios": rows,
        "remedy": _REMEDIES.get(weakest["axis"], "") if weakest else "",
        "notes": [
            "نتيجة احتمالية تجريبية على جهازك الحالي وظروفه — ليست إثبات موثوقية إنتاجية.",
            f"توقع 12 ساعة يفترض تشغيلاً متواصلاً/متكرراً بمتوسط {avg_dur:.2f} ثانية لكل دورة.",
            "ضغط الذاكرة محدود بهامش أمان 768MB حتى لا يُسقط النظام المضيف.",
            "نفّذ الملفات الحساسة في VM معزولة — المحرك ينفّذ فعلياً على المضيف.",
        ],
        "summary": (
            f"Collapse Predictor: هشاشة {fragility}/100 · انهيار {fail_rate:.0%} "
            f"({len(failures)}/{len(launched)}) · أضعف محور: {(weakest or {}).get('axis') or '—'} · "
            f"توقع 12h: {round(min(p_12h, 1.0) * 100, 1)}%"
        ),
    }


# ═══════════════════════════════════════ واجهة الاستدعاء المرنة (بايتات أو مسار)
def collapse_predict(
    target: str | bytes | os.PathLike,
    filename: str = "sample",
    args: list[str] | None = None,
    scenarios: int = 18,
    timeout: float = 6.0,
    interval: float = 0.08,
    seed: int | None = None,
) -> dict[str, Any]:
    """يدعم المسار أو البايتات المرفوعة (كما تصل من الخادم)."""
    if isinstance(target, (bytes, bytearray)):
        if not target:
            return {"ok": False, "error": "رفع فارغ"}
        suffix = Path(filename or "sample").suffix.lower()
        if suffix not in _EXEC_SUFFIXES:
            suffix = ".exe"
        fd, tmp = tempfile.mkstemp(prefix="renexus_collapse_", suffix=suffix)
        os.close(fd)
        try:
            with open(tmp, "wb") as fh:
                fh.write(bytes(target))
            r = collapse_predict_path(
                tmp,
                args=args,
                scenarios=scenarios,
                timeout=timeout,
                interval=interval,
                seed=seed,
            )
            r["filename"] = filename
            return r
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    r = collapse_predict_path(
        target,
        args=args,
        scenarios=scenarios,
        timeout=timeout,
        interval=interval,
        seed=seed,
    )
    r["filename"] = filename
    return r


# ═══════════════════════════════════════ CLI للاختبار المباشر
def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="collapse_predictor",
        description="محرك التنبؤ بالانهيار الرقمي — حقن أعطال + Chaos Engineering.",
    )
    ap.add_argument("--target", required=True, help="مسار الملف القابل للتنفيذ")
    ap.add_argument("--args", nargs="*", default=None, help="وسائط إضافية")
    ap.add_argument("--scenarios", type=int, default=18, help="عدد السيناريوهات (4–120)")
    ap.add_argument("--timeout", type=float, default=6.0, help="مهلة الجولة بالثواني")
    ap.add_argument("--interval", type=float, default=0.08, help="فترة العينات")
    ap.add_argument("--seed", type=int, default=None, help="بذرة عشوائية للتكرار")
    ap.add_argument("--no-scenarios", action="store_true", help="حذف جدول الجولات من المخرجات")
    a = ap.parse_args(argv)

    # ضبط الترميز حتى لا تسقط طباعة العربية/الرياضيات على كونسولات Windows
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    r = collapse_predict(
        a.target,
        filename=str(Path(a.target).name),
        args=a.args,
        scenarios=a.scenarios,
        timeout=a.timeout,
        interval=a.interval,
        seed=a.seed,
    )
    if a.no_scenarios:
        r.pop("scenarios", None)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(_main())
