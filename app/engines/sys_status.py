"""Host live metrics for Nexus Lair flame strip."""
from __future__ import annotations

import os
import time
from typing import Any


_last = {"t": 0.0, "cpu": 0.0}


def host_metrics() -> dict[str, Any]:
    cpu = 0.0
    ram = {"total": 0, "used": 0, "percent": 0.0}
    procs = 0
    try:
        import psutil  # type: ignore

        cpu = float(psutil.cpu_percent(interval=0.05))
        vm = psutil.virtual_memory()
        ram = {
            "total": int(vm.total),
            "used": int(vm.used),
            "percent": float(vm.percent),
        }
        procs = len(psutil.pids())
        per_cpu = [float(x) for x in psutil.cpu_percent(interval=0.05, percpu=True)]
    except Exception:
        per_cpu = []
        # fallback crude
        cpu = min(99.0, (time.time() % 7) * 9)

    # synthetic render load proxy (for UI flame): blend CPU + RAM
    render = round(min(100.0, cpu * 0.65 + ram["percent"] * 0.35), 2)

    # mini flame buckets (16 bars)
    import random

    rng = random.Random(int(time.time() * 4))
    flame = []
    base = max(cpu, 1.0)
    for i in range(16):
        flame.append(round(max(2, min(100, base * (0.45 + rng.random()) + (per_cpu[i % len(per_cpu)] if per_cpu else 0) * 0.3)), 1))

    return {
        "ok": True,
        "cpu_percent": cpu,
        "per_cpu": per_cpu,
        "ram": ram,
        "render_load": render,
        "processes": procs,
        "cores": os.cpu_count() or len(per_cpu) or 1,
        "flame": flame,
        "ts": time.time(),
    }
