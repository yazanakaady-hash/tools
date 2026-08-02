"""Combi Scan (مسح كومبي) — full-system sweep in one shot.

Aggregates: digital fingerprint + port scan + process monitor + stealth
task manager + secret browser + event log into a single fast report.
Designed to run locally on the authorized lab host.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

from .elite_dashboard import (
    digital_fingerprint,
    event_log,
    process_monitor,
    scan_ports,
    secret_browser,
    stealth_tasks,
)

SCAN_STAGES = ["fingerprint", "ports", "processes", "tasks", "files", "events"]


def combi_scan(path: Optional[str] = None, ports: Optional[list[int]] = None) -> dict[str, Any]:
    """Run the full combo scan and return a merged report with timings."""
    result: dict[str, Any] = {"ok": True, "started_at": time.time(), "stages": {}, "total_elapsed_sec": 0.0, "error": ""}
    t0 = time.perf_counter()
    try:
        stage_t0 = time.perf_counter()
        result["stages"]["fingerprint"] = digital_fingerprint()
        result["stages"]["fingerprint"]["elapsed_sec"] = round(time.perf_counter() - stage_t0, 3)

        stage_t0 = time.perf_counter()
        result["stages"]["ports"] = scan_ports(ports=ports)
        result["stages"]["ports"]["elapsed_sec"] = round(time.perf_counter() - stage_t0, 3)

        stage_t0 = time.perf_counter()
        result["stages"]["processes"] = process_monitor(limit=30)
        result["stages"]["processes"]["elapsed_sec"] = round(time.perf_counter() - stage_t0, 3)

        stage_t0 = time.perf_counter()
        result["stages"]["tasks"] = stealth_tasks(limit=15)
        result["stages"]["tasks"]["elapsed_sec"] = round(time.perf_counter() - stage_t0, 3)

        stage_t0 = time.perf_counter()
        result["stages"]["files"] = secret_browser(path=path, max_entries=40)
        result["stages"]["files"]["elapsed_sec"] = round(time.perf_counter() - stage_t0, 3)

        stage_t0 = time.perf_counter()
        result["stages"]["events"] = event_log(limit=30)
        result["stages"]["events"]["elapsed_sec"] = round(time.perf_counter() - stage_t0, 3)

        result["engine_count"] = len(SCAN_STAGES)
        result["health_score"] = _health_score(result["stages"])
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)
    result["total_elapsed_sec"] = round(time.perf_counter() - t0, 3)
    return result


def _health_score(stages: dict[str, Any]) -> int:
    """0-100 rough health score from scan results."""
    score = 100
    ports = stages.get("ports", {}).get("open", [])
    score -= len(ports) * 6
    tasks = stages.get("tasks", {})
    if tasks.get("cpu_percent", 0) > 85:
        score -= 15
    if tasks.get("ram_percent", 0) > 85:
        score -= 15
    return max(0, min(100, score))

