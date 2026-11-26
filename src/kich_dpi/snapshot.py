"""One status snapshot for the panel, shared by `status` and strategies."""
from __future__ import annotations

import time

from . import constants as C
from . import core
from . import strategies
from . import warp

CONFLICT_UNIT = "omarchy-zapret2.service"


def progress_data():
    data = core.read_dict(C.PROGRESS_FILE)
    if data.get("running") and time.time() - core.to_int(data.get("started")) > 1800:
        data["running"] = False
        data["error"] = "подбор прерван"
    return data


def strategy_rows(saved):
    """Normalise, rank and cap the saved strategies for both status and CLI."""
    rows = []
    for item in saved:
        if not isinstance(item, dict):
            continue
        rows.append({
            "id": str(item.get("id") or ""), "name": str(item.get("name") or ""),
            "passed": core.to_int(item.get("passed")),
            "total": core.to_int(item.get("total")),
            "ms": core.to_int(item.get("ms")), "time": core.to_int(item.get("time")),
        })
    rows.sort(key=lambda r: (-r["passed"], r["ms"]))
    return rows[:8]


def status_data():
    version, is_installed = core.engine_info()
    states = core.batched_unit_states([C.UNIT, C.WARP_UNIT, CONFLICT_UNIT])
    active, enabled = states[C.UNIT]
    running = active == "active"
    failed = active == "failed"
    active_doc = core.read_dict(C.ACTIVE_FILE)
    spec = strategies.active_spec_from(active_doc, {})
    check = core.read_dict(C.CHECK_FILE)
    progress = progress_data()
    saved = core.read_list(C.STRATEGIES_FILE)

    error = ""
    if not is_installed:
        error = "движок не установлен"
    elif failed:
        error = "служба не запустилась"

    return {
        "ok": True, "version": C.VERSION, "installed": is_installed,
        "engine": version, "unit": C.UNIT, "running": running, "failed": failed,
        "active": active, "enabled": enabled,
        "active_id": str(active_doc.get("id") or ""),
        "active_name": strategies.strategy_name(spec) if spec else "",
        "check": check, "generating": bool(progress.get("running")),
        "progress": progress, "strategies": strategy_rows(saved),
        "conflict": states[CONFLICT_UNIT][0] == "active",
        "wanted": core.wanted_flags(),
        "warp": warp.warp_status(_states=states), "error": error,
    }
