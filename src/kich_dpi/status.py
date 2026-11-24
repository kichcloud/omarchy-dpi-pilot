"""Status, strategies list, logs and doctor — everything the panel reads."""
from __future__ import annotations

import os
import shutil
import time

from . import constants as C
from . import core
from . import strategies
from . import warp

CONFLICT_UNIT = "omarchy-zapret2.service"


def progress_data():
    data = core.read_dict(C.PROGRESS_FILE)
    if data.get("running") and time.time() - int(data.get("started") or 0) > 1800:
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
            "passed": int(item.get("passed") or 0),
            "total": int(item.get("total") or 0),
            "ms": int(item.get("ms") or 0), "time": int(item.get("time") or 0),
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


def cmd_status():
    core.out(status_data())


def cmd_strategies():
    saved = core.read_list(C.STRATEGIES_FILE)
    core.out({"ok": True, "strategies": strategy_rows(saved)})


def cmd_logs(count):
    count = max(1, int(count))
    cp = core.run(
        ["journalctl", "-u", C.UNIT, "-n", str(count), "--no-pager", "-o", "cat"],
        timeout=15,
    )
    lines = [line for line in cp.stdout.splitlines() if line.strip()]
    core.out({"ok": True, "lines": lines[-count:]})


def service_detail(state):
    if state.get("failed"):
        return "не запустилась (failed)"
    if state.get("running"):
        return "работает"
    return "остановлена (%s)" % (state.get("active") or "inactive")


def polkit_rule_state():
    parent = str(C.POLKIT_PATH.parent)
    if not os.access(parent, os.R_OK | os.X_OK):
        return True, "проверить может только root: %s" % parent
    if not C.POLKIT_PATH.exists():
        return False, str(C.POLKIT_PATH)
    return True, str(C.POLKIT_PATH)


def doctor_checks():
    """Collect the diagnostic rows without printing them."""
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:300]})

    def service_row(name, running, detail, wanted):
        # `wanted is None` is an older status payload without the flag: there,
        # a stopped service has always meant unhealthy.
        if wanted is not False:
            add(name, running, detail)
        elif running:
            add(name, False, detail)
        else:
            add(name, True, "отключена намеренно")

    version, is_installed = core.engine_info()
    add("движок", is_installed, version)
    if is_installed:
        cp = core.run([str(core.engine_bin()), "--version"], timeout=10)
        add("nfqws2", cp.returncode == 0, (cp.stdout or cp.stderr).strip())
    add("systemd unit", C.UNIT_PATH.exists(), C.UNIT_PATH)
    polkit_ok, polkit_detail = polkit_rule_state()
    add("polkit", polkit_ok, polkit_detail)
    add("curl", core.curl_available(), shutil.which("curl") or "")
    add("nft", shutil.which("nft") is not None, shutil.which("nft") or "")
    state = status_data()
    wanted = state.get("wanted") or {}
    service_row("служба", state["running"], service_detail(state),
                wanted.get("dpi"))
    add("конфликт zapret2", not state["conflict"],
        "omarchy-zapret2 активен" if state["conflict"] else "нет")
    info = state["warp"]
    add("mihomo", info["available"], warp.mihomo_version())
    add("аккаунт WARP", info["registered"], info["account"])
    service_row("служба WARP", info["running"], service_detail(info),
                wanted.get("warp"))
    if state["active_name"]:
        add("стратегия", True, state["active_name"])
    return checks, state


def doctor_summary(checks):
    failed = [row["name"] for row in checks if not row["ok"]]
    return {"passed": len(checks) - len(failed), "total": len(checks),
            "failed": failed}


def cmd_doctor():
    checks, state = doctor_checks()
    core.out({"ok": True, "checks": checks, "status": state})


# A deliberately disabled WARP is not a broken WARP: leave its rows out of the
# combined check, but keep them in the full `doctor` command.
WARP_ONLY_ROWS = ("mihomo", "аккаунт WARP", "служба WARP")


def cmd_check_all():
    """Run only the probes for services the user actually wants enabled."""
    wanted = core.wanted_flags()
    payload = {"ok": True, "check": None, "warp_check": None, "doctor": None}
    if wanted.get("dpi") and core.installed():
        payload["check"] = strategies.run_check()
    if wanted.get("warp"):
        payload["warp_check"] = warp.warp_check_data()

    checks, _ = doctor_checks()
    if not wanted.get("warp"):
        checks = [row for row in checks if row["name"] not in WARP_ONLY_ROWS]
    payload["doctor"] = doctor_summary(checks)
    core.out(payload)
