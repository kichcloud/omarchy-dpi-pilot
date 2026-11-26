"""Status, strategies list, logs and doctor — everything the panel reads."""
from __future__ import annotations

import os
import shutil
import time

from . import constants as C
from . import core
from . import doctor as _doctor
from . import snapshot as _snapshot
from . import strategies
from . import warp

CONFLICT_UNIT = _snapshot.CONFLICT_UNIT
WARP_ONLY_ROWS = _doctor.WARP_ONLY_ROWS


def progress_data():
    return _snapshot.progress_data()


def strategy_rows(saved):
    return _snapshot.strategy_rows(saved)


def status_data():
    return _snapshot.status_data()


def service_detail(state):
    return _doctor.service_detail(state)


def polkit_rule_state():
    return _doctor.polkit_rule_state(os)


def doctor_checks():
    return _doctor.doctor_checks()


def doctor_summary(checks):
    return _doctor.doctor_summary(checks)


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


def cmd_doctor():
    checks, state = doctor_checks()
    core.out({"ok": True, "checks": checks, "status": state})


def cmd_check_all():
    return _doctor.cmd_check_all()
