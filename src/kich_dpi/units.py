"""systemd unit state and error reporting."""
from __future__ import annotations

from pathlib import Path

from . import constants as C
from . import core
from .errors import Fail


def unit_error(cp, fallback="", limit=400):
    return core.clip(cp.stderr or cp.stdout or fallback, limit=limit, tail=True)


def checked_unit_call(call, action, fallback, timeout):
    cp = call(action, timeout=timeout)
    if cp.returncode != 0:
        raise Fail(unit_error(cp, fallback))
    return cp


def systemctl(*args, timeout=25, unit=None):
    return core.run(["systemctl", *args, unit or C.UNIT], timeout=timeout)


def unit_state(unit=None, path=None, missing_ok=True):
    unit = unit or C.UNIT
    path = Path(path) if path is not None else C.UNIT_PATH
    if not path.exists() and not (missing_ok and core.installed()):
        return "inactive", "not-found"
    active = core.systemctl("is-active", unit=unit).stdout.strip() or "inactive"
    enabled = core.systemctl("is-enabled", unit=unit).stdout.strip() or "disabled"
    return active, enabled


def batched_unit_states(units):
    """Active/enabled for several units from one `systemctl show`."""
    units = list(dict.fromkeys(units))
    result = {u: ("inactive", "not-found") for u in units}
    if not units:
        return result
    cp = core.run(
        ["systemctl", "show", *units, "-p", "Id", "-p", "ActiveState",
         "-p", "UnitFileState", "--value"],
        timeout=12,
    )
    for block in cp.stdout.split("\n\n"):
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if len(lines) < 2:
            continue
        name, active = lines[0], lines[1] or "inactive"
        enabled = (lines[2] if len(lines) >= 3 else "") or "not-found"
        if name in result:
            result[name] = (active, enabled)
    return result


def is_running():
    return core.unit_state()[0] == "active"
