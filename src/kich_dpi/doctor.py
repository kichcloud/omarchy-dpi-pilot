"""Diagnostic rows and the combined `check-all` command."""
from __future__ import annotations

import shutil

from . import constants as C
from . import core
from . import strategies
from . import warp

# A deliberately disabled WARP is not a broken WARP: leave its rows out of the
# combined check, but keep them in the full `doctor` command.
WARP_ONLY_ROWS = ("mihomo", "аккаунт WARP", "служба WARP")


def service_detail(state):
    if state.get("failed"):
        return "не запустилась (failed)"
    if state.get("running"):
        return "работает"
    return "остановлена (%s)" % (state.get("active") or "inactive")


def polkit_rule_state(os_module):
    parent = str(C.POLKIT_PATH.parent)
    if not os_module.access(parent, os_module.R_OK | os_module.X_OK):
        return True, "проверить может только root: %s" % parent
    if not C.POLKIT_PATH.exists():
        return False, str(C.POLKIT_PATH)
    return True, str(C.POLKIT_PATH)


def doctor_checks():
    """Collect the diagnostic rows without printing them."""
    from . import status  # calls go through the facade so patches still land

    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok),
                       "detail": core.clip(detail, limit=300, strip=False)})

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
    polkit_ok, polkit_detail = status.polkit_rule_state()
    add("polkit", polkit_ok, polkit_detail)
    add("curl", core.curl_available(), shutil.which("curl") or "")
    add("nft", shutil.which("nft") is not None, shutil.which("nft") or "")
    state = status.status_data()
    wanted = state.get("wanted") or {}
    service_row("служба", state["running"], status.service_detail(state),
                wanted.get("dpi"))
    add("конфликт zapret2", not state["conflict"],
        "omarchy-zapret2 активен" if state["conflict"] else "нет")
    info = state["warp"]
    add("mihomo", info["available"], warp.mihomo_version())
    add("аккаунт WARP", info["registered"], info["account"])
    service_row("служба WARP", info["running"], status.service_detail(info),
                wanted.get("warp"))
    if state["active_name"]:
        add("стратегия", True, state["active_name"])
    return checks, state


def doctor_summary(checks):
    failed = [row["name"] for row in checks if not row["ok"]]
    return {"passed": len(checks) - len(failed), "total": len(checks),
            "failed": failed}


def cmd_check_all():
    """Run only the probes for services the user actually wants enabled."""
    from . import status  # patched doctor_checks must be observed here

    wanted = core.wanted_flags()
    payload = {"ok": True, "check": None, "warp_check": None, "doctor": None}
    if wanted.get("dpi") and core.installed():
        payload["check"] = strategies.run_check()
    if wanted.get("warp"):
        payload["warp_check"] = warp.warp_check_data()

    checks, _ = status.doctor_checks()
    if not wanted.get("warp"):
        checks = [row for row in checks if row["name"] not in WARP_ONLY_ROWS]
    payload["doctor"] = doctor_summary(checks)
    core.out(payload)
