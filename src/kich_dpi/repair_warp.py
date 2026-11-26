"""Delayed, readiness-aware WARP restart during `repair`."""
from __future__ import annotations

from . import constants as C
from . import polling


def probe_warp_after_restart(repair):
    """Wait for the local proxy, then confirm the tunnel itself.

    A systemd `start`/`restart` says nothing about mihomo being ready: curl can
    fail to connect for several seconds after the unit reports active.
    """
    time = repair.time
    core = repair.core
    listening = polling.wait_until(
        lambda: core.tcp_reachable("127.0.0.1", C.WARP_MIXED_PORT, timeout=1),
        repair.WARP_REPAIR_WAIT_SECONDS, repair.WARP_REPAIR_POLL_SECONDS,
        clock=time.monotonic, sleep=time.sleep,
    )
    if not listening:
        return {"ok": False, "error": "локальный порт WARP не открылся"}
    check = repair.warp.warp_check_data()
    if check.get("ok"):
        return check
    # The MASQUE handshake can finish just after the port starts listening.
    time.sleep(repair.WARP_REPAIR_POLL_SECONDS)
    return repair.warp.warp_check_data()


def restart_warp_for_repair(repair, report):
    core, warp = repair.core, repair.warp
    if not core.wanted_flags()["warp"]:
        return None
    account = warp.warp_account()
    if not account:
        report.blocked_by("WARP: нет учётной записи — зарегистрируйте туннель")
        return None
    if not C.WARP_CONFIG.is_file():
        # A skipped unit (ConditionPathExists) returns rc=0 on restart, so a
        # restart alone can never repair a missing config.
        try:
            warp.warp_build(account)
            repair.chown_for_user(report, (C.WARP_CONFIG, C.WARP_RULES,
                                           C.WARP_USER_DOMAINS,
                                           C.WARP_USER_PROCESSES,
                                           C.DPI_DOMAINS_FILE))
            report.fixed("конфиг WARP создан")
        except core.Fail as exc:
            report.blocked_by("WARP config: %s" % exc)
            return warp.warp_check_data()
    check = warp.warp_check_data()
    if check.get("ok"):
        return check
    cp = warp.warp_systemctl("restart", timeout=35)
    active, _enabled = warp.warp_unit_state()
    if cp.returncode != 0 or active != "active":
        detail = repair.repair_error(cp.stderr or cp.stdout, "restart failed") \
            if cp.returncode != 0 else "служба не активна (%s)" % active
        report.blocked_by("WARP: " + detail)
        return check
    check = repair.probe_warp_after_restart()
    state = " · подключён" if check.get("ok") else " · всё ещё не отвечает"
    report.fixed("WARP перезапущен" + state)
    if not check.get("ok"):
        report.blocked_by("WARP: " + (check.get("error") or "туннель не подтвердился"))
    return check
