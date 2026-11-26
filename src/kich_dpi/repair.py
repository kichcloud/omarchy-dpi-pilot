"""The one-click repair path: known DPI and WARP failures, no guessing."""
from __future__ import annotations

import os
import shutil
import sys
import time

from . import constants as C
from . import core
from . import ownership
from . import polling
from . import repair_discord as _repair_discord
from . import repair_report as _repair_report
from . import repair_warp as _repair_warp
from . import strategies
from . import warp

_self = sys.modules[__name__]

# mihomo needs a moment after `start` before its local proxy accepts requests.
# A probe fired immediately after systemctl reports active always fails.
WARP_REPAIR_WAIT_SECONDS = 15
WARP_REPAIR_POLL_SECONDS = 1

RepairReport = _repair_report.RepairReport


def repair_error(cp_text, fallback):
    return _repair_report.repair_error(cp_text, fallback)


def chown_for_user(report, paths):
    """Root's pkexec repairs must leave config/rules writable by the user."""
    if os.geteuid() != 0:
        return
    try:
        user = core.target_user()
        # The parents must be writable too: atomic writes create a temp file
        # next to state.json / warp.yaml before replacing it.
        ownership.chown_with_parents(paths, user.pw_uid, user.pw_gid,
                                     os_module=os)
    except (OSError, core.Fail) as exc:
        report.blocked_by("права на конфигурацию: %s" % exc)


def repair_discord_domains(report):
    return _repair_discord.repair_discord_domains(_self, report)


def repair_discord_media_hosts(report):
    return _repair_discord.repair_discord_media_hosts(_self, report)


def restart_dpi_for_repair(report, domains_changed):
    # Do not start a service the user deliberately switched off: state.json is
    # the desired state, and a running unit with dpi=false would be a lie.
    if not core.wanted_flags()["dpi"]:
        return
    if domains_changed or not core.is_running():
        cp = core.systemctl("restart" if core.is_running() else "start", timeout=30)
        if cp.returncode == 0:
            report.fixed("DPI перезапущен" if domains_changed else "DPI запущен")
        else:
            report.blocked_by("DPI: " + repair_error(cp.stderr or cp.stdout,
                                                       "restart failed"))


def probe_warp_after_restart():
    return _repair_warp.probe_warp_after_restart(_self)


def restart_warp_for_repair(report):
    return _repair_warp.restart_warp_for_repair(_self, report)


def cmd_repair():
    """Apply the known fixes, then refresh the panel's probe cache."""
    if not core.installed():
        raise core.Fail("сначала установите движок")
    report = RepairReport()
    # Heal installs whose root-run setup left ~/.config/kich-dpi unwritable.
    chown_for_user(report, (C.STATE_FILE, C.DPI_DOMAINS_FILE,
                            C.WARP_USER_DOMAINS, C.WARP_USER_PROCESSES,
                            C.WARP_CONFIG))
    domains_changed = repair_discord_domains(report)
    repair_discord_media_hosts(report)
    restart_dpi_for_repair(report, domains_changed)
    warp_check = restart_warp_for_repair(report)
    probe_result = strategies.run_check()
    core.out({"ok": True, "fixes": report.fixes, "blocked": report.blocked,
              "check": probe_result, "warp_check": warp_check})
