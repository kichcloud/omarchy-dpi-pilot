"""The one-click repair path: known DPI and WARP failures, no guessing."""
from __future__ import annotations

import os
import shutil

from . import constants as C
from . import core
from . import strategies
from . import warp


class RepairReport:
    def __init__(self):
        self.fixes = []
        self.blocked = []

    def fixed(self, text):
        self.fixes.append(text)

    def blocked_by(self, text):
        self.blocked.append(text)


def repair_error(cp_text, fallback):
    return (cp_text or fallback).strip()[:160]


def repair_discord_domains(report):
    path = C.DPI_DOMAINS_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Recreate the user's default list, not a root-owned empty file.
        warp.ensure_user_lists()
        try:
            if core.os.geteuid() == 0:
                user = core.target_user()
                core.os.chown(path, user.pw_uid, user.pw_gid)
        except (OSError, core.Fail):
            pass
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            report.blocked_by("dpi-domains.txt: %s" % exc)
            return False
    except OSError as exc:
        report.blocked_by("dpi-domains.txt: %s" % exc)
        return False

    current = core.list_lines(path)
    missing = [d for d in C.REPAIR_DISCORD_DOMAINS if d not in current]
    if not missing:
        return False
    prefix = "" if not text or text.endswith("\n") else "\n"
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(prefix + "\n".join(missing) + "\n")
    except OSError as exc:
        report.blocked_by("dpi-domains.txt: %s" % exc)
        return False
    report.fixed("домены Discord добавлены: " + ", ".join(missing))
    return True


def repair_discord_media_hosts(report):
    hosts_text = ""
    try:
        hosts_text = C.REPAIR_HOSTS.read_text(encoding="utf-8")
    except OSError:
        pass
    if C.REPAIR_HOSTS_MARKER in hosts_text or \
            core.tcp_reachable(C.REPAIR_MEDIA_BLOCKED_IP):
        return
    if os.geteuid() != 0:
        report.blocked_by("правка /etc/hosts требует root (запустите через pkexec)")
        return
    try:
        if not C.REPAIR_HOSTS_BACKUP.exists():
            shutil.copy2(C.REPAIR_HOSTS, C.REPAIR_HOSTS_BACKUP)
        rows = ["%s %s" % (ip, " ".join(C.REPAIR_MEDIA_DOMAINS))
                for ip in C.REPAIR_MEDIA_GOOD_IPS]
        with open(C.REPAIR_HOSTS, "a", encoding="utf-8") as fh:
            fh.write("\n%s\n%s\n" % (C.REPAIR_HOSTS_MARKER, "\n".join(rows)))
    except OSError as exc:
        report.blocked_by("/etc/hosts: %s" % exc)
        return
    report.fixed("медиа-домены Discord закреплены на рабочих IP")


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


def restart_warp_for_repair(report):
    if not core.wanted_flags()["warp"]:
        return None
    if not warp.warp_account():
        return None
    check = warp.warp_check_data()
    if check.get("ok"):
        return check
    cp = warp.warp_systemctl("restart", timeout=25)
    if cp.returncode != 0:
        report.blocked_by("WARP: " + repair_error(cp.stderr, "restart failed"))
        return check
    check = warp.warp_check_data()
    state = " · подключён" if check.get("ok") else " · всё ещё не отвечает"
    report.fixed("WARP перезапущен" + state)
    return check


def cmd_repair():
    """Apply the known fixes, then refresh the panel's probe cache."""
    if not core.installed():
        raise core.Fail("сначала установите движок")
    report = RepairReport()
    domains_changed = repair_discord_domains(report)
    repair_discord_media_hosts(report)
    restart_dpi_for_repair(report, domains_changed)
    warp_check = restart_warp_for_repair(report)
    probe_result = strategies.run_check()
    core.out({"ok": True, "fixes": report.fixes, "blocked": report.blocked,
              "check": probe_result, "warp_check": warp_check})
