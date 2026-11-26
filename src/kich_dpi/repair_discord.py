"""Known Discord DPI and media-host repairs."""
from __future__ import annotations

from . import constants as C
from . import core


def repair_discord_domains(repair, report):
    path = C.DPI_DOMAINS_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Recreate the user's default list, not a root-owned empty file.
        repair.warp.ensure_user_lists()
        repair.chown_for_user(report, (path, C.STATE_FILE, C.WARP_USER_DOMAINS,
                                       C.WARP_USER_PROCESSES))
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


def repair_discord_media_hosts(repair, report):
    hosts_text = ""
    try:
        hosts_text = C.REPAIR_HOSTS.read_text(encoding="utf-8")
    except OSError:
        pass
    if C.REPAIR_HOSTS_MARKER in hosts_text or \
            core.tcp_reachable(C.REPAIR_MEDIA_BLOCKED_IP):
        return
    if repair.os.geteuid() != 0:
        report.blocked_by("правка /etc/hosts требует root (запустите через pkexec)")
        return
    try:
        if not C.REPAIR_HOSTS_BACKUP.exists():
            repair.shutil.copy2(C.REPAIR_HOSTS, C.REPAIR_HOSTS_BACKUP)
        rows = ["%s %s" % (ip, " ".join(C.REPAIR_MEDIA_DOMAINS))
                for ip in C.REPAIR_MEDIA_GOOD_IPS]
        with open(C.REPAIR_HOSTS, "a", encoding="utf-8") as fh:
            fh.write("\n%s\n%s\n" % (C.REPAIR_HOSTS_MARKER, "\n".join(rows)))
    except OSError as exc:
        report.blocked_by("/etc/hosts: %s" % exc)
        return
    report.fixed("медиа-домены Discord закреплены на рабочих IP")
