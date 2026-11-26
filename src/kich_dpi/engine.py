"""Installation, systemd units, firewall and the long-running engine."""
from __future__ import annotations

import grp
import os
import shutil
import tempfile
import time
from pathlib import Path

from . import constants as C
from . import core
from . import firewall
from . import installer
from . import runtime
from . import warp
from .templates import (
    LAUNCHER_TEMPLATE, NFT_SCRIPT, POLKIT_TEMPLATE, UNIT_GUARDS,
    UNIT_HARDENING, UNIT_TEMPLATE, WARP_RUN_TEMPLATE,
    WARP_UNIT_TEMPLATE, unit_text,
)


def sysctl_value(key):
    """Current kernel setting, or '' when it cannot be read."""
    try:
        cp = core.run(["sysctl", "-n", key], timeout=10)
    except Exception:
        return ""
    return (cp.stdout or "").strip() if cp.returncode == 0 else ""


def install_system(user):
    """Install system files and units; return whether anything changed."""
    try:
        group = grp.getgrgid(user.pw_gid).gr_name
    except KeyError:
        group = user.pw_name
    home = Path(user.pw_dir)
    legacy = legacy_enabled_states()
    needs_enable = {unit: installer.needs_enabling(unit)
                    for unit in (C.UNIT, C.WARP_UNIT)}

    changed = False
    files = (
        (C.UNIT_PATH, unit_text(
            UNIT_TEMPLATE, user.pw_dir, user=user.pw_name, group=group)),
        (C.WARP_UNIT_PATH, unit_text(
            WARP_UNIT_TEMPLATE, user.pw_dir, user=user.pw_name, group=group)),
        (C.POLKIT_PATH, POLKIT_TEMPLATE.format(
            user=user.pw_name, unit=C.UNIT, warp_unit=C.WARP_UNIT)),
        (C.SYSCTL_PATH, "net.netfilter.nf_conntrack_tcp_be_liberal=1\n"),
    )
    for path, text in files:
        if installer.text_changed(path, text):
            core.write_text(path, text)
            changed = True
    if changed:
        core.run(["systemctl", "daemon-reload"], timeout=30)
    for unit in (C.UNIT, C.WARP_UNIT):
        if needs_enable[unit]:
            core.run(["systemctl", "enable", unit], timeout=30)
            changed = True

    state_dir = merge_config_into_state(home, user.pw_uid, user.pw_gid)
    state_path = state_dir / "state.json"
    if not state_path.exists():
        core.write_json(state_path, {
            "version": 1, "dpi": legacy[C.UNIT], "warp": legacy[C.WARP_UNIT],
        })
        changed = True
    chown_tree(state_dir, user.pw_uid, user.pw_gid)
    # Root-run setup can also create ~/.config/kich-dpi directly. Without this
    # the user cannot write state.json/warp.yaml and every toggle fails.
    config_dir = Path(home) / ".config" / C.ENGINE_SLUG
    config_dir.mkdir(parents=True, exist_ok=True)
    chown_tree(config_dir, user.pw_uid, user.pw_gid)

    C.WARP_RUN.parent.mkdir(parents=True, exist_ok=True)
    run_text = WARP_RUN_TEMPLATE.format(
        state=str(state_path),
        config=str(state_dir / "warp.yaml"),
        data=str(state_dir),
    )
    if installer.text_changed(C.WARP_RUN, run_text):
        core.write_text(C.WARP_RUN, run_text, 0o755)
        changed = True
    warp.migrate_account(home, user.pw_uid, user.pw_gid)

    for path in (Path("/run") / C.ENGINE_SLUG,):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
            changed = True
    sysctl_key = "net.netfilter.nf_conntrack_tcp_be_liberal"
    if sysctl_value(sysctl_key) != "1":
        core.run(["sysctl", "-q", "-w", sysctl_key + "=1"], timeout=10)
        changed = True
    return changed



# Facade: keep patchable names in engine for callers and tests.
def source_paths():
    return installer.source_paths()

def install_app():
    return installer.install_app()

def chown_tree(path, uid, gid):
    return installer.chown_tree(path, uid, gid)

def merge_config_into_state(home, uid, gid):
    return installer.merge_config_into_state(home, uid, gid)

def legacy_enabled_states():
    return installer.legacy_enabled_states()

def restart_services(was_running, changed=True):
    return installer.restart_services(was_running, changed)

def refresh_warp_config(user):
    return installer.refresh_warp_config(user)

def finish_system_update(user, was_running, changed=True):
    return installer.finish_system_update(user, was_running, changed)

def download(url, dest):
    return installer.download(url, dest)

def sha256_file(path):
    return installer.sha256_file(path)

def github_latest_tag(repo):
    return installer.github_latest_tag(repo)

def release_info():
    return installer.release_info()

def extract_engine(archive, tag):
    return installer.extract_engine(archive, tag)

def install_mihomo():
    return installer.install_mihomo()



def cmd_setup(archive_arg=""):
    core.require_root()
    user = core.target_user()
    was_running = core.is_running()
    previous = core.installed_version()
    installed_at = int(core.read_dict(C.ENGINE_ROOT / "install.json").get("installed") or 0)

    archive = Path(archive_arg) if archive_arg else None
    tag, url, digest = "", "", ""
    if archive:
        if not archive.exists():
            raise core.Fail("архив не найден: %s" % archive)
        tag = "custom-" + sha256_file(archive)[:8]
    else:
        try:
            tag, url, digest = release_info()
        except Exception as exc:
            if core.installed():
                app_changed = install_app()
                system_changed = install_system(user)
                changed = bool(app_changed or system_changed)
                note = finish_system_update(user, was_running, changed)
                core.out({"ok": True, "version": previous, "previous": previous,
                          "note": "сеть недоступна, системная часть обновлена без движка",
                          "warp_config": note, "detail": core.clip(exc, limit=200, strip=False)})
                return
            raise core.Fail("не удалось получить релиз zapret2: %s" % exc)

    version_changed = bool(archive or tag != previous
                           or not (C.ENGINE_DIR / tag / "nfqws2").exists())
    if version_changed:
        with tempfile.TemporaryDirectory(prefix="kich-dpi-") as tmp:
            tar_path = Path(tmp) / "zapret2.tar.gz"
            if archive:
                shutil.copy2(archive, tar_path)
            else:
                try:
                    download(url, tar_path)
                except Exception as exc:
                    raise core.Fail("не удалось скачать zapret2: %s" % exc)
                if digest.startswith("sha256:") and \
                        ("sha256:" + sha256_file(tar_path)).lower() != digest.lower():
                    raise core.Fail("sha256 не совпал: ожидался %s" % digest)
            extract_engine(tar_path, tag)
    else:
        current = C.ENGINE_DIR / "current"
        if not current.is_symlink() or os.readlink(current) != tag:
            if current.is_symlink() or current.exists():
                current.unlink()
            current.symlink_to(tag)
            version_changed = True

    core.write_text(C.ENGINE_ROOT / "README", (
        "Engine: zapret2 by bol-van (https://github.com/bol-van/zapret2).\n"
        "Installed by the kich-dpi Omarchy plugin. The plugin code is MIT.\n"
    ))
    app_changed = install_app()
    system_changed = install_system(user)

    mihomo_before = warp.mihomo_version()
    warp_note = ""
    try:
        install_mihomo()
    except core.Fail as exc:
        warp_note = core.clip(exc, limit=200, strip=False)
    mihomo_changed = warp.mihomo_version() != mihomo_before

    changed = bool(version_changed or app_changed or system_changed or mihomo_changed)
    note = finish_system_update(user, was_running, changed)
    if changed or not installed_at:
        installed_at = int(time.time())
    core.write_json(C.ENGINE_ROOT / "install.json", {
        "version": tag, "installed": installed_at, "sha256": digest,
    })
    core.out({"ok": True, "version": tag, "previous": previous,
              "user": user.pw_name, "installed": installed_at,
              "warp": not bool(warp_note), "warp_note": warp_note,
              "warp_config": note})


def cmd_remove(purge=False):
    core.require_root()
    user = core.target_user()
    for unit in (C.WARP_UNIT, C.UNIT):
        core.run(["systemctl", "disable", "--now", unit], timeout=40)
    for path in (C.UNIT_PATH, C.WARP_UNIT_PATH, C.POLKIT_PATH, C.SYSCTL_PATH):
        try:
            path.unlink()
        except OSError:
            pass
    core.run(["systemctl", "daemon-reload"], timeout=30)
    shutil.rmtree(C.ENGINE_ROOT, ignore_errors=True)
    shutil.rmtree(Path("/run") / C.ENGINE_SLUG, ignore_errors=True)
    if purge:
        home = Path(user.pw_dir)
        for path in (home / ".config" / C.ENGINE_SLUG,
                     home / ".local" / "state" / C.ENGINE_SLUG,
                     home / ".local" / "share" / C.ENGINE_SLUG):
            shutil.rmtree(path, ignore_errors=True)
    core.out({"ok": True, "removed": True, "purged": bool(purge)})


# Facade: keep patchable names in engine for callers and tests.
def fw_rule(action):
    return firewall.fw_rule(action)

def fw_up():
    return firewall.fw_up()

def fw_down():
    return firewall.fw_down()

def cmd_fw_down():
    return firewall.cmd_fw_down()

def supervise_child(child):
    return runtime.supervise_child(child)

def cmd_run():
    return runtime.cmd_run()
