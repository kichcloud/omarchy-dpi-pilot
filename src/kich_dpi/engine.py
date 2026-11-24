"""Installation, systemd units, firewall and the long-running engine."""
from __future__ import annotations

import gzip
import grp
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from . import constants as C
from . import core
from . import strategies
from . import warp

LAUNCHER_TEMPLATE = '''#!/usr/bin/env python3
# Installed by kich-dpi. A two-line shim: the app itself lives in ../lib.
import os
import sys

root = {root!r}
sys.path.insert(0, os.path.join(root, "lib"))
os.environ["KICH_DPI_ROOT"] = root

from kich_dpi.cli import main
if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''

UNIT_GUARDS = """ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=-{home}/.config/kich-dpi -{home}/.local/state/kich-dpi
PrivateTmp=yes
"""

UNIT_HARDENING = """ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LimitNOFILE=65535
"""

UNIT_TEMPLATE = """# Installed by kich-dpi (Omarchy plugin). Removed by `kich-dpi remove`.
[Unit]
Description=DPI bypass for Omarchy (kich-dpi)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/kich-dpi/engine/current/nfqws2

[Service]
Type=simple
User={user}
Group={group}
Environment=HOME={home}
ExecStart=/usr/bin/python3 -I /opt/kich-dpi/app/bin/kich-dpi _run
ExecStopPost=/usr/bin/python3 -I /opt/kich-dpi/app/bin/kich-dpi _fw-down
Restart=on-failure
RestartSec=3
TimeoutStopSec=6
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
{guards}
PrivateDevices=yes
ProtectKernelTunables=yes
{hardening}

[Install]
WantedBy=multi-user.target
"""

POLKIT_TEMPLATE = """// Installed by kich-dpi. Allows the session user to manage our two units.
polkit.addRule(function(action, subject) {{
  if (action.id !== "org.freedesktop.systemd1.manage-units") return;
  if (subject.user !== "{user}") return;
  var unit = action.lookup("unit");
  if (unit === "{unit}" || unit === "{warp_unit}") return polkit.Result.YES;
}});
"""

WARP_UNIT_TEMPLATE = """# Installed by kich-dpi (Omarchy plugin). Removed by `kich-dpi remove`.
[Unit]
Description=WARP MASQUE tunnel for Omarchy (kich-dpi)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/kich-dpi/mihomo
ConditionPathExists={home}/.config/kich-dpi/warp.yaml

[Service]
Type=simple
User={user}
Group={group}
Environment=HOME={home}
WorkingDirectory={home}/.local/state/kich-dpi
ExecStartPre=/opt/kich-dpi/mihomo -t -f {home}/.config/kich-dpi/warp.yaml -d {home}/.local/state/kich-dpi
ExecStart=/opt/kich-dpi/app/bin/kich-dpi-warp-run
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
{guards}
PrivateDevices=no
DeviceAllow=/dev/net/tun rw
ProtectKernelTunables=no
{hardening}

[Install]
WantedBy=multi-user.target
"""

WARP_RUN_TEMPLATE = '''#!/usr/bin/python3
# Installed by kich-dpi. Starts mihomo only while the WARP toggle is on.
import json
import os
import sys

STATE = {state!r}
MIHOMO = "/opt/kich-dpi/mihomo"
CONFIG = {config!r}
DATA = {data!r}

try:
    with open(STATE, encoding="utf-8") as fh:
        wanted = bool(json.load(fh).get("warp", True))
except (OSError, ValueError):
    wanted = True
if not wanted:
    sys.exit(0)
os.execv(MIHOMO, [MIHOMO, "-f", CONFIG, "-d", DATA])
'''

NFT_SCRIPT = """table inet {table} {{
  set warp_ep {{
    type ipv4_addr
    elements = {{ {warp_ips} }}
  }}
  chain predefrag {{
    type filter hook output priority -401; policy accept;
    meta mark and {mark} != 0 notrack comment "kich-dpi generated"
  }}
  chain out {{
    type filter hook postrouting priority 101; policy accept;
    meta oiftype 65534 return comment "skip tunnels"
    ip daddr @warp_ep return comment "skip WARP endpoints"
    meta mark and {mark} != 0 return
    tcp dport {{ 80, 443 }} ct original packets 1-16 queue num {queue} bypass
    udp dport 443 ct original packets 1-6 queue num {queue} bypass
  }}
  chain in {{
    type filter hook prerouting priority -101; policy accept;
    meta iiftype 65534 return comment "skip tunnels"
    ip saddr @warp_ep return comment "skip WARP endpoints"
    meta mark and {mark} != 0 return
    tcp sport {{ 80, 443 }} ct reply packets 1-12 queue num {queue} bypass
    udp sport 443 ct reply packets 1-4 queue num {queue} bypass
  }}
}}
"""


def unit_text(template, home, **fields):
    return template.format(
        home=home, guards=UNIT_GUARDS.format(home=home),
        hardening=UNIT_HARDENING, **fields,
    )


def source_paths():
    """(package dir, rule-file dir) for the tree this process came from."""
    root = C.SOURCE_ROOT
    package = root / "src" / "kich_dpi"
    if package.is_dir():
        return package, root
    return root / "lib" / "kich_dpi", root / "data" / "rules"


def install_app():
    """Install the Python package, the launcher and the bundled rule lists."""
    package, rules_root = source_paths()
    lib_dest = C.APP_DIR / "lib" / "kich_dpi"
    bin_dest = C.APP_DIR / "bin" / "kich-dpi"
    data_dest = C.APP_DIR / "data" / "rules"
    bin_dest.parent.mkdir(parents=True, exist_ok=True)

    if package.is_dir() and package.resolve() != lib_dest.resolve():
        shutil.rmtree(lib_dest, ignore_errors=True)
        shutil.copytree(package, lib_dest,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    core.write_text(bin_dest, LAUNCHER_TEMPLATE.format(root=str(C.APP_DIR)), 0o755)

    data_dest.mkdir(parents=True, exist_ok=True)
    for name in ("ru-domain.txt", "ru-ip.txt"):
        source = rules_root / name
        if source.is_file() and source.resolve() != (data_dest / name).resolve():
            shutil.copy2(source, data_dest / name)


def merge_config_into_state(home, uid, gid):
    """One-time 0.3.0 layout migration; config stays a symlink to state."""
    legacy = Path(home) / ".config" / C.ENGINE_SLUG
    state = Path(home) / ".local" / "state" / C.ENGINE_SLUG
    state.mkdir(parents=True, exist_ok=True)
    if legacy.is_symlink():
        return state
    if legacy.is_dir():
        for entry in legacy.iterdir():
            target = state / entry.name
            if not target.exists():
                shutil.move(str(entry), str(target))
        legacy.rmdir()
        legacy.symlink_to(state, target_is_directory=True)
    try:
        os.chown(state, uid, gid)
    except OSError:
        pass
    return state


def legacy_enabled_states():
    result = {}
    for unit in (C.UNIT, C.WARP_UNIT):
        state = core.systemctl("is-enabled", unit=unit).stdout.strip()
        result[unit] = state not in ("disabled", "masked", "masked-runtime")
    return result


def install_system(user):
    try:
        group = grp.getgrgid(user.pw_gid).gr_name
    except KeyError:
        group = user.pw_name
    home = Path(user.pw_dir)
    legacy = legacy_enabled_states()
    core.write_text(C.UNIT_PATH, unit_text(
        UNIT_TEMPLATE, user.pw_dir, user=user.pw_name, group=group,
    ))
    core.write_text(C.WARP_UNIT_PATH, unit_text(
        WARP_UNIT_TEMPLATE, user.pw_dir, user=user.pw_name, group=group,
    ))
    core.write_text(C.POLKIT_PATH, POLKIT_TEMPLATE.format(
        user=user.pw_name, unit=C.UNIT, warp_unit=C.WARP_UNIT,
    ))
    core.write_text(C.SYSCTL_PATH, "net.netfilter.nf_conntrack_tcp_be_liberal=1\n")
    core.run(["systemctl", "daemon-reload"], timeout=30)
    for unit in (C.UNIT, C.WARP_UNIT):
        core.run(["systemctl", "enable", unit], timeout=30)

    merge_config_into_state(home, user.pw_uid, user.pw_gid)
    state_path = home / ".config" / C.ENGINE_SLUG / "state.json"
    if not state_path.exists():
        core.write_json(state_path, {
            "version": 1, "dpi": legacy[C.UNIT], "warp": legacy[C.WARP_UNIT],
        })
    try:
        os.chown(state_path, user.pw_uid, user.pw_gid)
    except OSError:
        pass

    C.WARP_RUN.parent.mkdir(parents=True, exist_ok=True)
    core.write_text(C.WARP_RUN, WARP_RUN_TEMPLATE.format(
        state=str(state_path),
        config=str(home / ".config" / C.ENGINE_SLUG / "warp.yaml"),
        data=str(home / ".local" / "state" / C.ENGINE_SLUG),
    ), 0o755)
    warp.migrate_account(home, user.pw_uid, user.pw_gid)

    for path in (Path("/run") / C.ENGINE_SLUG,):
        shutil.rmtree(path, ignore_errors=True)
    core.run(["sysctl", "-q", "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1"],
             timeout=10)


def restart_services(was_running):
    if was_running:
        core.systemctl("restart", timeout=30)
    if warp.warp_unit_state()[0] == "active":
        warp.warp_systemctl("restart", timeout=30)


def refresh_warp_config(user):
    """Re-render derived user files from the freshly installed app."""
    home = Path(user.pw_dir)
    config = home / ".config" / C.ENGINE_SLUG / "warp.yaml"
    warp.migrate_account(home)
    account = home / ".local" / "state" / C.ENGINE_SLUG / "account.json"
    if not config.is_file() or not account.is_file():
        return ""
    cp = core.run([
        "runuser", "-u", user.pw_name, "--", "env",
        "HOME=%s" % user.pw_dir, "USER=%s" % user.pw_name,
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        str(C.APP_DIR / "bin" / "kich-dpi"), "warp-config",
    ], timeout=90)
    if cp.returncode != 0:
        return (cp.stderr or cp.stdout).strip()[-200:]
    return ""


def finish_system_update(user, was_running):
    note = refresh_warp_config(user)
    restart_services(was_running)
    return note


def download(url, dest):
    import urllib.request
    with urllib.request.urlopen(core.http_request(url), timeout=120) as resp, \
            open(dest, "wb") as fh:
        shutil.copyfileobj(resp, fh, 1024 * 256)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()


def github_latest_tag(repo):
    """Resolve the latest release tag without the rate-limited API."""
    import urllib.error
    import urllib.request
    url = "https://github.com/%s/releases/latest" % repo
    try:
        with urllib.request.urlopen(core.http_request(url), timeout=25) as resp:
            final = resp.geturl()
    except urllib.error.HTTPError as exc:
        raise core.Fail("GitHub ответил HTTP %s" % exc.code)
    except urllib.error.URLError as exc:
        raise core.Fail("нет связи с GitHub: %s" % exc.reason)
    tag = final.rstrip("/").rsplit("/", 1)[-1]
    if not tag.startswith("v"):
        raise core.Fail("не удалось определить версию релиза")
    return tag


def release_info():
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(
                core.http_request(C.RELEASE_API, json_api=True), timeout=30) as resp:
            data = json.load(resp)
        tag = str(data.get("tag_name") or "")
        assets = {str(a.get("name")): a for a in data.get("assets") or []}
        name = "zapret2-%s.tar.gz" % tag
        asset = assets.get(name)
        if not tag or not asset:
            raise core.Fail("в последнем релизе zapret2 нет %s" % name)
        return tag, str(asset.get("browser_download_url") or ""), str(asset.get("digest") or "")
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise
        tag = github_latest_tag("bol-van/zapret2")
        name = "zapret2-%s.tar.gz" % tag
        url = "https://github.com/bol-van/zapret2/releases/download/%s/%s" % (tag, name)
        return tag, url, ""


def extract_engine(archive, tag):
    arch = core.machine_arch()
    stage = C.ENGINE_DIR / (".%s.new" % tag)
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="kich-dpi-") as tmp:
        tmpdir = Path(tmp)
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                name = Path(member.name)
                if name.is_absolute() or ".." in name.parts:
                    continue
                tf.extract(member, tmpdir)

        roots = [p for p in tmpdir.iterdir() if p.is_dir()]
        if not roots:
            raise core.Fail("архив zapret2 пуст")
        root = roots[0]
        binary = root / "binaries" / ("linux-" + arch) / "nfqws2"
        if not binary.exists():
            raise core.Fail("в релизе нет nfqws2 для linux-%s" % arch)
        shutil.copy2(binary, stage / "nfqws2")
        os.chmod(stage / "nfqws2", 0o755)

        lua_src = root / "lua"
        if not lua_src.is_dir():
            raise core.Fail("в релизе нет lua/")
        shutil.copytree(lua_src, stage / "lua")
        fake_src = root / "files" / "fake"
        if not fake_src.is_dir():
            raise core.Fail("в релизе нет files/fake")
        shutil.copytree(fake_src, stage / "files" / "fake")

    target = C.ENGINE_DIR / tag
    shutil.rmtree(target, ignore_errors=True)
    stage.rename(target)
    current = C.ENGINE_DIR / "current"
    if current.is_symlink() or current.exists():
        current.unlink()
    current.symlink_to(tag)
    return target


def install_mihomo():
    """Download mihomo next to the DPI engine. Root only; called from setup."""
    if warp.warp_available():
        return warp.mihomo_version()
    arch = {"x86_64": "amd64", "arm64": "arm64"}.get(core.machine_arch())
    if not arch:
        raise core.Fail("нет сборки mihomo для архитектуры %s" % core.machine_arch())

    local = os.environ.get("KICH_DPI_MIHOMO_ARCHIVE")
    if local:
        tag, url, digest = "custom", "", ""
        source = Path(local)
        if not source.exists():
            raise core.Fail("архив mihomo не найден: %s" % local)
    else:
        import json as _json
        import urllib.error
        import urllib.request
        api = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
        tag, digest, assets = "", "", {}
        try:
            with urllib.request.urlopen(core.http_request(api, json_api=True), timeout=25) as resp:
                data = _json.load(resp)
            tag = str(data.get("tag_name") or "")
            assets = {str(a.get("name")): a for a in data.get("assets") or []}
        except Exception:
            pass
        if not tag:
            tag = github_latest_tag("MetaCubeX/mihomo")
        names = ("mihomo-linux-%s-compatible-%s.gz" % (arch, tag),
                 "mihomo-linux-%s-%s.gz" % (arch, tag))
        source = None
        url, digest = "", ""
        for name in names:
            asset = assets.get(name)
            if asset:
                url = str(asset.get("browser_download_url") or "")
                digest = str(asset.get("digest") or "")
                break
        if not url:
            for name in names:
                candidate = ("https://github.com/MetaCubeX/mihomo/releases/download/"
                             "%s/%s" % (tag, name))
                if warp.remote_exists(candidate):
                    url = candidate
                    break
        if not url:
            raise core.Fail("не удалось найти сборку mihomo %s для %s" % (tag, arch))

    with tempfile.TemporaryDirectory(prefix="kich-dpi-mihomo-") as tmp:
        archive = Path(tmp) / "mihomo.gz"
        if local:
            shutil.copy2(source, archive)
        else:
            try:
                download(url, archive)
            except Exception as exc:
                raise core.Fail("не удалось скачать mihomo: %s" % exc)
        if digest.startswith("sha256:") and \
                ("sha256:" + sha256_file(archive)).lower() != digest.lower():
            raise core.Fail("sha256 mihomo не совпал")
        target = C.MIHOMO.with_name(".mihomo.new")
        try:
            with gzip.open(archive, "rb") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 256)
        except (OSError, gzip.BadGzipFile) as exc:
            raise core.Fail("повреждён архив mihomo: %s" % exc)
        os.chmod(target, 0o755)
        check = core.run([str(target), "-v"], timeout=20)
        if check.returncode != 0:
            target.unlink(missing_ok=True)
            raise core.Fail("скачанный mihomo не запускается")
        os.replace(target, C.MIHOMO)
    core.write_json(C.ENGINE_ROOT / "mihomo.json", {
        "version": tag, "installed": int(time.time()), "sha256": digest,
    })
    return tag


def cmd_setup(archive_arg=""):
    core.require_root()
    user = core.target_user()
    was_running = core.is_running()
    previous = core.installed_version()

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
                install_app()
                install_system(user)
                note = finish_system_update(user, was_running)
                core.out({"ok": True, "version": previous, "previous": previous,
                          "note": "сеть недоступна, системная часть обновлена без движка",
                          "warp_config": note, "detail": str(exc)[:200]})
                return
            raise core.Fail("не удалось получить релиз zapret2: %s" % exc)

    if archive or tag != previous or not (C.ENGINE_DIR / tag / "nfqws2").exists():
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

    core.write_json(C.ENGINE_ROOT / "install.json", {
        "version": tag, "installed": int(time.time()), "sha256": digest,
    })
    core.write_text(C.ENGINE_ROOT / "README", (
        "Engine: zapret2 by bol-van (https://github.com/bol-van/zapret2).\n"
        "Installed by the kich-dpi Omarchy plugin. The plugin code is MIT.\n"
    ))
    install_app()
    install_system(user)

    warp_note = ""
    try:
        install_mihomo()
    except core.Fail as exc:
        warp_note = str(exc)[:200]

    note = finish_system_update(user, was_running)
    core.out({"ok": True, "version": tag, "previous": previous,
              "user": user.pw_name, "installed": int(time.time()),
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


def fw_rule(action):
    return ["ip", "rule", action, "fwmark", "%s/%s" % (C.FWMARK, C.FWMARK),
            "lookup", "main", "priority", str(C.DPI_RULE_PRIORITY)]


def fw_up():
    script = NFT_SCRIPT.format(table=C.TABLE, mark=C.FWMARK, queue=C.QUEUE,
                               warp_ips=", ".join(C.WARP_ENDPOINTS))
    core.run(["nft", "delete", "table", "inet", C.TABLE])
    cp = core.run(["nft", "-f", "-"], input=script)
    if cp.returncode != 0:
        raise core.Fail("nft: " + core.unit_error(cp, "", 500))
    core.run(fw_rule("del"))
    cp = core.run(fw_rule("add"))
    if cp.returncode != 0:
        raise core.Fail("ip rule: " + core.unit_error(cp, "", 500))


def fw_down():
    core.run(["nft", "delete", "table", "inet", C.TABLE], timeout=10)
    core.run(fw_rule("del"), timeout=10)


def cmd_fw_down():
    fw_down()
    return 0


def supervise_child(child):
    """Forward stop signals to nfqws2 and wait for it to exit."""
    stopping = {"value": False}

    def stop(_signum, _frame):
        stopping["value"] = True
        if child and child.poll() is None:
            child.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        code = child.poll()
        if code is not None:
            break
        time.sleep(0.3)
        if stopping["value"] and child.poll() is None:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
    return stopping["value"]


def cmd_run():
    if not core.installed():
        core.log("kich-dpi: engine is not installed")
        return 1
    if not core.wanted_flags()["dpi"]:
        core.log("kich-dpi: выключено (state.json), ничего не запускаю")
        return 0

    from . import warp as _warp  # noqa: F401  (user lists are shared with WARP)
    _warp.ensure_user_lists()
    spec = strategies.active_spec_from(core.read_dict(C.ACTIVE_FILE),
                                       strategies.default_spec)
    conf = C.STATE_DIR / "nfqws2.conf"
    try:
        C.STATE_DIR.mkdir(parents=True, exist_ok=True)
        core.write_text(conf, strategies.render_config(spec), 0o600)
        fw_up()
    except (OSError, core.Fail) as exc:
        core.log("kich-dpi: setup failed: %s" % exc)
        return 1

    try:
        child = subprocess.Popen([str(core.engine_bin()), "@%s" % conf])
    except OSError as exc:
        core.log("kich-dpi: cannot start nfqws2: %s" % exc)
        fw_down()
        return 1

    stopping = supervise_child(child)
    fw_down()
    return 0 if stopping else (child.returncode or 0)
