"""Installation, release lookup and system update helpers for kich-dpi."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path

from . import constants as C
from . import core
from . import ownership
from . import warp
from .templates import LAUNCHER_TEMPLATE


def source_paths():
    """(package dir, rule-file dir) for the tree this process came from."""
    root = C.SOURCE_ROOT
    package = root / "src" / "kich_dpi"
    if package.is_dir():
        return package, root
    return root / "lib" / "kich_dpi", root / "data" / "rules"


def _tree_files(root):
    """Content of the files that belong in an installed package tree."""
    files = {}
    if not root.is_dir():
        return files
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        parts = path.relative_to(root).parts
        if "__pycache__" in parts or any(p.endswith(".pyc") for p in parts):
            continue
        try:
            files[path.relative_to(root).as_posix()] = path.read_bytes()
        except OSError:
            return None
    return files


def _sync_tree(source, dest):
    """Replace a tree only when its content differs; return whether it changed."""
    wanted = _tree_files(source)
    if wanted is not None and wanted == _tree_files(dest):
        return False
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(source, dest,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return True


def text_changed(path, text):
    """True when a file is missing or its content differs from `text`."""
    try:
        return path.read_text(encoding="utf-8") != text
    except (OSError, UnicodeError):
        return True


def install_app():
    """Install the Python package, the launcher and the bundled rule lists.

    Returns whether anything changed, so `setup` can avoid restarting services
    that are already running the exact same code.
    """
    package, rules_root = source_paths()
    lib_dest = C.APP_DIR / "lib" / "kich_dpi"
    bin_dest = C.APP_DIR / "bin" / "kich-dpi"
    data_dest = C.APP_DIR / "data" / "rules"
    bin_dest.parent.mkdir(parents=True, exist_ok=True)

    changed = False
    if package.is_dir() and package.resolve() != lib_dest.resolve():
        changed = _sync_tree(package, lib_dest)
    launcher = LAUNCHER_TEMPLATE.format(root=str(C.APP_DIR))
    if text_changed(bin_dest, launcher):
        core.write_text(bin_dest, launcher, 0o755)
        changed = True

    data_dest.mkdir(parents=True, exist_ok=True)
    for name in ("ru-domain.txt", "ru-ip.txt"):
        source = rules_root / name
        target = data_dest / name
        if not source.is_file() or source.resolve() == target.resolve():
            continue
        try:
            same = target.is_file() and source.read_bytes() == target.read_bytes()
        except OSError:
            same = False
        if not same:
            shutil.copy2(source, target)
            changed = True
    return changed


def chown_tree(path, uid, gid):
    """Give the target user the state/config tree created by root setup."""
    ownership.chown_tree(path, uid, gid)


def merge_config_into_state(home, uid, gid):
    """One-time 0.3.0 layout migration; config stays a symlink to state."""
    legacy = Path(home) / ".config" / C.ENGINE_SLUG
    state = Path(home) / ".local" / "state" / C.ENGINE_SLUG
    state.mkdir(parents=True, exist_ok=True)
    if legacy.is_symlink():
        chown_tree(state, uid, gid)
        return state
    if legacy.is_dir():
        for entry in legacy.iterdir():
            target = state / entry.name
            if not target.exists():
                shutil.move(str(entry), str(target))
                continue
            # Never clobber newer state. Keep the old file alongside as a
            # backup so the migration can still finish and create the symlink.
            backup = state / (entry.name + ".from-config")
            if entry.is_file() and not backup.exists():
                shutil.move(str(entry), str(backup))
            else:
                entry.unlink()
        legacy.rmdir()
        legacy.symlink_to(state, target_is_directory=True)
    chown_tree(state, uid, gid)
    return state
def enabled_state(unit):
    return core.systemctl("is-enabled", unit=unit).stdout.strip()


def legacy_enabled_states():
    result = {}
    for unit in (C.UNIT, C.WARP_UNIT):
        result[unit] = enabled_state(unit) not in ("disabled", "masked", "masked-runtime")
    return result


def needs_enabling(unit):
    """Enable a unit only if systemd does not already consider it enabled."""
    return enabled_state(unit) in ("", "not-found", "disabled",
                                   "masked", "masked-runtime")
def restart_services(was_running, changed=True):
    """Restart only services affected by an actual change."""
    if not changed:
        return
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


def finish_system_update(user, was_running, changed=True):
    """Only re-render WARP and restart services after a real change."""
    note = refresh_warp_config(user) if changed else ""
    restart_services(was_running, changed)
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
    backup = C.ENGINE_DIR / (".%s.old" % tag)
    shutil.rmtree(backup, ignore_errors=True)
    moved_old = False
    if target.exists() or target.is_symlink():
        target.rename(backup)
        moved_old = True
    try:
        stage.rename(target)
    except BaseException:
        if moved_old:
            backup.rename(target)
        raise
    current = C.ENGINE_DIR / "current"
    link = C.ENGINE_DIR / ".current.tmp"
    try:
        link.unlink()
    except OSError:
        pass
    try:
        link.symlink_to(tag)
        os.replace(link, current)
    except BaseException:
        try:
            link.unlink()
        except OSError:
            pass
        if moved_old:
            shutil.rmtree(target, ignore_errors=True)
            backup.rename(target)
        raise
    if moved_old:
        shutil.rmtree(backup, ignore_errors=True)
    return target


def _record_mihomo(version, digest=""):
    """Persist which binary is installed; content-compare keeps this a no-op."""
    core.write_json(C.ENGINE_ROOT / "mihomo.json", {
        "version": version, "installed": int(time.time()), "sha256": digest,
    })


def _mihomo_version_from_binary():
    """Best-effort version of an already-installed binary (heals a lost stamp)."""
    cp = core.run([str(C.MIHOMO), "-v"], timeout=10)
    text = ((cp.stdout or "") + " " + (cp.stderr or "")).strip()
    for token in text.split():
        candidate = token.lstrip("v").rstrip(",;")
        if candidate[:1].isdigit() and "." in candidate:
            return candidate
    return ""


def install_mihomo():
    """Download mihomo next to the DPI engine. Root only; called from setup."""
    if warp.warp_available():
        version = warp.mihomo_version()
        if not version:
            version = _mihomo_version_from_binary()
            if version:
                _record_mihomo(version)
        return version
    arch = {"x86_64": "amd64", "arm64": "arm64"}.get(core.machine_arch())
    if not arch:
        raise core.Fail("нет сборки mihomo для архитектуры %s" % core.machine_arch())
    C.ENGINE_ROOT.mkdir(parents=True, exist_ok=True)

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
    _record_mihomo(tag, digest)
    return tag
