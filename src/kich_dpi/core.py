"""Small shared primitives: files, commands, units and user state."""
from __future__ import annotations

import json
import os
import platform
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import constants as C


class Fail(Exception):
    """An error that should reach the panel as a short JSON message."""


def out(data):
    sys.stdout.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n")


def log(text):
    sys.stderr.write(str(text).rstrip() + "\n")


def read_json(path, fallback):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, (dict, list)) else fallback
    except (OSError, ValueError):
        return fallback


def read_dict(path):
    data = read_json(path, {})
    return data if isinstance(data, dict) else {}


def read_list(path):
    data = read_json(path, [])
    return data if isinstance(data, list) else []


def atomic_write(path, text, mode=None):
    """Write through a temp file so readers never see a half-written file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def write_text(path, text, mode=0o644):
    atomic_write(path, text, mode)


def write_json(path, data, mode=None):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=1) + "\n", mode)


def run(argv, timeout=20, text=True, input=None):
    """Every external command goes through here, so tests patch one place."""
    try:
        return subprocess.run(
            [str(a) for a in argv], capture_output=True, text=text,
            timeout=timeout, input=input,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(argv, 1, "" if text else b"", str(exc))


def unit_error(cp, fallback="", limit=400):
    return (cp.stderr or cp.stdout or fallback).strip()[-limit:]


def checked_unit_call(call, action, fallback, timeout):
    cp = call(action, timeout=timeout)
    if cp.returncode != 0:
        raise Fail(unit_error(cp, fallback))
    return cp


def systemctl(*args, timeout=25, unit=None):
    return run(["systemctl", *args, unit or C.UNIT], timeout=timeout)


def unit_state(unit=None, path=None, missing_ok=True):
    unit = unit or C.UNIT
    path = Path(path) if path is not None else C.UNIT_PATH
    if not path.exists() and not (missing_ok and installed()):
        return "inactive", "not-found"
    active = systemctl("is-active", unit=unit).stdout.strip() or "inactive"
    enabled = systemctl("is-enabled", unit=unit).stdout.strip() or "disabled"
    return active, enabled


def batched_unit_states(units):
    """Active/enabled for several units from one `systemctl show`."""
    units = list(dict.fromkeys(units))
    result = {u: ("inactive", "not-found") for u in units}
    if not units:
        return result
    cp = run(
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
    return unit_state()[0] == "active"


def engine_bin():
    return C.ENGINE_DIR / "current" / "nfqws2"


def engine_lua(name):
    return C.ENGINE_DIR / "current" / "lua" / name


def engine_info():
    version = str(read_dict(C.ENGINE_ROOT / "install.json").get("version") or "")
    if not engine_bin().exists():
        return "", False
    version = version or "установлен"
    return version, (engine_lua("zapret-lib.lua").exists()
                     and engine_lua("zapret-antidpi.lua").exists())


def installed_version():
    return engine_info()[0]


def installed():
    return engine_info()[1]


def wanted_flags():
    data = read_dict(C.STATE_FILE)
    return {"dpi": data.get("dpi", True), "warp": data.get("warp", True)}


def set_wanted(key, value):
    data = read_dict(C.STATE_FILE)
    data["version"] = 1
    data[key] = bool(value)
    write_json(C.STATE_FILE, data)


def require_root():
    if os.geteuid() != 0:
        raise Fail("нужен root: запустите через pkexec")


def target_user():
    uid = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
    if uid:
        try:
            return pwd.getpwuid(int(uid))
        except (ValueError, KeyError):
            pass
    if os.geteuid() != 0:
        return pwd.getpwuid(os.geteuid())
    raise Fail("не удалось определить пользователя: запустите установку из своей сессии")


def machine_arch():
    machine = platform.machine().lower()
    table = {
        "x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64",
        "arm64": "arm64", "armv7l": "arm", "armv6l": "arm", "i686": "x86",
        "i386": "x86", "riscv64": "riscv64", "mips": "mips", "mipsel": "mipsel",
        "mips64": "mips64", "ppc": "ppc",
    }
    return table.get(machine, machine)


def curl_available():
    return shutil.which("curl") is not None


def http_request(url, method="GET", json_api=False):
    import urllib.request
    headers = {"User-Agent": "kich-dpi/%s" % C.VERSION}
    if json_api:
        headers["Accept"] = "application/vnd.github+json"
    return urllib.request.Request(url, headers=headers, method=method)


def device_from_route(text):
    parts = str(text or "").split()
    if "dev" in parts:
        index = parts.index("dev") + 1
        if index < len(parts):
            return parts[index]
    return ""


def default_device(text):
    return device_from_route(text)


def direct_device():
    """Physical interface from the main table, not the WARP policy table."""
    cp = run(["ip", "-4", "route", "show", "default", "table", "main"], timeout=5)
    return default_device(cp.stdout)


def route_device():
    """Device the kernel picks for ordinary outbound traffic."""
    cp = run(["ip", "route", "get", "1.1.1.1"], timeout=5)
    return device_from_route(cp.stdout)


def tcp_reachable(host, port=443, timeout=3):
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def list_lines(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
