"""Installed engine and desired-state files."""
from __future__ import annotations

from . import constants as C
from . import core


def engine_bin():
    return C.ENGINE_DIR / "current" / "nfqws2"


def engine_lua(name):
    return C.ENGINE_DIR / "current" / "lua" / name


def engine_info():
    version = str(core.read_dict(C.ENGINE_ROOT / "install.json").get("version") or "")
    if not core.engine_bin().exists():
        return "", False
    version = version or "установлен"
    return version, (core.engine_lua("zapret-lib.lua").exists()
                     and core.engine_lua("zapret-antidpi.lua").exists())


def installed_version():
    return core.engine_info()[0]


def installed():
    return core.engine_info()[1]


def wanted_flags():
    data = core.read_dict(C.STATE_FILE)
    return {"dpi": data.get("dpi", True), "warp": data.get("warp", True)}


def set_wanted(key, value):
    data = core.read_dict(C.STATE_FILE)
    value = bool(value)
    if bool(data.get(key, True)) == value and data.get("version") == 1:
        return
    data["version"] = 1
    data[key] = value
    core.write_json(C.STATE_FILE, data)
