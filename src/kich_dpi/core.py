"""Stable facade over the small primitives used by every command.

The names here are also the patch points used by tests and callers: keep them
as forwarding functions, not aliases, so patching `core.run` or `core.out`
still affects every helper.
"""
from __future__ import annotations

import os
import subprocess

from . import constants as C
from . import identity as _identity
from . import io as _io
from . import network as _network
from . import proc as _proc
from . import state as _state
from . import units as _units
from .errors import Fail


def out(data):
    return _io.out(data)


def log(text):
    return _io.log(text)


def clip(text, fallback="", limit=400, *, tail=False, strip=True):
    return _io.clip(text, fallback, limit, tail=tail, strip=strip)


def read_json(path, fallback):
    return _io.read_json(path, fallback)


def read_dict(path):
    return _io.read_dict(path)


def read_list(path):
    return _io.read_list(path)


def atomic_write(path, text, mode=None):
    return _io.atomic_write(path, text, mode)


def write_text(path, text, mode=0o644):
    return _io.write_text(path, text, mode)


def write_json(path, data, mode=None):
    return _io.write_json(path, data, mode)


def run(argv, timeout=20, text=True, input=None):
    return _proc.run(argv, timeout, text, input, subprocess_module=subprocess)


def unit_error(cp, fallback="", limit=400):
    return _units.unit_error(cp, fallback, limit)


def checked_unit_call(call, action, fallback, timeout):
    return _units.checked_unit_call(call, action, fallback, timeout)


def systemctl(*args, timeout=25, unit=None):
    return _units.systemctl(*args, timeout=timeout, unit=unit)


def unit_state(unit=None, path=None, missing_ok=True):
    return _units.unit_state(unit, path, missing_ok)


def batched_unit_states(units):
    return _units.batched_unit_states(units)


def is_running():
    return _units.is_running()


def engine_bin():
    return _state.engine_bin()


def engine_lua(name):
    return _state.engine_lua(name)


def engine_info():
    return _state.engine_info()


def installed_version():
    return _state.installed_version()


def installed():
    return _state.installed()


def wanted_flags():
    return _state.wanted_flags()


def set_wanted(key, value):
    return _state.set_wanted(key, value)


def require_root():
    return _identity.require_root(os)


def target_user():
    return _identity.target_user(os)


def machine_arch():
    return _network.machine_arch()


def curl_available():
    return _network.curl_available()


def http_request(url, method="GET", json_api=False):
    return _network.http_request(url, method, json_api)


def device_from_route(text):
    return _network.device_from_route(text)


def default_device(text):
    return _network.default_device(text)


def direct_device():
    return _network.direct_device()


def route_device():
    return _network.route_device()


def tcp_reachable(host, port=443, timeout=3):
    return _network.tcp_reachable(host, port, timeout)


def list_lines(path):
    return _network.list_lines(path)
