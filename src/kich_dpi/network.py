"""Routing, interface and socket probes shared by status and repair."""
from __future__ import annotations

import platform
import shutil
from pathlib import Path

from . import constants as C
from . import core


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
    return core.device_from_route(text)


def direct_device():
    """Physical interface from the main table, not the WARP policy table."""
    cp = core.run(["ip", "-4", "route", "show", "default", "table", "main"], timeout=5)
    return core.default_device(cp.stdout)


def route_device():
    """Device the kernel picks for ordinary outbound traffic."""
    cp = core.run(["ip", "route", "get", "1.1.1.1"], timeout=5)
    return core.device_from_route(cp.stdout)


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
