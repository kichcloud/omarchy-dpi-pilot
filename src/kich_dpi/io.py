"""JSON, text files and stdout primitives shared by every command."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


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
    """Write through a temp file, but only when the content really changed."""
    path = Path(path)
    data = str(text).encode("utf-8")
    try:
        if path.is_file() and path.read_bytes() == data:
            if mode is not None and (path.stat().st_mode & 0o777) != mode:
                os.chmod(path, mode)
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def write_text(path, text, mode=0o644):
    atomic_write(path, text, mode)


def write_json(path, data, mode=None):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=1) + "\n", mode)


def clip(text, fallback="", limit=400, *, tail=False, strip=True):
    """Trim a diagnostic to the exact head/tail length its caller expects."""
    value = text or fallback
    value = str(value).strip() if strip else str(value)
    return value[-limit:] if tail else value[:limit]
