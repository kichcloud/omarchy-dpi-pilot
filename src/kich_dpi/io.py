"""JSON, text files and stdout primitives shared by every command."""
from __future__ import annotations

import json
import os
import sys
import tempfile
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


def _sync_directory(path):
    """Make the rename itself durable; not every filesystem supports it."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(path, text, mode=None):
    """Write through a unique temp file, fsync it, then replace.

    A file whose bytes already match is left untouched, so a repeated write is
    a true no-op. An existing file keeps its mode and owner unless `mode` asks
    for another mode.
    """
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
    try:
        previous = path.stat()
    except OSError:
        previous = None
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp",
                                    dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode if mode is not None else
                 (previous.st_mode & 0o777 if previous is not None else 0o644))
        if previous is not None and os.geteuid() == 0:
            try:
                os.chown(tmp, previous.st_uid, previous.st_gid)
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    _sync_directory(path.parent)


def write_text(path, text, mode=0o644):
    atomic_write(path, text, mode)


def write_json(path, data, mode=None):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=1) + "\n", mode)


def clip(text, fallback="", limit=400, *, tail=False, strip=True):
    """Trim a diagnostic to the exact head/tail length its caller expects."""
    value = text or fallback
    value = str(value).strip() if strip else str(value)
    return value[-limit:] if tail else value[:limit]
