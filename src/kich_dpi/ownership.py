"""Ownership repairs for files created by root-run setup/pkexec actions."""
from __future__ import annotations

import os


def _owned(path, uid, gid, os_module):
    stat = getattr(os_module, "stat", None)
    if stat is None:
        return False
    try:
        info = stat(path)
    except OSError:
        return False
    return info.st_uid == uid and info.st_gid == gid


def chown_tree(path, uid, gid, *, os_module=None, swallow=True):
    """Give `uid:gid` a tree created by root, deepest entries first."""
    os_module = os_module or os
    try:
        if path.is_dir():
            for root, dirs, files in os_module.walk(path):
                for name in dirs + files:
                    child = os.path.join(root, name)
                    if not _owned(child, uid, gid, os_module):
                        os_module.chown(child, uid, gid)
        elif path.exists() and not _owned(path, uid, gid, os_module):
            os_module.chown(path, uid, gid)
        if not _owned(path, uid, gid, os_module):
            os_module.chown(path, uid, gid)
    except OSError:
        if not swallow:
            raise


def chown_with_parents(paths, uid, gid, *, os_module=None):
    """Chown files plus their parents: atomic writes need a writable parent."""
    os_module = os_module or os
    for path in paths:
        chown_tree(path, uid, gid, os_module=os_module, swallow=False)
        if path.parent.exists() and not _owned(path.parent, uid, gid, os_module):
            os_module.chown(path.parent, uid, gid)
