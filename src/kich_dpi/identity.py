"""Root/session identity resolution for pkexec and sudo callers."""
from __future__ import annotations

import os
import pwd

from .errors import Fail


def require_root(os_module=os):
    if os_module.geteuid() != 0:
        raise Fail("нужен root: запустите через pkexec")


def target_user(os_module=os):
    uid = os_module.environ.get("PKEXEC_UID") or os_module.environ.get("SUDO_UID")
    if uid:
        try:
            return pwd.getpwuid(int(uid))
        except (ValueError, KeyError):
            pass
    if os_module.geteuid() != 0:
        return pwd.getpwuid(os_module.geteuid())
    raise Fail("не удалось определить пользователя: запустите установку из своей сессии")
