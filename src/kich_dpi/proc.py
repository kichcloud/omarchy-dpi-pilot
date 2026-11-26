"""The single external-command entry point used by all commands."""
from __future__ import annotations

import subprocess as _subprocess


def run(argv, timeout=20, text=True, input=None, *, subprocess_module=None):
    sp = subprocess_module or _subprocess
    try:
        return sp.run(
            [str(a) for a in argv], capture_output=True, text=text,
            timeout=timeout, input=input,
        )
    except (OSError, sp.SubprocessError) as exc:
        return sp.CompletedProcess(argv, 1, "" if text else b"", str(exc))
