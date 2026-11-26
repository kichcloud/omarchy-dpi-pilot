"""Long-running nfqws2 supervisor."""
from __future__ import annotations

import signal
import subprocess
import time

from . import constants as C
from . import core
from . import strategies
from . import warp
from .firewall import fw_down, fw_up


def supervise_child(child):
    """Forward stop signals to nfqws2 and wait for it to exit."""
    stopping = {"value": False}

    def stop(_signum, _frame):
        stopping["value"] = True
        if child and child.poll() is None:
            child.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        code = child.poll()
        if code is not None:
            break
        time.sleep(0.3)
        if stopping["value"] and child.poll() is None:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
    return stopping["value"]


def cmd_run():
    if not core.installed():
        core.log("kich-dpi: engine is not installed")
        return 1
    if not core.wanted_flags()["dpi"]:
        core.log("kich-dpi: выключено (state.json), ничего не запускаю")
        return 0

    warp.ensure_user_lists()  # user lists are shared with WARP
    spec = strategies.active_spec_from(core.read_dict(C.ACTIVE_FILE),
                                       strategies.default_spec)
    conf = C.STATE_DIR / "nfqws2.conf"
    try:
        C.STATE_DIR.mkdir(parents=True, exist_ok=True)
        core.write_text(conf, strategies.render_config(spec), 0o600)
        fw_up()
    except (OSError, core.Fail) as exc:
        core.log("kich-dpi: setup failed: %s" % exc)
        return 1

    try:
        child = subprocess.Popen([str(core.engine_bin()), "@%s" % conf])
    except OSError as exc:
        core.log("kich-dpi: cannot start nfqws2: %s" % exc)
        fw_down()
        return 1

    stopping = supervise_child(child)
    fw_down()
    return 0 if stopping else (child.returncode or 0)
