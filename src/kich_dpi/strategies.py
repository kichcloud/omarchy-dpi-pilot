"""DPI strategies: render one config, measure it, keep the best one."""
from __future__ import annotations

import sys
import time

from . import constants as C
from . import core
from . import generation as _generation
from .dpi_specs import (
    FOOLING, PRIORITY_WEIGHTS, SANITY_TARGETS, candidates, default_spec,
    dpi_domains, render_config, strategy_id, strategy_name,
)

_self = sys.modules[__name__]


def http_probes(urls, timeout, interface=""):
    """One curl for many URLs; returns (ok, code, ms, error) per URL."""
    started = time.monotonic()
    args = [
        "curl", "-sS", "--connect-timeout", "4",
        "--max-time", str(timeout), "-A", "Mozilla/5.0 (X11; Linux x86_64)",
        "-w", "%{http_code} %{time_total}\\n",
    ]
    if interface:
        args += ["--interface", interface, "-4"]
    for url in urls:
        args += ["-o", "/dev/null", url]
    cp = core.run(args, timeout=timeout * max(1, len(urls)) + 3)
    lines = (cp.stdout or "").splitlines()
    stderr = (cp.stderr or "").strip()
    error = stderr.splitlines()[-1] if stderr else ""
    answers = []
    for index in range(len(urls)):
        parts = lines[index].split() if index < len(lines) else []
        code = int(parts[0]) if parts and parts[0].isdigit() else 0
        try:
            elapsed = float(parts[1]) if len(parts) > 1 else None
        except ValueError:
            elapsed = None
        if elapsed is None:
            elapsed = time.monotonic() - started
        ok = 200 <= code < 400
        answers.append((ok, code, int(round(elapsed * 1000)),
                        "" if ok else core.clip(error, limit=160, strip=False)))
    return answers


def http_probe(url, timeout, interface=""):
    """One request; kept for single-URL callers and tests."""
    return http_probes([url], timeout, interface)[0]


def probe_rows(targets, answers):
    return [{"key": key, "label": label, "ok": ok, "code": code,
             "ms": ms, "error": error}
            for (key, label, _url), (ok, code, ms, error) in zip(targets, answers)]


def probe(targets=C.TARGETS, timeout=7, direct=False, interface=None):
    if not core.curl_available():
        raise core.Fail("не найден curl")
    device = interface if interface is not None else (core.direct_device() if direct else "")
    results = probe_rows(targets, http_probes([url for _key, _label, url in targets],
                                              timeout, device))
    passed = sum(1 for row in results if row["ok"])
    latency = sum(row["ms"] for row in results if row["ok"]) if passed else 10 ** 9
    return {
        "time": int(time.time()), "passed": passed, "total": len(results),
        "ms": latency, "results": results, "direct": bool(device),
    }


def sanity(timeout=6, device=None):
    """Reject a strategy that breaks TLS to hosts which are not blocked."""
    if device is None:
        device = core.direct_device()
    targets = [(key, key, url) for key, url in SANITY_TARGETS]
    results = probe_rows(targets, http_probes([url for _key, _label, url in targets],
                                              timeout, device))
    retry = [(index, row) for index, row in enumerate(results) if not row["ok"]]
    if retry:
        time.sleep(0.2)
        again = http_probes([targets[index][2] for index, _row in retry],
                           timeout, device)
        for (index, _row), answer in zip(retry, again):
            results[index] = probe_rows([targets[index]], [answer])[0]
    return {"ok": all(row["ok"] for row in results), "device": device,
            "results": results}


def priority_health(result, check):
    got = 0
    for row in result.get("results", []):
        weight = PRIORITY_WEIGHTS.get(row.get("key"), 0)
        if weight and row.get("ok"):
            got += weight
    for row in check.get("results", []):
        weight = PRIORITY_WEIGHTS.get(row.get("label"), 0)
        if weight and row.get("ok"):
            got += weight
    if not got:
        return (0, -10 ** 9)
    return (got, -int(result.get("ms") or 10 ** 9))


def active_spec_from(doc, fallback=None):
    spec = doc.get("spec") if isinstance(doc, dict) else None
    spec = spec if isinstance(spec, dict) else None
    return spec or (fallback() if callable(fallback) else fallback)


def apply_spec(spec, start=True):
    identifier = strategy_id(spec)
    old = core.read_dict(C.ACTIVE_FILE)
    unchanged = str(old.get("id") or "") == identifier and old.get("spec") == spec
    if not unchanged:
        core.write_json(C.ACTIVE_FILE, {
            "id": identifier, "name": strategy_name(spec),
            "spec": spec, "time": int(time.time()),
        })
    if start:
        core.set_wanted("dpi", True)
        running = core.is_running()
        if unchanged and running:
            return
        action = "restart" if running else "start"
        core.checked_unit_call(core.systemctl, action,
                               "systemctl %s не удался" % action, 30)


def wait_active(timeout=8.0):
    from . import polling
    return polling.wait_until(core.is_running, timeout, 0.25,
                              clock=time.monotonic, sleep=time.sleep)


def cmd_on():
    if not core.installed():
        raise core.Fail("сначала установите движок")
    core.set_wanted("dpi", True)
    if not core.is_running():
        core.checked_unit_call(core.systemctl, "start", "не удалось запустить службу", 35)
    from . import status
    core.out(status.status_data())


def cmd_off():
    core.set_wanted("dpi", False)
    if not core.is_running():
        from . import status
        core.out(status.status_data())
        return
    cp = core.systemctl("stop", timeout=25)
    if cp.returncode != 0 and core.installed():
        raise core.Fail(core.unit_error(cp, "не удалось остановить службу"))
    from . import status
    core.out(status.status_data())


def cmd_toggle():
    if core.is_running():
        cmd_off()
    else:
        cmd_on()


def cmd_restart():
    core.checked_unit_call(core.systemctl, "restart", "systemctl restart не удался", 30)
    from . import status
    core.out(status.status_data())


def run_check():
    """One DPI probe with a cached result; shared by `check` and `check-all`."""
    result = probe()
    core.write_json(C.CHECK_FILE, result)
    return result


def cmd_check():
    if not core.installed():
        raise core.Fail("сначала установите движок")
    core.out({"ok": True, "check": run_check(),
              "running": core.is_running()})


def cmd_use(strategy_id_arg):
    for item in core.read_list(C.STRATEGIES_FILE):
        if isinstance(item, dict) and str(item.get("id")) == str(strategy_id_arg):
            spec = item.get("spec")
            if isinstance(spec, dict):
                apply_spec(spec, start=True)
                core.out({"ok": True, "active_id": strategy_id(spec),
                          "active_name": strategy_name(spec)})
                return
    raise core.Fail("стратегия не найдена")

# Facade: keep patchable names in strategies for callers and tests.
def merge_strategies(rows):
    return _generation.merge_strategies(_self, rows)


def generation_progress(total):
    return _generation.generation_progress(_self, total)


def generation_baseline(device):
    return _generation.generation_baseline(_self, device)


def measure_candidate(spec, device):
    return _generation.measure_candidate(_self, spec, device)


def restore_after_generation(best, baseline, baseline_health, original,
                             fallback, was_running, old_wanted, progress):
    return _generation.restore_after_generation(
        _self, best, baseline, baseline_health, original, fallback,
        was_running, old_wanted, progress)


def generation_final(progress, baseline, best):
    return _generation.generation_final(_self, progress, baseline, best)


def generation_cached(force=False):
    return _generation.generation_cached(_self, force)


def cmd_generate(force=False):
    return _generation.cmd_generate(_self, force)
