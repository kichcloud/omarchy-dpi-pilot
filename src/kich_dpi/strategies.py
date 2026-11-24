"""DPI strategies: render one config, measure it, keep the best one."""
from __future__ import annotations

import fcntl
import hashlib
import json
import time

from . import constants as C
from . import core

FOOLING = {
    "tcp_md5": "tcp_md5",
    "ip_ttl": "ip_ttl=1:ip6_ttl=1",
    "tcp_seq": "tcp_seq=-10000",
    "tcp_flags": "tcp_flags_unset=ack",
}

SANITY_TARGETS = (
    ("ya", "https://ya.ru/"),
    ("example", "https://example.com/"),
    ("aur", "https://aur.archlinux.org/"),
    ("gosuslugi", "https://www.gosuslugi.ru/"),
    ("api-proxyapi", "https://api.proxyapi.ru/"),
    ("console-proxyapi", "https://console.proxyapi.ru/"),
    ("opencode", "https://opencode.ai/inference/openai/v1/models"),
)

PRIORITY_WEIGHTS = {
    "discord": 6, "youtube": 6, "api-proxyapi": 5, "opencode": 5,
    "console-proxyapi": 2, "google": 1,
}


def strategy_name(spec):
    return str(spec.get("name") or "своя стратегия")


def strategy_id(spec):
    payload = json.dumps(spec, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()[:10]


def candidates():
    """A small, ordered tree of nfqws2 configurations to measure."""
    result = []

    def add(name, action, pos, fool, fake="fake_default_tls", repeats=6,
            quic="quic_google", quic_repeats=6):
        result.append({
            "name": name, "action": action, "pos": pos, "fool": fool,
            "fake": fake, "repeats": repeats, "quic": quic,
            "quic_repeats": quic_repeats,
        })

    add("fake + multidisorder", "multidisorder", "1,midsld", "tcp_md5")
    add("fake + multisplit", "multisplit", "midsld", "tcp_md5")
    add("fakeddisorder", "fakeddisorder", "midsld", "tcp_md5", fake=None)
    add("fakedsplit", "fakedsplit", "midsld", "tcp_md5", fake=None)
    add("fake + disorder · TTL", "multidisorder", "1,midsld", "ip_ttl")
    add("fake + split · seq", "multisplit", "midsld", "tcp_seq")
    add("fake ×8 + disorder", "multidisorder", "1,midsld", "tcp_md5", repeats=8,
        quic="fake_default_quic")
    add("fake + split · noack", "multisplit", "midsld", "tcp_flags")
    add("fake + split at 1", "multisplit", "1,midsld", "tcp_md5")
    add("fake + disorder at 2", "multidisorder", "2", "tcp_seq")
    add("fakedsplit at 1", "fakedsplit", "1", "tcp_md5", fake=None)
    add("fake + split · sld", "multisplit", "sld+1", "tcp_md5",
        quic_repeats=4)
    add("fakedsplit · seq", "fakedsplit", "midsld", "tcp_seq", fake=None)
    add("fakedsplit · noack", "fakedsplit", "midsld", "tcp_flags", fake=None)
    add("fakedsplit at 1 · seq", "fakedsplit", "1", "tcp_seq", fake=None)
    add("fakedsplit at 1 · noack", "fakedsplit", "1", "tcp_flags", fake=None)
    add("fakeddisorder · seq", "fakeddisorder", "midsld", "tcp_seq", fake=None)
    add("fakeddisorder at 2 · seq", "fakeddisorder", "2", "tcp_seq", fake=None)
    return result


def default_spec():
    """Split-only default: no fake packets, no reordering of real data."""
    for spec in candidates():
        if spec["name"] == "fakedsplit at 1":
            return spec
    return candidates()[-1]


def dpi_domains():
    """Hosts allowed to receive DPI desync; empty means global bypass."""
    if not C.DPI_DOMAINS_FILE.exists():
        return list(C.DPI_DOMAINS_DEFAULT)
    try:
        rows = []
        for line in C.DPI_DOMAINS_FILE.read_text(encoding="utf-8").splitlines():
            item = line.strip()
            if item and not item.startswith("#"):
                rows.append(item)
        return rows
    except OSError:
        return list(C.DPI_DOMAINS_DEFAULT)


def render_config(spec, dry_run=False):
    """Render one nfqws2 config. Every line is exactly one option."""
    lines = [
        "--qnum=%d" % C.QUEUE,
        "--fwmark=%s" % C.FWMARK,
        "--comment=kich-dpi",
        "--ctrack-disable=0",
        "--ipcache-lifetime=8400",
        "--lua-init=@%s" % core.engine_lua("zapret-lib.lua"),
        "--lua-init=@%s" % core.engine_lua("zapret-antidpi.lua"),
        "--blob=tls_google:@%s" % (
            C.ENGINE_DIR / "current" / "files" / "fake" / "tls_clienthello_www_google_com.bin"),
        "--blob=quic_google:@%s" % (
            C.ENGINE_DIR / "current" / "files" / "fake" / "quic_initial_www_google_com.bin"),
    ]
    if dry_run:
        lines.insert(0, "--dry-run")

    lines += [
        "--filter-tcp=80", "--filter-l7=http", "--payload=http_req",
        "--out-range=-d12", "--lua-desync=fake:blob=fake_default_http:tcp_md5",
        "--lua-desync=multisplit:pos=method+2", "--new", "--filter-tcp=443",
        "--filter-l7=tls", "--payload=tls_client_hello", "--out-range=-d12",
    ]

    action = str(spec.get("action") or "multisplit")
    pos = str(spec.get("pos") or "midsld")
    fool = FOOLING.get(str(spec.get("fool") or ""), "")
    fake = spec.get("fake")
    repeats = max(1, int(spec.get("repeats") or 1))

    if fake:
        args = "blob=%s:repeats=%d" % (fake, repeats)
        if fool:
            args += ":" + fool
        args += ":tls_mod=rnd,rndsni"
        lines.append("--lua-desync=fake:" + args)

    if action in ("fakedsplit", "fakeddisorder"):
        args = "pattern=tls_google:pos=%s" % pos
        if fool:
            args += ":" + fool
        lines.append("--lua-desync=%s:%s" % (action, args))
    else:
        args = "pos=%s" % pos
        if fool and action in ("multisplit", "multidisorder"):
            args += ":" + fool
        lines.append("--lua-desync=%s:%s" % (action, args))

    quic = str(spec.get("quic") or "quic_google")
    quic_repeats = max(1, int(spec.get("quic_repeats") or 6))
    lines += [
        "--new", "--filter-udp=443", "--filter-l7=quic",
        "--payload=quic_initial",
        "--lua-desync=fake:blob=%s:repeats=%d" % (quic, quic_repeats),
    ]
    domains = dpi_domains()
    if domains:
        hostlist = "--hostlist-domains=" + ",".join(domains)
        for l7 in ("http", "tls", "quic"):
            marker = "--filter-l7=" + l7
            if marker in lines:
                lines.insert(lines.index(marker) + 1, hostlist)
    return "\n".join(lines) + "\n"


def http_probe(url, timeout, interface=""):
    """One request; returns (ok, code, ms, error)."""
    started = time.monotonic()
    args = [
        "curl", "-sS", "-o", "/dev/null", "--connect-timeout", "4",
        "--max-time", str(timeout), "-A", "Mozilla/5.0 (X11; Linux x86_64)",
        "-w", "%{http_code} %{time_total}",
    ]
    if interface:
        args += ["--interface", interface, "-4"]
    args.append(url)
    cp = core.run(args, timeout=timeout + 3)
    parts = (cp.stdout or "").strip().split()
    code = int(parts[0]) if parts and parts[0].isdigit() else 0
    try:
        elapsed = float(parts[1]) if len(parts) > 1 else time.monotonic() - started
    except ValueError:
        elapsed = time.monotonic() - started
    ok = cp.returncode == 0 and 200 <= code < 400
    error = "" if ok else (cp.stderr or "").strip()
    error = error.splitlines()[-1] if error else ""
    return ok, code, int(round(elapsed * 1000)), error[:160]


def probe_row(key, label, url, timeout, device):
    ok, code, ms, error = http_probe(url, timeout, device)
    return {"key": key, "label": label, "ok": ok, "code": code,
            "ms": ms, "error": error}


def probe(targets=C.TARGETS, timeout=7, direct=False, interface=None):
    if not core.curl_available():
        raise core.Fail("не найден curl")
    device = interface if interface is not None else (core.direct_device() if direct else "")
    results = []
    for key, label, url in targets:
        results.append(probe_row(key, label, url, timeout, device))
        time.sleep(0.15)
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
    results = []
    for key, url in SANITY_TARGETS:
        row = probe_row(key, key, url, timeout, device)
        if not row["ok"]:
            time.sleep(0.2)
            row = probe_row(key, key, url, timeout, device)
        results.append(row)
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
    core.write_json(C.ACTIVE_FILE, {
        "id": strategy_id(spec), "name": strategy_name(spec),
        "spec": spec, "time": int(time.time()),
    })
    if start:
        core.set_wanted("dpi", True)
        core.checked_unit_call(core.systemctl, "restart", "systemctl restart не удался", 30)


def wait_active(timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if core.is_running():
            return True
        time.sleep(0.25)
    return False


def cmd_on():
    if not core.installed():
        raise core.Fail("сначала установите движок")
    core.set_wanted("dpi", True)
    core.checked_unit_call(core.systemctl, "start", "не удалось запустить службу", 35)
    from . import status
    core.out(status.status_data())


def cmd_off():
    core.set_wanted("dpi", False)
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


def merge_strategies(rows):
    by_id = {}
    for item in core.read_list(C.STRATEGIES_FILE):
        if isinstance(item, dict) and item.get("id"):
            by_id[str(item["id"])] = item
    for item in rows:
        by_id[str(item["id"])] = item
    ordered = sorted(
        by_id.values(),
        key=lambda r: (-int(r.get("health", r.get("passed") or 0)),
                       int(r.get("ms") or 10 ** 9)),
    )[:8]
    core.write_json(C.STRATEGIES_FILE, ordered)


def generation_progress(total):
    return {
        "running": True, "started": int(time.time()), "done": 0,
        "total": total, "current": "", "best": None, "error": "",
    }


def generation_baseline(device):
    result = probe(interface=device)
    check = sanity(device=device)
    health = (priority_health(result, check) if check["ok"] else (0, -10 ** 9))
    return result, health


def measure_candidate(spec, device):
    try:
        apply_spec(spec, start=True)
        if not wait_active():
            raise core.Fail("служба не запустилась")
        result = probe(interface=device)
        check = sanity(device=device)
        if result["passed"] > 0 and not check["ok"]:
            broken = ", ".join(row["label"] for row in check["results"] if not row["ok"])
            result = dict(result, passed=0, ms=10 ** 9,
                          error="ломает прямой TLS: " + broken)
            health = (0, -10 ** 9)
        else:
            health = priority_health(result, check)
    except core.Fail as exc:
        error = str(exc)
        result = {"passed": 0, "total": len(C.TARGETS), "ms": 10 ** 9,
                  "results": [], "time": int(time.time()), "error": error}
        health = (0, -10 ** 9)

    row = {
        "id": strategy_id(spec), "name": strategy_name(spec), "spec": spec,
        "passed": result["passed"], "total": result["total"],
        "ms": result["ms"], "health": health[0], "time": int(time.time()),
        "error": str(result.get("error") or "")[:160],
    }
    return result, health, row


def restore_after_generation(best, baseline, baseline_health, original,
                             fallback, was_running, old_wanted, progress):
    """Always leave a working configuration behind, even after Ctrl+C."""
    keep_original = best is None
    if not keep_original and baseline is not None and baseline_health >= best[2]:
        keep_original = True
    try:
        if keep_original:
            if not old_wanted:
                core.set_wanted("dpi", False)
                core.systemctl("stop", timeout=20)
            elif original:
                if was_running:
                    apply_spec(original, start=True)
            elif was_running:
                apply_spec(fallback, start=True)
            else:
                # The current config is already the best one. Keep the desired
                # flag as it was, but do not start a service that was down.
                apply_spec(fallback, start=False)
        else:
            apply_spec(best[0], start=True)
    except core.Fail as exc:
        progress["error"] = str(exc)
    return keep_original


def generation_final(progress, baseline, best):
    final = baseline if baseline is not None else core.read_dict(C.CHECK_FILE)
    if not progress.get("kept_original") and best is not None:
        final = best[1]
    if isinstance(final, dict) and final:
        core.write_json(C.CHECK_FILE, final)
    core.out({
        "ok": True, "baseline": baseline,
        "best": None if best is None else {
            "name": strategy_name(best[0]), "passed": best[1]["passed"],
            "total": best[1]["total"], "ms": best[1]["ms"],
        },
        "kept_original": bool(progress.get("kept_original")),
        "error": progress.get("error", ""), "check": final,
    })


def cmd_generate():
    if not core.installed():
        raise core.Fail("сначала установите движок")
    if not core.curl_available():
        raise core.Fail("не найден curl")
    C.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    C.STATE_DIR.mkdir(parents=True, exist_ok=True)

    lock = open(C.STATE_DIR / "generate.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise core.Fail("подбор уже идёт")

    was_running = core.is_running()
    old_wanted = core.wanted_flags()["dpi"]
    original_doc = core.read_dict(C.ACTIVE_FILE)
    original = original_doc.get("spec") if isinstance(original_doc.get("spec"), dict) else None
    fallback = original or default_spec()
    progress = generation_progress(len(candidates()))
    core.write_json(C.PROGRESS_FILE, progress)

    def save_progress(**fields):
        progress.update(fields)
        core.write_json(C.PROGRESS_FILE, progress)

    baseline = None
    baseline_health = (0, -10 ** 9)
    best = None
    rows = []
    device = core.direct_device()
    try:
        baseline, baseline_health = generation_baseline(device)
        for index, spec in enumerate(candidates(), 1):
            save_progress(running=True, done=index - 1, current=strategy_name(spec))
            result, health, row = measure_candidate(spec, device)
            rows.append(row)
            if best is None or health > best[2]:
                best = (spec, result, health)
                progress["best"] = {
                    "name": strategy_name(spec), "passed": result["passed"],
                    "total": result["total"], "ms": result["ms"],
                }
            save_progress(done=index)
    finally:
        keep_original = restore_after_generation(
            best, baseline, baseline_health,
            original, fallback, was_running, old_wanted, progress)
        if rows:
            merge_strategies(rows)
        progress["running"] = False
        progress["done"] = progress.get("done") or 0
        progress["kept_original"] = keep_original
        progress["finished"] = int(time.time())
        if not progress.get("error") and best and best[1]["passed"] == 0:
            progress["error"] = "ни одна стратегия не прошла проверку"
        core.write_json(C.PROGRESS_FILE, progress)
        lock.close()

    generation_final(progress, baseline, best)
