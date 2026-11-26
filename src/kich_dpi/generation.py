"""Candidate measurement and the `generate` command's finally semantics."""
from __future__ import annotations

import fcntl

from . import constants as C


def merge_strategies(strategies, rows):
    core = strategies.core
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


def generation_progress(strategies, total):
    return {
        "running": True, "started": int(strategies.time.time()), "done": 0,
        "total": total, "current": "", "best": None, "error": "",
    }


def generation_baseline(strategies, device):
    result = strategies.probe(interface=device)
    check = strategies.sanity(device=device)
    health = (strategies.priority_health(result, check) if check["ok"]
              else (0, -10 ** 9))
    return result, health


def measure_candidate(strategies, spec, device):
    core = strategies.core
    try:
        strategies.apply_spec(spec, start=True)
        if not strategies.wait_active():
            raise core.Fail("служба не запустилась")
        result = strategies.probe(interface=device)
        check = strategies.sanity(device=device)
        if result["passed"] > 0 and not check["ok"]:
            broken = ", ".join(row["label"] for row in check["results"] if not row["ok"])
            result = dict(result, passed=0, ms=10 ** 9,
                          error="ломает прямой TLS: " + broken)
            health = (0, -10 ** 9)
        else:
            health = strategies.priority_health(result, check)
    except core.Fail as exc:
        error = str(exc)
        result = {"passed": 0, "total": len(C.TARGETS), "ms": 10 ** 9,
                  "results": [], "time": int(strategies.time.time()), "error": error}
        health = (0, -10 ** 9)

    row = {
        "id": strategies.strategy_id(spec), "name": strategies.strategy_name(spec),
        "spec": spec,
        "passed": result["passed"], "total": result["total"],
        "ms": result["ms"], "health": health[0], "time": int(strategies.time.time()),
        "error": core.clip(result.get("error") or "", limit=160, strip=False),
    }
    return result, health, row


def restore_after_generation(strategies, best, baseline, baseline_health,
                             original, fallback, was_running, old_wanted, progress):
    """Always leave a working configuration behind, even after Ctrl+C."""
    core = strategies.core
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
                    strategies.apply_spec(original, start=True)
            elif was_running:
                strategies.apply_spec(fallback, start=True)
            else:
                # The current config is already the best one. Keep the desired
                # flag as it was, but do not start a service that was down.
                strategies.apply_spec(fallback, start=False)
        else:
            strategies.apply_spec(best[0], start=True)
    except core.Fail as exc:
        progress["error"] = str(exc)
    return keep_original


def generation_final(strategies, progress, baseline, best):
    core = strategies.core
    final = baseline if baseline is not None else core.read_dict(C.CHECK_FILE)
    if not progress.get("kept_original") and best is not None:
        final = best[1]
    if isinstance(final, dict) and final:
        core.write_json(C.CHECK_FILE, final)
    summary = None if best is None else {
        "name": strategies.strategy_name(best[0]), "passed": best[1]["passed"],
        "total": best[1]["total"], "ms": best[1]["ms"],
    }
    progress.update({
        "active_id": str(core.read_dict(C.ACTIVE_FILE).get("id") or ""),
        "wanted_dpi": bool(core.wanted_flags()["dpi"]),
        "best_summary": summary,
        "final": final,
    })
    core.write_json(C.PROGRESS_FILE, progress)
    core.out({
        "ok": True, "baseline": baseline, "best": summary,
        "kept_original": bool(progress.get("kept_original")),
        "error": progress.get("error", ""), "check": final,
    })


def generation_cached(strategies, force=False):
    """Reuse a fresh, successful measurement when nothing about it changed."""
    if force:
        return None
    core = strategies.core
    progress = core.read_dict(C.PROGRESS_FILE)
    finished = int(progress.get("finished") or 0)
    if progress.get("running") or not finished:
        return None
    if strategies.time.time() - finished > 1800:
        return None
    active = core.read_dict(C.ACTIVE_FILE)
    if str(active.get("id") or "") != str(progress.get("active_id") or ""):
        return None
    wanted = core.wanted_flags()["dpi"]
    if bool(progress.get("wanted_dpi", True)) != wanted or wanted != core.is_running():
        return None
    final = progress.get("final") or core.read_dict(C.CHECK_FILE)
    if not isinstance(final, dict) or not final:
        return None
    return {
        "ok": True, "baseline": progress.get("baseline"),
        "best": progress.get("best_summary"),
        "kept_original": bool(progress.get("kept_original")),
        "error": progress.get("error", ""), "check": final,
    }


def cmd_generate(strategies, force=False):
    core = strategies.core
    if not core.installed():
        raise core.Fail("сначала установите движок")
    if not core.curl_available():
        raise core.Fail("не найден curl")
    cached = strategies.generation_cached(force)
    if cached is not None:
        core.out(cached)
        return
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
    fallback = original or strategies.default_spec()
    progress = strategies.generation_progress(len(strategies.candidates()))
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
        baseline, baseline_health = strategies.generation_baseline(device)
        for index, spec in enumerate(strategies.candidates(), 1):
            save_progress(running=True, done=index - 1,
                          current=strategies.strategy_name(spec))
            result, health, row = strategies.measure_candidate(spec, device)
            rows.append(row)
            if best is None or health > best[2]:
                best = (spec, result, health)
                progress["best"] = {
                    "name": strategies.strategy_name(spec),
                    "passed": result["passed"], "total": result["total"],
                    "ms": result["ms"],
                }
            save_progress(done=index)
    finally:
        keep_original = strategies.restore_after_generation(
            best, baseline, baseline_health,
            original, fallback, was_running, old_wanted, progress)
        if rows:
            strategies.merge_strategies(rows)
        progress["running"] = False
        progress["done"] = progress.get("done") or 0
        progress["kept_original"] = keep_original
        progress["finished"] = int(strategies.time.time())
        if not progress.get("error") and best and best[1]["passed"] == 0:
            progress["error"] = "ни одна стратегия не прошла проверку"
        core.write_json(C.PROGRESS_FILE, progress)
        lock.close()

    strategies.generation_final(progress, baseline, best)
