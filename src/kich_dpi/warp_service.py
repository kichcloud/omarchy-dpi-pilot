"""WARP unit state, generated config, status and tunnel checks."""
from __future__ import annotations

import hashlib
import pathlib

from .warp_format import domain_payload, warp_config_text


def warp_available(warp):
    return warp.C.MIHOMO.is_file() and warp.os.access(warp.C.MIHOMO, warp.os.X_OK)


def warp_systemctl(warp, *args, timeout=25):
    return warp.core.systemctl(*args, timeout=timeout, unit=warp.C.WARP_UNIT)


def warp_unit_state(warp):
    if not warp.C.WARP_UNIT_PATH.exists():
        return "inactive", "not-found"
    return warp.core.batched_unit_states([warp.C.WARP_UNIT])[warp.C.WARP_UNIT]


def install_rule_lists(warp):
    missing = []
    warp.C.WARP_RULES.mkdir(parents=True, exist_ok=True)
    for name in ("ru-domain.txt", "ru-ip.txt"):
        src = warp.C.BUNDLED_RULES / name
        if not src.is_file():
            missing.append(name)
            continue
        text = src.read_text(encoding="utf-8")
        if name == "ru-domain.txt":
            text = domain_payload(text)
        warp.core.write_text(warp.C.WARP_RULES / name, text, 0o644)
    if missing:
        raise warp.core.Fail("нет списков правил (%s): обновите системную часть плагина"
                             % ", ".join(missing))
    warp.core.write_text(
        warp.C.WARP_RULES / "direct-domains.txt",
        domain_payload("\n".join(warp.core.list_lines(warp.C.WARP_USER_DOMAINS))), 0o644,
    )


def ensure_user_lists(warp):
    for path, header in (
            (warp.C.WARP_USER_DOMAINS, warp.C.WARP_USER_DOMAINS_HEADER),
            (warp.C.WARP_USER_PROCESSES, warp.C.WARP_USER_PROCESSES_HEADER),
            (warp.C.DPI_DOMAINS_FILE,
             "# DPI desync applies only to these hosts (subdomains included).\n"
             "# One host per line; '#' starts a comment. Leave the file empty "
             "to desync all TCP 80/443 and UDP 443 as older versions did.\n"
             + "\n".join(warp.C.DPI_DOMAINS_DEFAULT) + "\n")):
        if not path.exists():
            warp.core.write_text(path, header, 0o644)


def warp_build_stamp(warp, account=None):
    """Remember which account and host produced the generated config."""
    stamp = warp.core.read_dict(warp.C.WARP_BUILD_STAMP)
    if not stamp or stamp.get("version") != 1:
        return {}
    account = account or warp.warp_account()
    wg = warp.wg_account()
    if str(stamp.get("account") or "") != str((account or {}).get("id") or ""):
        return {}
    if str(stamp.get("wg_account") or "") != str((wg or {}).get("id") or ""):
        return {}
    return stamp


def _file_digest(path):
    try:
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def warp_build_inputs(warp):
    """Network and user-rule inputs that decide whether a config is stale."""
    try:
        network = warp.warp_network_signature()
    except Exception:
        network = {}
    return {
        "network": network,
        "files": {
            "user_domains": _file_digest(warp.C.WARP_USER_DOMAINS),
            "user_processes": _file_digest(warp.C.WARP_USER_PROCESSES),
            "rules": {name: _file_digest(warp.C.WARP_RULES / name)
                      for name in ("ru-domain.txt", "ru-ip.txt",
                                   "direct-domains.txt")},
        },
    }


def warp_config_matches_stamp(warp, stamp):
    path = warp.C.WARP_CONFIG
    if not path.is_file():
        return False
    for name in ("ru-domain.txt", "ru-ip.txt", "direct-domains.txt"):
        if not (warp.C.WARP_RULES / name).is_file():
            return False
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return False
    if digest != str(stamp.get("sha256") or ""):
        return False
    return warp_build_inputs(warp) == stamp.get("inputs")


def save_build_stamp(warp, account, text):
    warp.core.write_json(warp.C.WARP_BUILD_STAMP, {
        "version": 1,
        "account": str((account or {}).get("id") or ""),
        "wg_account": str((warp.wg_account() or {}).get("id") or ""),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "inputs": warp_build_inputs(warp),
    }, 0o600)


def warp_build(warp, account=None, force=False):
    account = account or warp.warp_account()
    if not account:
        raise warp.core.Fail("WARP ещё не зарегистрирован")
    if not force:
        stamp = warp_build_stamp(warp, account)
        if stamp and warp_config_matches_stamp(warp, stamp):
            return warp.C.WARP_CONFIG
    warp.ensure_user_lists()
    warp.install_rule_lists()
    network = warp.warp_network()
    wg = warp.wg_profile()
    if wg:
        network.update(wg)
    text = warp.warp_config_text(account, network)
    warp.core.write_text(warp.C.WARP_CONFIG, text, 0o600)
    save_build_stamp(warp, account, text)
    return warp.C.WARP_CONFIG


def warp_status(warp, _states=None):
    if _states is not None:
        active, enabled = _states[warp.C.WARP_UNIT]
    else:
        active, enabled = warp.warp_unit_state()
    account = warp.warp_account()
    check = warp.core.read_dict(warp.C.WARP_CHECK_FILE)
    available = warp.warp_available()
    error = ""
    if not available:
        error = "mihomo не установлен"
    elif active == "failed":
        error = "служба WARP не запустилась"
    return {
        "available": available, "registered": bool(account),
        "configured": warp.C.WARP_CONFIG.exists(), "running": active == "active",
        "failed": active == "failed", "active": active, "enabled": enabled,
        "name": str(account.get("name") or ""),
        "account": str(account.get("id") or "")[:8],
        "check": check, "error": error,
    }


def remote_exists(warp, url):
    import urllib.request
    try:
        with urllib.request.urlopen(warp.core.http_request(url, method="HEAD"),
                                   timeout=20) as resp:
            return resp.status == 200
    except Exception:
        return False


def mihomo_version(warp):
    return str(warp.core.read_dict(warp.C.ENGINE_ROOT / "mihomo.json").get("version") or "")


def warp_check_data(warp):
    """One tunnel probe; shared by `warp-check` and `repair`."""
    started = warp.time.monotonic()
    result = {"time": int(warp.time.time()), "ok": False, "warp": "", "ip": "",
              "colo": "", "ms": 0, "error": "", "tun": False}
    cp = warp.core.run([
        "curl", "-fsS", "--max-time", "10",
        "-x", "http://127.0.0.1:%d" % warp.C.WARP_MIXED_PORT,
        "https://www.cloudflare.com/cdn-cgi/trace",
    ], timeout=15)
    if cp.returncode != 0:
        result["error"] = ("туннель не отвечает: "
                           + (cp.stderr or "нет ответа").strip())[:200]
    else:
        values = {}
        for line in cp.stdout.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
        result["warp"] = values.get("warp", "")
        result["ip"] = values.get("ip", "")
        result["colo"] = values.get("colo", "")
        result["ok"] = result["warp"] in ("on", "plus")
        if not result["ok"]:
            result["error"] = "трафик не идёт через WARP"
    result["tun"] = warp.core.route_device() == warp.C.WARP_DEVICE
    result["ms"] = int((warp.time.monotonic() - started) * 1000)
    warp.core.write_json(warp.C.WARP_CHECK_FILE, result)
    return result


def cmd_warp_config(warp, force=False):
    account = warp.warp_account()
    if not account:
        raise warp.core.Fail("WARP не зарегистрирован")
    path = warp.warp_build(account, force=force)
    warp.core.out({"ok": True, "config": str(path)})


def cmd_warp_on(warp):
    if not warp.warp_available():
        raise warp.core.Fail("mihomo не установлен: сначала установите плагин")
    account = warp.warp_account() or warp.warp_register()
    before = warp.warp_build_stamp()
    had_config = warp.C.WARP_CONFIG.is_file()
    warp.warp_build(account)
    after = warp.warp_build_stamp()
    changed = before != after or not had_config
    warp.core.set_wanted("warp", True)
    active, enabled = warp.warp_unit_state()
    healthy = False
    if not changed and active == "active":
        healthy = bool(warp.warp_check_data().get("ok"))
    if changed or active != "active" or not healthy:
        action = "restart" if active == "active" else "start"
        warp.core.checked_unit_call(warp.warp_systemctl, action,
                                    "не удалось включить WARP", 35)
        active = "active"
    states = {warp.C.WARP_UNIT: (active, enabled)}
    warp.core.out({"ok": True, "warp": warp.warp_status(_states=states)})


def cmd_warp_off(warp):
    active, enabled = warp.warp_unit_state()
    warp.core.set_wanted("warp", False)
    if active == "active":
        warp.core.checked_unit_call(warp.warp_systemctl, "stop",
                                    "не удалось отключить WARP", 25)
        active = "inactive"
    states = {warp.C.WARP_UNIT: (active, enabled)}
    warp.core.out({"ok": True, "warp": warp.warp_status(_states=states)})


def cmd_warp_toggle(warp):
    active, _ = warp.warp_unit_state()
    warp.cmd_warp_off() if active == "active" else warp.cmd_warp_on()


def cmd_warp_register(warp, force=False):
    account = warp.warp_account()
    wg = warp.wg_account()
    if force or not account:
        if account:
            try:
                account = warp.warp_enroll(account)
            except warp.core.Fail:
                if not warp.warp_available():
                    raise
                account = warp.warp_register()
        else:
            account = warp.warp_register()
    if force or not wg:
        try:
            warp.warp_register_wg()
        except warp.core.Fail as exc:
            warp.core.log("не удалось зарегистрировать WireGuard: %s" % exc)
    warp.warp_build(account, force=force)
    warp.core.out({"ok": True, "registered": True, "name": account.get("name", ""),
                   "account": str(account.get("id") or "")[:8]})


def cmd_warp_check(warp):
    warp.core.out({"ok": True, "check": warp.warp_check_data()})
