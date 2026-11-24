"""WARP (mihomo MASQUE): registration, generated config, status and checks."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import tempfile
import time
from pathlib import Path

from . import constants as C
from . import core


def warp_available():
    return C.MIHOMO.is_file() and os.access(C.MIHOMO, os.X_OK)


def warp_systemctl(*args, timeout=25):
    return core.systemctl(*args, timeout=timeout, unit=C.WARP_UNIT)


def warp_unit_state():
    return core.unit_state(C.WARP_UNIT, C.WARP_UNIT_PATH, missing_ok=False)


def warp_account():
    data = core.read_dict(C.WARP_ACCOUNT)
    needed = ("private_key", "endpoint_pub_key", "id", "access_token")
    if any(not str(data.get(key) or "").strip() for key in needed):
        return {}
    return data


def migrate_account(home, uid=None, gid=None):
    legacy_dir = Path(home) / ".local" / "share" / C.ENGINE_SLUG
    legacy = legacy_dir / "account.json"
    target = Path(home) / ".local" / "state" / C.ENGINE_SLUG / "account.json"
    if legacy.is_file() and not target.exists():
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(legacy), str(target))
            os.chmod(target, 0o600)
            if uid is not None and gid is not None:
                os.chown(target, uid, gid)
        except OSError:
            pass
    try:
        legacy_dir.rmdir()
    except OSError:
        pass


def save_warp_account(account):
    core.write_json(C.WARP_ACCOUNT, account, mode=0o600)


def cf_error(code, raw):
    message = raw
    try:
        body = json.loads(raw)
        message = body.get("message") or body.get("error") or raw
    except ValueError:
        pass
    if code in (401, 403):
        raise core.Fail("Cloudflare отклонил аккаунт — нужна повторная регистрация")
    if code == 429 or "1015" in raw:
        raise core.Fail("Cloudflare временно ограничил регистрацию, повторите позже")
    raise core.Fail("Cloudflare API: HTTP %s: %s" % (code, str(message)[:200]))


def cf_request(path, payload, token="", method="POST"):
    """Cloudflare client API. curl is preferred: its ClientHello passes where
    Python's sometimes hangs on this host."""
    url = C.CF_ORIGIN + "/" + C.CF_VERSION + path
    body = json.dumps(payload).encode("utf-8")
    curl = shutil.which("curl")
    if curl:
        args = [curl, "-sS", "--max-time", "30", "-X", method]
        for key, value in C.CF_HEADERS.items():
            args.extend(["-H", "%s: %s" % (key, value)])
        args.extend(["-w", "\n%{http_code}", "--data-binary", "@-", url])
        if token:
            args[1:1] = ["-H", "Authorization: Bearer " + token]
        cp = core.run(args, timeout=40, text=False, input=body)
        if cp.returncode != 0:
            detail = (cp.stderr or b"curl failed").decode("utf-8", "replace").strip()
            raise core.Fail("нет связи с Cloudflare: %s" % detail[:200])
        raw, _, code_text = cp.stdout.decode("utf-8", "replace").rpartition("\n")
        try:
            code = int(code_text.strip())
        except ValueError:
            code = 0
        if code >= 400 or code == 0:
            cf_error(code, raw)
        return json.loads(raw or "{}")

    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=body, headers=dict(C.CF_HEADERS), method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        cf_error(exc.code, exc.read().decode("utf-8", "replace"))
    except urllib.error.URLError as exc:
        raise core.Fail("нет связи с Cloudflare: %s" % exc.reason)


def warp_keys():
    openssl = shutil.which("openssl")
    if not openssl:
        raise core.Fail("для ключей WARP нужен openssl")
    with tempfile.TemporaryDirectory(prefix="kich-dpi-warp-") as tmp:
        work = Path(tmp)
        pem, der, pub = work / "key.pem", work / "key.der", work / "pub.der"
        steps = (
            [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(pem)],
            [openssl, "ec", "-in", str(pem), "-outform", "DER", "-out", str(der)],
            [openssl, "ec", "-in", str(pem), "-pubout", "-outform", "DER", "-out", str(pub)],
        )
        for step in steps:
            cp = core.run(step, timeout=20)
            if cp.returncode != 0:
                raise core.Fail("openssl: " + core.unit_error(cp, "", 200))
        private_key = base64.b64encode(der.read_bytes()).decode()
        public_key = base64.b64encode(pub.read_bytes()).decode()
    return private_key, public_key


def strip_endpoint(value):
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.match(r"^\[([^\]]+)\](?::\d+)?$", text)
    if match:
        return match.group(1)
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$", text):
        return text.rsplit(":", 1)[0]
    return text


def cidr_of(value, version):
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        suffix = "32" if version == 4 else "128"
        return str(ipaddress.ip_network(text if "/" in text else "%s/%s" % (text, suffix),
                                        strict=False))
    except ValueError:
        return ""


def warp_enroll_fields(updated, account):
    peer = ((updated.get("config") or {}).get("peers") or [{}])[0]
    iface = ((updated.get("config") or {}).get("interface") or {}).get("addresses") or {}
    endpoint = peer.get("endpoint") or {}
    fresh = dict(account)
    fresh.update({
        "endpoint_pub_key": peer.get("public_key") or account.get("endpoint_pub_key", ""),
        "endpoint_v4": strip_endpoint(endpoint.get("v4")) or account.get("endpoint_v4", ""),
        "endpoint_v6": strip_endpoint(endpoint.get("v6")) or account.get("endpoint_v6", ""),
        "ipv4": iface.get("v4") or account.get("ipv4", ""),
        "ipv6": iface.get("v6") or account.get("ipv6", ""),
        "license": ((updated.get("account") or {}).get("license") or account.get("license", "")),
        "nameserver": ((updated.get("config") or {}).get("interface") or {}).get("dns")
                      or account.get("nameserver", []),
    })
    return fresh


def warp_patch(identifier, token, key, name):
    return cf_request("/reg/%s" % identifier, {
        "key": key, "key_type": "secp256r1", "tunnel_type": "masque", "name": name,
    }, token=token, method="PATCH")


def warp_register():
    if os.environ.get("KICH_DPI_OFFLINE"):
        raise core.Fail("регистрация WARP недоступна в офлайн-режиме")
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    reg = cf_request("/reg", {
        "key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "install_id": "", "fcm_token": "", "tos": now, "model": "PC",
        "serial_number": secrets.token_hex(8), "os_version": "",
        "key_type": "curve25519", "tunnel_type": "wireguard", "locale": "en_US",
    })
    if not reg.get("id") or not reg.get("token"):
        raise core.Fail("Cloudflare не вернул id/token при регистрации")
    private_key, public_key = warp_keys()
    name = ("omarchy-%s" % (platform.node() or "linux"))[:64]
    updated = warp_patch(reg["id"], reg["token"], public_key, name)
    account = {
        "private_key": private_key, "public_key": public_key,
        "id": updated.get("id") or reg["id"], "access_token": reg["token"],
        "name": name, "registered_at": int(time.time()),
    }
    account = warp_enroll_fields(updated, account)
    if not account.get("endpoint_pub_key"):
        raise core.Fail("Cloudflare не вернул ключ MASQUE-шлюза")
    if not account.get("ipv4") and not account.get("ipv6"):
        raise core.Fail("Cloudflare не вернул адрес устройства")
    save_warp_account(account)
    return account


def warp_enroll(account):
    updated = warp_patch(account["id"], account["access_token"],
                         account["public_key"], account.get("name") or "omarchy")
    fresh = warp_enroll_fields(updated, account)
    save_warp_account(fresh)
    return fresh


def yaml_str(value):
    return json.dumps(str(value), ensure_ascii=False)


def domain_payload(text):
    """Bare entries in a mihomo `domain` file are exact matches; `+.` means suffix."""
    rows = []
    for line in text.splitlines():
        item = line.strip()
        if not item or item.startswith("#") or item.startswith(("+.", "*.")):
            rows.append(line)
            continue
        rows.append("+." + item)
    return "\n".join(rows) + "\n"


def install_rule_lists():
    missing = []
    C.WARP_RULES.mkdir(parents=True, exist_ok=True)
    for name in ("ru-domain.txt", "ru-ip.txt"):
        src = C.BUNDLED_RULES / name
        if not src.is_file():
            missing.append(name)
            continue
        text = src.read_text(encoding="utf-8")
        if name == "ru-domain.txt":
            text = domain_payload(text)
        core.write_text(C.WARP_RULES / name, text, 0o644)
    if missing:
        raise core.Fail("нет списков правил (%s): обновите системную часть плагина"
                        % ", ".join(missing))
    core.write_text(
        C.WARP_RULES / "direct-domains.txt",
        domain_payload("\n".join(core.list_lines(C.WARP_USER_DOMAINS))), 0o644,
    )


def ensure_user_lists():
    for path, header in (
            (C.WARP_USER_DOMAINS, C.WARP_USER_DOMAINS_HEADER),
            (C.WARP_USER_PROCESSES, C.WARP_USER_PROCESSES_HEADER),
            (C.DPI_DOMAINS_FILE,
             "# DPI desync applies only to these hosts (subdomains included).\n"
             "# One host per line; '#' starts a comment. Leave the file empty "
             "to desync all TCP 80/443 and UDP 443 as older versions did.\n"
             + "\n".join(C.DPI_DOMAINS_DEFAULT) + "\n")):
        if not path.exists():
            core.write_text(path, header, 0o644)


def warp_config_text(account):
    if not account:
        raise core.Fail("аккаунт WARP не зарегистрирован")
    gateway = "".join(line for line in str(account.get("endpoint_pub_key") or "").splitlines()
                      if not line.startswith("-----")).strip()
    if not gateway:
        raise core.Fail("в аккаунте нет ключа MASQUE-шлюза")
    ip4 = cidr_of(account.get("ipv4"), 4)
    ip6 = cidr_of(account.get("ipv6"), 6)
    own_domains = core.list_lines(C.WARP_USER_DOMAINS)
    processes = core.list_lines(C.WARP_USER_PROCESSES)
    for name in processes:
        if "," in name:
            raise core.Fail("в direct-processes.txt недопустима запятая: %s" % name)

    lines = []
    add = lines.append
    add("# Generated by kich-dpi. Do not edit: change the plugin instead.")
    add("# WARP over MASQUE (QUIC) · account %s" % str(account.get("id") or "")[:8])
    add("mixed-port: %d" % C.WARP_MIXED_PORT)
    add("bind-address: 127.0.0.1")
    add("allow-lan: false")
    add("mode: rule")
    add("log-level: warning")
    add("ipv6: true")
    add("find-process-mode: %s" % ('"strict"' if processes else '"off"'))
    add("routing-mark: %s" % C.WARP_MARK)
    add("sniffer:")
    add("  enable: true")
    add("  sniff:")
    add("    TLS:")
    add("      ports: [443, 8443]")
    add("    HTTP:")
    add("      ports: [80, 8080-8880]")
    add("      override-destination: true")
    add("    QUIC:")
    add("      ports: [443, 8443]")
    add("tun:")
    add("  enable: true")
    add("  stack: gvisor")
    add("  device: %s" % C.WARP_DEVICE)
    add("  auto-route: true")
    add("  auto-detect-interface: true")
    add("  auto-redirect: false")
    add("  dns-hijack:")
    add("    - any:53")
    add("    - tcp://any:53")
    add("  mtu: 1280")
    if ip6:
        add("  inet6-address:")
        add("    - fdfe:dcba:9876::1/126")
    add("  route-exclude-address:")
    for address in C.WARP_ENDPOINTS:
        add("    - %s/32" % address)
    for address in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8"):
        add("    - %s" % address)
    add("  strict-route: false")
    add("dns:")
    add("  enable: true")
    add("  listen: 127.0.0.1:1053")
    add("  ipv6: %s" % ("true" if ip6 else "false"))
    if ip6:
        add("  fake-ip-range6: fc00::1/18")
    add("  enhanced-mode: fake-ip")
    add("  fake-ip-range: 198.18.0.1/16")
    add("  fake-ip-filter:")
    for domain in ("lan", "local", "home.arpa"):
        add("    - DOMAIN-SUFFIX,%s,real-ip" % domain)
    add("  default-nameserver: [77.88.8.8, 1.1.1.1]")
    add("  nameserver: [https://1.1.1.1/dns-query, https://1.0.0.1/dns-query]")
    add("  direct-nameserver: [77.88.8.8, 77.88.8.1]")
    add("  proxy-server-nameserver: [77.88.8.8, 77.88.8.1]")
    add("proxies:")
    add("  - name: WARP")
    add("    type: masque")
    add("    server: %s" % yaml_str(C.WARP_ENDPOINT))
    add("    port: 443")
    add("    private-key: %s" % yaml_str(account["private_key"]))
    add("    public-key: %s" % yaml_str(gateway))
    if ip4:
        add("    ip: %s" % yaml_str(ip4))
    if ip6:
        add("    ipv6: %s" % yaml_str(ip6))
    add("    mtu: 1280")
    add("    udp: true")
    add("    sni: %s" % yaml_str(C.WARP_SNI))
    add("    network: quic")
    add("    ip-version: ipv6-prefer")
    add("    ip-stack:")
    add("      mode: auto")
    add("      congestion-controller: bbr")
    add("    remote-dns-resolve: true")
    add('    dns: ["https://1.1.1.1/dns-query"]')
    add("    handshake-timeout: 20")
    add("rule-providers:")
    for name, behavior, path in (
            ("ru-domain", "domain", C.WARP_RULES / "ru-domain.txt"),
            ("ru-ip", "ipcidr", C.WARP_RULES / "ru-ip.txt")):
        add("  %s:" % name)
        add("    type: file")
        add("    behavior: %s" % behavior)
        add("    format: text")
        add("    path: %s" % yaml_str(path))
    if own_domains:
        add("  direct-domains:")
        add("    type: file")
        add("    behavior: domain")
        add("    format: text")
        add("    path: %s" % yaml_str(C.WARP_RULES / "direct-domains.txt"))
    add("rules:")
    for name in processes:
        add("  - PROCESS-NAME,%s,DIRECT" % name)
    add("  - RULE-SET,ru-domain,DIRECT")
    add("  - RULE-SET,ru-ip,DIRECT")
    if own_domains:
        add("  - RULE-SET,direct-domains,DIRECT")
    for domain in ("lan", "local", "home.arpa"):
        add("  - DOMAIN-SUFFIX,%s,DIRECT" % domain)
    for address in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8",
                    "169.254.0.0/16"):
        add("  - IP-CIDR,%s,DIRECT,no-resolve" % address)
    add("  - AND,((NETWORK,udp),(DST-PORT,443)),WARP")
    add("  - NETWORK,udp,DIRECT")
    add("  - MATCH,WARP")
    add("")
    return "\n".join(lines)


def warp_build(account=None):
    account = account or warp_account()
    if not account:
        raise core.Fail("WARP ещё не зарегистрирован")
    ensure_user_lists()
    install_rule_lists()
    text = warp_config_text(account)
    core.write_text(C.WARP_CONFIG, text, 0o600)
    return C.WARP_CONFIG


def warp_status(_states=None):
    if _states is not None:
        active, enabled = _states[C.WARP_UNIT]
    else:
        active, enabled = warp_unit_state()
    account = warp_account()
    check = core.read_dict(C.WARP_CHECK_FILE)
    available = warp_available()
    error = ""
    if not available:
        error = "mihomo не установлен"
    elif active == "failed":
        error = "служба WARP не запустилась"
    return {
        "available": available, "registered": bool(account),
        "configured": C.WARP_CONFIG.exists(), "running": active == "active",
        "failed": active == "failed", "active": active, "enabled": enabled,
        "name": str(account.get("name") or ""),
        "account": str(account.get("id") or "")[:8],
        "check": check, "error": error,
    }


def remote_exists(url):
    import urllib.request
    try:
        with urllib.request.urlopen(core.http_request(url, method="HEAD"), timeout=20) as resp:
            return resp.status == 200
    except Exception:
        return False


def mihomo_version():
    return str(core.read_dict(C.ENGINE_ROOT / "mihomo.json").get("version") or "")


def warp_check_data():
    """One tunnel probe; shared by `warp-check` and `repair`."""
    started = time.monotonic()
    result = {"time": int(time.time()), "ok": False, "warp": "", "ip": "", "colo": "",
              "ms": 0, "error": "", "tun": False}
    cp = core.run([
        "curl", "-fsS", "--max-time", "10",
        "-x", "http://127.0.0.1:%d" % C.WARP_MIXED_PORT,
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
    result["tun"] = core.route_device() == C.WARP_DEVICE
    result["ms"] = int((time.monotonic() - started) * 1000)
    core.write_json(C.WARP_CHECK_FILE, result)
    return result


def cmd_warp_config():
    account = warp_account()
    if not account:
        raise core.Fail("WARP не зарегистрирован")
    path = warp_build(account)
    core.out({"ok": True, "config": str(path)})


def cmd_warp_on():
    if not warp_available():
        raise core.Fail("mihomo не установлен: сначала установите плагин")
    account = warp_account() or warp_register()
    warp_build(account)
    core.set_wanted("warp", True)
    core.checked_unit_call(warp_systemctl, "restart", "не удалось включить WARP", 35)
    core.out({"ok": True, "warp": warp_status()})


def cmd_warp_off():
    core.set_wanted("warp", False)
    core.checked_unit_call(warp_systemctl, "stop", "не удалось отключить WARP", 25)
    core.out({"ok": True, "warp": warp_status()})


def cmd_warp_toggle():
    active, _ = warp_unit_state()
    cmd_warp_off() if active == "active" else cmd_warp_on()


def cmd_warp_register():
    account = warp_account()
    if account:
        try:
            account = warp_enroll(account)
        except core.Fail:
            if not warp_available():
                raise
            account = warp_register()
    else:
        account = warp_register()
    warp_build(account)
    core.out({"ok": True, "registered": True, "name": account.get("name", ""),
              "account": str(account.get("id") or "")[:8]})


def cmd_warp_check():
    core.out({"ok": True, "check": warp_check_data()})
