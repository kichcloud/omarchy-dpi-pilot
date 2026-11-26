"""Read the host's real network so WARP can be generated for this machine.

Everything here is best-effort: a missing `ip` or `resolvectl` must never make
`warp-config` / `warp-on` fail. The formatter falls back to the generic rules
when a value cannot be detected.
"""
from __future__ import annotations

import ipaddress
import re
import time

from pathlib import Path

from . import constants as C

PROBE_TTL = 1800


def _cache_fresh(cache):
    path = str((cache or {}).get("path") or "")
    started = cache.get("time") if isinstance(cache, dict) else 0
    try:
        age = time.time() - int(started or 0)
    except (TypeError, ValueError):
        return False
    return bool(path) and 0 <= age <= PROBE_TTL


def load_probe_cache(warp):
    cache = warp.core.read_dict(C.WARP_PROBE_CACHE)
    return cache if cache.get("version") == 1 else {}


def save_probe_cache(warp, cache):
    cache["version"] = 1
    warp.core.write_json(C.WARP_PROBE_CACHE, cache, 0o600)


def path_key(profile):
    return "%s|%s|%s" % (profile.get("interface") or "",
                         profile.get("gateway") or "",
                         profile.get("address") or "")


def tcp_open(host, port=443, timeout=2.0):
    """Cheap reachability gate before starting a full mihomo handshake."""
    import socket
    host = str(host or "").split("#")[0]
    if not host:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _run(warp, argv, timeout=5):
    try:
        cp = warp.core.run(argv, timeout=timeout)
    except Exception:
        return ""
    if getattr(cp, "returncode", 1) != 0:
        return ""
    return str(getattr(cp, "stdout", "") or "")


def _after(text, key):
    parts = str(text or "").split()
    if key in parts:
        index = parts.index(key) + 1
        if index < len(parts):
            return parts[index]
    return ""


def _valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).split("#")[0]))
    except ValueError:
        return ""


def _cidrs(text):
    rows = []
    for line in str(text or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            row = str(ipaddress.ip_network(parts[0], strict=False))
        except ValueError:
            continue
        if row not in rows:
            rows.append(row)
    return rows


def default_route(warp):
    text = _run(warp, ["ip", "-4", "route", "show", "default", "table", "main"])
    if not text:
        text = _run(warp, ["ip", "-4", "route", "show", "default"])
    return {
        "interface": _after(text, "dev"),
        "gateway": _after(text, "via"),
        "address": _after(text, "src"),
    }


def interface_address(warp, device):
    if not device:
        return ""
    text = _run(warp, ["ip", "-4", "addr", "show", "dev", device])
    match = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", text)
    return match.group(1) if match else ""


def interface_mtu(warp, device):
    if not device or not re.fullmatch(r"[A-Za-z0-9_.:-]+", device):
        return 0
    try:
        return int(Path("/sys/class/net/%s/mtu" % device).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def dns_servers(warp):
    rows = []

    def add(token):
        address = _valid_ip(token.strip().rstrip(";,"))
        if address and address not in rows:
            rows.append(address)

    # resolvectl wraps long IPv6 lines, so parse tokens rather than labels.
    for token in _run(warp, ["resolvectl", "dns"]).replace(",", " ").split():
        add(token)
    if not rows:
        try:
            text = Path("/etc/resolv.conf").read_text(encoding="utf-8")
        except OSError:
            text = ""
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                address = _valid_ip(parts[1])
                if address and address not in rows:
                    rows.append(address)
    return rows[:3]


def has_ipv6(warp):
    route = _run(warp, ["ip", "-6", "route", "show", "default", "table", "main"])
    if "default" not in route.split():
        return False
    return bool(re.search(r"\binet6\s+",
                          _run(warp, ["ip", "-6", "addr", "show", "scope", "global"])))


def free_port():
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def probe_config(warp, host, port, account):
    from .warp_format import cidr_of, yaml_str
    gateway = "".join(line for line in str(account.get("endpoint_pub_key") or "").splitlines()
                      if not line.startswith("-----")).strip()
    ip4 = cidr_of(account.get("ipv4"), 4)
    ip6 = cidr_of(account.get("ipv6"), 6)
    lines = [
        "mixed-port: %d" % port,
        "bind-address: 127.0.0.1",
        "mode: rule",
        "log-level: error",
        'cache-file: ""',
        "find-process-mode: off",
        "proxies:",
        "  - name: WARP-PROBE",
        "    type: masque",
        "    server: %s" % yaml_str(host),
        "    port: 443",
        "    private-key: %s" % yaml_str(account["private_key"]),
        "    public-key: %s" % yaml_str(gateway),
    ]
    if ip4:
        lines.append("    ip: %s" % yaml_str(ip4))
    if ip6:
        lines.append("    ipv6: %s" % yaml_str(ip6))
    lines.extend([
        "    sni: %s" % yaml_str(C.WARP_SNI),
        "    network: quic",
        "    ip-version: ipv4-only",
        "    handshake-timeout: 8",
        "    remote-dns-resolve: false",
        "rules:",
        "  - MATCH,WARP-PROBE",
        "",
    ])
    return "\n".join(lines)


def endpoint_healthy(warp, host):
    """Only a real MASQUE handshake proves a gateway serves this account."""
    import subprocess
    import tempfile
    import time

    binary = warp.C.MIHOMO
    account = warp.warp_account()
    if not binary.is_file() or not account or not account.get("endpoint_pub_key"):
        return False
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="kich-dpi-ep-") as tmp:
        work = Path(tmp)
        config = work / "probe.yaml"
        config.write_text(probe_config(warp, host, port, account), encoding="utf-8")
        log = (work / "probe.log").open("w")
        try:
            process = subprocess.Popen(
                [str(binary), "-f", str(config), "-d", str(warp.C.STATE_DIR)],
                stdout=log, stderr=subprocess.STDOUT,
            )
        except OSError:
            log.close()
            return False
        try:
            time.sleep(1.5)
            cp = subprocess.run([
                "curl", "-fsS", "--max-time", "9", "-x",
                "http://127.0.0.1:%d" % port,
                "https://www.cloudflare.com/cdn-cgi/trace",
            ], capture_output=True, text=True, timeout=13)
            return cp.returncode == 0 and "warp=on" in cp.stdout
        except (OSError, subprocess.SubprocessError):
            return False
        finally:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
            log.close()


def wg_probe_config(warp, endpoint, account, local_port):
    from .warp_format import cidr_of, yaml_str
    host, _, port = endpoint.rpartition(":")
    ip4 = cidr_of(account.get("ipv4"), 4)
    lines = [
        "mixed-port: %d" % local_port,
        "bind-address: 127.0.0.1",
        "mode: rule",
        "log-level: error",
        'cache-file: ""',
        "find-process-mode: off",
        "proxies:",
        "  - name: WARP-WG-PROBE",
        "    type: wireguard",
        "    private-key: %s" % yaml_str(account["private_key"]),
    ]
    if ip4:
        lines.append("    ip: %s" % yaml_str(ip4))
    lines.extend([
        "    peers:",
        "      - server: %s" % yaml_str(host),
        "        port: %s" % port,
        "        public-key: %s" % yaml_str(account["public_key"]),
        "        allowed-ips: ['0.0.0.0/0']",
        "        persistent-keepalive: 25",
        "    udp: true",
        "    remote-dns-resolve: true",
        "    dns: ['1.1.1.1', '1.0.0.1']",
        "rules:",
        "  - MATCH,WARP-WG-PROBE",
        "",
    ])
    return "\n".join(lines)


def wg_endpoint_healthy(warp, endpoint, account):
    """A WireGuard endpoint is usable only if it exits outside the DME node."""
    import subprocess
    import tempfile
    import time

    binary = warp.C.MIHOMO
    if not binary.is_file() or not account.get("private_key") or not account.get("public_key"):
        return False
    local_port = free_port()
    with tempfile.TemporaryDirectory(prefix="kich-dpi-wg-") as tmp:
        work = Path(tmp)
        config = work / "probe.yaml"
        config.write_text(wg_probe_config(warp, endpoint, account, local_port),
                          encoding="utf-8")
        log = (work / "probe.log").open("w")
        try:
            process = subprocess.Popen(
                [str(binary), "-f", str(config), "-d", str(warp.C.STATE_DIR)],
                stdout=log, stderr=subprocess.STDOUT,
            )
        except OSError:
            log.close()
            return False
        try:
            time.sleep(3)
            cp = subprocess.run([
                "curl", "-fsS", "--max-time", "9", "-x",
                "http://127.0.0.1:%d" % local_port,
                "https://www.cloudflare.com/cdn-cgi/trace",
            ], capture_output=True, text=True, timeout=13)
            values = {}
            for line in cp.stdout.splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    values[key.strip()] = value.strip()
            return (cp.returncode == 0
                    and values.get("warp") in ("on", "plus")
                    and values.get("colo") not in ("", warp.C.WARP_WG_DME))
        except (OSError, subprocess.SubprocessError):
            return False
        finally:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
            log.close()


def wg_profile(warp):
    """Pick a working non-DME WireGuard endpoint for the generated config."""
    from .warp_format import cidr_of
    account = warp.wg_account()
    if not account:
        return {}
    cache = load_probe_cache(warp)
    fresh = _cache_fresh(cache)
    known = dict(cache.get("wg") or {})
    chosen = ""
    attempts = 0
    for endpoint in warp.C.WARP_WG_ENDPOINTS:
        if fresh and endpoint in known:
            ok = bool(known[endpoint])
        else:
            ok = wg_endpoint_healthy(warp, endpoint, account)
            known[endpoint] = ok
            attempts += 1
        if ok:
            chosen = endpoint
            break
        # Probing every sibling costs ~3 s each; one backup is enough.
        if attempts >= 2:
            break
    if attempts:
        cache["time"] = int(time.time())
        cache["path"] = str(cache.get("path") or "wg")
        cache["wg"] = known
        save_probe_cache(warp, cache)
    if not chosen:
        return {}
    host, _, port = chosen.rpartition(":")
    return {
        "wg_endpoint": host,
        "wg_port": int(port),
        "wg_private_key": account["private_key"],
        "wg_public_key": account["public_key"],
        "wg_ipv4": cidr_of(account.get("ipv4"), 4),
    }


def reachable_endpoints(warp, profile=None):
    """Prefer the pinned gateway, but use a proven sibling if it is blocked."""
    ordered = [C.WARP_ENDPOINT] + [ip for ip in C.WARP_ENDPOINTS
                                   if ip != C.WARP_ENDPOINT]
    key = path_key(profile or {})
    cache = load_probe_cache(warp)
    fresh = _cache_fresh(cache) and (not key or cache.get("path") == key)
    known = dict(cache.get("endpoints") or {})
    result = []
    attempts = 0
    for ip in ordered:
        if fresh and ip in known:
            ok = bool(known[ip])
        else:
            ok = tcp_open(ip) and endpoint_healthy(warp, ip)
            known[ip] = ok
            attempts += 1
        if ok:
            result.append(ip)
            break
        # The pinned gateway plus one backup covers a blocked pin without
        # probing every sibling on every rebuild.
        if attempts >= 2:
            break
    if attempts:
        cache["time"] = int(time.time())
        cache["path"] = key or str(cache.get("path") or "")
        cache["endpoints"] = known
        save_probe_cache(warp, cache)
    return result


def network_signature(warp):
    """Cheap, stable description of this machine's link (no gateway probes)."""
    route = default_route(warp)
    device = route["interface"]
    link_address = interface_address(warp, device)
    nets4 = _cidrs(_run(warp, ["ip", "-4", "route", "show", "table", "main",
                               "scope", "link", "dev", device])) if device else []
    if not nets4:
        nets4 = [link_address or "192.168.0.0/24"]
    nets6 = _cidrs(_run(warp, ["ip", "-6", "route", "show", "table", "main",
                               "scope", "link", "dev", device])) if device else []
    return {
        "interface": device,
        "gateway": route["gateway"],
        "address": route["address"] or link_address.split("/")[0],
        "networks4": nets4,
        "networks6": nets6,
        "mtu": interface_mtu(warp, device),
        "ipv6": has_ipv6(warp),
        "dns": dns_servers(warp),
    }


def warp_network(warp, probe=True):
    profile = network_signature(warp)
    endpoints = reachable_endpoints(warp, profile) if probe else []
    profile.update({
        "endpoint": endpoints[0] if endpoints else C.WARP_ENDPOINT,
        "endpoints": endpoints,
    })
    return profile
