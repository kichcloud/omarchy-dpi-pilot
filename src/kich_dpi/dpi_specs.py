"""Strategy tree and nfqws2 config rendering (pure data, no services)."""
from __future__ import annotations

import hashlib
import json

from . import constants as C
from . import core
from .templates import DISCORD_VOICE_TCP_PORTS, DISCORD_VOICE_UDP_PORTS


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
    """Split-only default: no TLS fake packets, no reordering of real data."""
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

    # Discord voice: poison DPI's view of IP discovery and STUN with QUIC
    # fakes. These UDP flows have no hostname, so the shared domain
    # hostlist cannot be used here.
    lines += [
        "--new", "--filter-udp=" + DISCORD_VOICE_UDP_PORTS,
        "--filter-l7=discord", "--payload=discord_ip_discovery",
        "--lua-desync=fake:blob=quic_google:repeats=6",
        "--new", "--filter-udp=" + DISCORD_VOICE_UDP_PORTS,
        "--filter-l7=stun", "--payload=stun",
        "--lua-desync=fake:blob=quic_google:repeats=6",
        "--new", "--filter-tcp=" + DISCORD_VOICE_TCP_PORTS,
        "--hostlist-domains=discord.media", "--payload=tls_client_hello",
        "--out-range=-d12",
        "--lua-desync=multisplit:seqovl=681:pos=1:seqovl_pattern=tls_google",
    ]

    domains = dpi_domains()
    if domains:
        hostlist = "--hostlist-domains=" + ",".join(domains)
        for l7 in ("http", "tls", "quic"):
            marker = "--filter-l7=" + l7
            if marker in lines:
                lines.insert(lines.index(marker) + 1, hostlist)
    return "\n".join(lines) + "\n"
