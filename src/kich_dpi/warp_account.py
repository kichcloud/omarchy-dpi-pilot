"""WARP account storage and Cloudflare MASQUE registration."""
from __future__ import annotations

import base64
import json
import platform
import secrets
import tempfile
from pathlib import Path

from .warp_format import strip_endpoint


def warp_account(warp):
    data = warp.core.read_dict(warp.C.WARP_ACCOUNT)
    needed = ("private_key", "endpoint_pub_key", "id", "access_token")
    if any(not str(data.get(key) or "").strip() for key in needed):
        return {}
    return data


def wg_account(warp):
    """Optional WireGuard identity used to leave a non-DME Cloudflare node."""
    data = warp.core.read_dict(warp.C.WARP_WG_ACCOUNT)
    needed = ("private_key", "public_key", "id", "access_token")
    if any(not str(data.get(key) or "").strip() for key in needed):
        return {}
    return data


def migrate_account(warp, home, uid=None, gid=None):
    legacy_dir = Path(home) / ".local" / "share" / warp.C.ENGINE_SLUG
    legacy = legacy_dir / "account.json"
    target = Path(home) / ".local" / "state" / warp.C.ENGINE_SLUG / "account.json"
    if legacy.is_file() and not target.exists():
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            warp.shutil.move(str(legacy), str(target))
            warp.os.chmod(target, 0o600)
            if uid is not None and gid is not None:
                warp.os.chown(target, uid, gid)
        except OSError:
            pass
    try:
        legacy_dir.rmdir()
    except OSError:
        pass


def save_warp_account(warp, account):
    warp.core.write_json(warp.C.WARP_ACCOUNT, account, mode=0o600)


def save_wg_account(warp, account):
    warp.core.write_json(warp.C.WARP_WG_ACCOUNT, account, mode=0o600)


def cf_error(warp, code, raw):
    message = raw
    try:
        body = json.loads(raw)
        message = body.get("message") or body.get("error") or raw
    except ValueError:
        pass
    if code in (401, 403):
        raise warp.core.Fail("Cloudflare отклонил аккаунт — нужна повторная регистрация")
    if code == 429 or "1015" in raw:
        raise warp.core.Fail("Cloudflare временно ограничил регистрацию, повторите позже")
    raise warp.core.Fail("Cloudflare API: HTTP %s: %s"
                         % (code, warp.core.clip(message, limit=200, strip=False)))


def cf_request(warp, path, payload, token="", method="POST"):
    """Cloudflare client API. curl is preferred: its ClientHello passes where
    Python's sometimes hangs on this host."""
    url = warp.C.CF_ORIGIN + "/" + warp.C.CF_VERSION + path
    body = json.dumps(payload).encode("utf-8")
    curl = warp.shutil.which("curl")
    if curl:
        args = [curl, "-sS", "--max-time", "30", "-X", method]
        for key, value in warp.C.CF_HEADERS.items():
            args.extend(["-H", "%s: %s" % (key, value)])
        args.extend(["-w", "\n%{http_code}", "--data-binary", "@-", url])
        if token:
            args[1:1] = ["-H", "Authorization: Bearer " + token]
        cp = warp.core.run(args, timeout=40, text=False, input=body)
        if cp.returncode != 0:
            detail = (cp.stderr or b"curl failed").decode("utf-8", "replace").strip()
            raise warp.core.Fail("нет связи с Cloudflare: %s"
                                 % warp.core.clip(detail, limit=200, strip=False))
        raw, _, code_text = cp.stdout.decode("utf-8", "replace").rpartition("\n")
        try:
            code = int(code_text.strip())
        except ValueError:
            code = 0
        if code >= 400 or code == 0:
            warp.cf_error(code, raw)
        return json.loads(raw or "{}")

    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=body,
                                 headers=dict(warp.C.CF_HEADERS), method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        warp.cf_error(exc.code, exc.read().decode("utf-8", "replace"))
    except urllib.error.URLError as exc:
        raise warp.core.Fail("нет связи с Cloudflare: %s" % exc.reason)


def warp_keys(warp):
    openssl = warp.shutil.which("openssl")
    if not openssl:
        raise warp.core.Fail("для ключей WARP нужен openssl")
    with tempfile.TemporaryDirectory(prefix="kich-dpi-warp-") as tmp:
        work = Path(tmp)
        pem, der, pub = work / "key.pem", work / "key.der", work / "pub.der"
        steps = (
            [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(pem)],
            [openssl, "ec", "-in", str(pem), "-outform", "DER", "-out", str(der)],
            [openssl, "ec", "-in", str(pem), "-pubout", "-outform", "DER", "-out", str(pub)],
        )
        for step in steps:
            cp = warp.core.run(step, timeout=20)
            if cp.returncode != 0:
                raise warp.core.Fail("openssl: " + warp.core.unit_error(cp, "", 200))
        private_key = base64.b64encode(der.read_bytes()).decode()
        public_key = base64.b64encode(pub.read_bytes()).decode()
    return private_key, public_key


def warp_enroll_fields(warp, updated, account):
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


def warp_patch(warp, identifier, token, key, name):
    return warp.cf_request("/reg/%s" % identifier, {
        "key": key, "key_type": "secp256r1", "tunnel_type": "masque", "name": name,
    }, token=token, method="PATCH")


def warp_register(warp):
    if warp.os.environ.get("KICH_DPI_OFFLINE"):
        raise warp.core.Fail("регистрация WARP недоступна в офлайн-режиме")
    now = warp.time.strftime("%Y-%m-%dT%H:%M:%S.000Z", warp.time.gmtime())
    reg = warp.cf_request("/reg", {
        "key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "install_id": "", "fcm_token": "", "tos": now, "model": "PC",
        "serial_number": secrets.token_hex(8), "os_version": "",
        "key_type": "curve25519", "tunnel_type": "wireguard", "locale": "en_US",
    })
    if not reg.get("id") or not reg.get("token"):
        raise warp.core.Fail("Cloudflare не вернул id/token при регистрации")
    private_key, public_key = warp.warp_keys()
    name = ("omarchy-%s" % (platform.node() or "linux"))[:64]
    updated = warp.warp_patch(reg["id"], reg["token"], public_key, name)
    account = {
        "private_key": private_key, "public_key": public_key,
        "id": updated.get("id") or reg["id"], "access_token": reg["token"],
        "name": name, "registered_at": int(warp.time.time()),
    }
    account = warp.warp_enroll_fields(updated, account)
    if not account.get("endpoint_pub_key"):
        raise warp.core.Fail("Cloudflare не вернул ключ MASQUE-шлюза")
    if not account.get("ipv4") and not account.get("ipv6"):
        raise warp.core.Fail("Cloudflare не вернул адрес устройства")
    warp.save_warp_account(account)
    return account


def warp_enroll(warp, account):
    updated = warp.warp_patch(account["id"], account["access_token"],
                              account["public_key"], account.get("name") or "omarchy")
    fresh = warp.warp_enroll_fields(updated, account)
    warp.save_warp_account(fresh)
    return fresh


def wg_public_key(warp, private_key):
    """Derive the X25519 public key Cloudflare stores for a WireGuard device."""
    openssl = warp.shutil.which("openssl")
    if not openssl:
        return private_key
    try:
        raw = base64.b64decode(private_key, validate=True)
        if len(raw) != 32:
            return private_key
        der = bytes.fromhex("302e020100300506032b656e04220420") + raw
        with tempfile.TemporaryDirectory(prefix="kich-dpi-wg-key-") as tmp:
            key = Path(tmp) / "key.pem"
            key.write_bytes(b"-----BEGIN PRIVATE KEY-----\n"
                            + base64.b64encode(der) + b"\n-----END PRIVATE KEY-----\n")
            cp = warp.core.run([openssl, "pkey", "-in", str(key), "-pubout",
                                "-outform", "DER"], timeout=20, text=False)
        if cp.returncode == 0 and len(cp.stdout) >= 32:
            return base64.b64encode(cp.stdout[-32:]).decode()
    except (ValueError, OSError):
        pass
    return private_key


def warp_wg_enroll_fields(warp, reg, private_key):
    peer = ((reg.get("config") or {}).get("peers") or [{}])[0]
    addresses = ((reg.get("config") or {}).get("interface") or {}).get("addresses") or {}
    return {
        "private_key": private_key,
        "public_key": peer.get("public_key") or "",
        "id": reg.get("id") or "",
        "access_token": reg.get("token") or "",
        "ipv4": addresses.get("v4") or "",
        "ipv6": addresses.get("v6") or "",
        "registered_at": int(warp.time.time()),
    }


def warp_register_wg(warp):
    """Register a separate WireGuard device; MASQUE anycast always exits via DME."""
    if warp.os.environ.get("KICH_DPI_OFFLINE"):
        raise warp.core.Fail("регистрация WARP недоступна в офлайн-режиме")
    private_key = base64.b64encode(secrets.token_bytes(32)).decode()
    public_key = warp.wg_public_key(private_key)
    name = ("omarchy-wg-%s" % (platform.node() or "linux"))[:64]
    reg = warp.cf_request("/reg", {
        "key": public_key, "install_id": "", "fcm_token": "",
        "tos": warp.time.strftime("%Y-%m-%dT%H:%M:%S.000Z", warp.time.gmtime()),
        "model": "PC", "serial_number": secrets.token_hex(8), "os_version": "",
        "key_type": "curve25519", "tunnel_type": "wireguard", "locale": "en_US",
    })
    if not reg.get("id") or not reg.get("token"):
        raise warp.core.Fail("Cloudflare не вернул id/token при регистрации WireGuard")
    warp.cf_request("/reg/%s" % reg["id"], {
        "key": public_key, "key_type": "curve25519", "tunnel_type": "wireguard",
        "warp_enabled": True, "name": name,
    }, token=reg["token"], method="PATCH")
    account = warp.warp_wg_enroll_fields(reg, private_key)
    if not account.get("public_key") or not account.get("ipv4"):
        raise warp.core.Fail("Cloudflare не вернул ключ/адрес WireGuard")
    warp.save_wg_account(account)
    return account
