"""Paths, tunables and the small tables that describe kich-dpi.

Nothing in here performs I/O except resolving HOME. Keeping every constant in
one module makes the rest of the app easy to point at a temporary tree in tests.
"""
from __future__ import annotations

import os
import pwd
from pathlib import Path

VERSION = "0.8.0"

UNIT = "kich-dpi.service"
TABLE = "kich_dpi"
QUEUE = 230
FWMARK = "0x10000000"
# mihomo owns the 9000 block, so the DPI rule sits just above it.
DPI_RULE_PRIORITY = 8999

ENGINE_SLUG = "kich-dpi"
ENGINE_ROOT = Path("/opt") / ENGINE_SLUG
APP_DIR = ENGINE_ROOT / "app"
ENGINE_DIR = ENGINE_ROOT / "engine"
UNIT_PATH = Path("/etc/systemd/system") / UNIT
POLKIT_PATH = Path("/etc/polkit-1/rules.d/49-kich-dpi.rules")
SYSCTL_PATH = Path("/etc/sysctl.d/90-kich-dpi.conf")

RELEASE_API = "https://api.github.com/repos/bol-van/zapret2/releases/latest"
TARGETS = (
    ("youtube", "YouTube", "https://www.youtube.com/"),
    ("discord", "Discord", "https://discord.com/"),
    ("google", "Google", "https://www.google.com/generate_204"),
)

def invoking_home():
    """Restore the session user's home when a command arrives via pkexec.

    pkexec resets HOME to /root. Commands such as `repair` still have to read
    the invoking user's config, while `setup` uses target_user() explicitly.
    """
    home = os.environ.get("HOME") or pwd.getpwuid(os.getuid()).pw_dir
    if os.geteuid() != 0:
        return home
    for key in ("PKEXEC_UID", "SUDO_UID"):
        raw = os.environ.get(key)
        if not raw:
            continue
        try:
            return pwd.getpwuid(int(raw)).pw_dir
        except (ValueError, KeyError):
            continue
    return home


HOME = Path(invoking_home())
CONFIG_DIR = HOME / ".config" / ENGINE_SLUG
STATE_DIR = HOME / ".local" / "state" / ENGINE_SLUG
DPI_DOMAINS_FILE = CONFIG_DIR / "dpi-domains.txt"
DPI_DOMAINS_DEFAULT = (
    "discord.com", "discordapp.com", "youtube.com", "youtu.be",
    "googlevideo.com", "ytimg.com", "ggpht.com",
)
ACTIVE_FILE = CONFIG_DIR / "active.json"
STATE_FILE = CONFIG_DIR / "state.json"
STRATEGIES_FILE = CONFIG_DIR / "strategies.json"
CHECK_FILE = STATE_DIR / "check.json"
PROGRESS_FILE = STATE_DIR / "progress.json"

WARP_UNIT = "kich-dpi-warp.service"
WARP_UNIT_PATH = Path("/etc/systemd/system") / WARP_UNIT
WARP_RUN = APP_DIR / "bin" / "kich-dpi-warp-run"
MIHOMO = ENGINE_ROOT / "mihomo"
WARP_CONFIG = CONFIG_DIR / "warp.yaml"
WARP_ACCOUNT = STATE_DIR / "account.json"
WARP_CHECK_FILE = STATE_DIR / "warp-check.json"

REPAIR_DISCORD_DOMAINS = ("discord.com", "discordapp.com", "discordapp.net", "discord.gg")
REPAIR_MEDIA_DOMAINS = ("media.discordapp.net", "images.discordapp.net")
REPAIR_MEDIA_BLOCKED_IP = "162.159.133.232"
REPAIR_MEDIA_GOOD_IPS = ("162.159.129.233", "162.159.133.233")
REPAIR_HOSTS = Path("/etc/hosts")
REPAIR_HOSTS_BACKUP = Path("/etc/hosts.kich-dpi-bak")
REPAIR_HOSTS_MARKER = "# kich-dpi: Discord media CDN"

WARP_DEVICE = "kichwarp"
WARP_MIXED_PORT = 17890
BUNDLED_RULES = APP_DIR / "data" / "rules"
WARP_RULES = STATE_DIR / "rules"
WARP_USER_DOMAINS = CONFIG_DIR / "direct-domains.txt"
WARP_USER_PROCESSES = CONFIG_DIR / "direct-processes.txt"
WARP_USER_DOMAINS_HEADER = """# Domains that always go direct, one per line (`#` starts a comment).
# Applied by `kich-dpi warp-on`; this file is never rewritten.
"""
WARP_USER_PROCESSES_HEADER = """# Applications that always go direct, one per line, matched against the
# process name (`ps -o comm=`). Applied by `kich-dpi warp-on`; this file is
# never rewritten. Matching makes mihomo track process owners, so keep it
# empty unless you actually need it.
"""

CF_ORIGIN = "https://api.cloudflareclient.com"
CF_VERSION = "v0a4471"
CF_HEADERS = {
    "User-Agent": "WARP for Android",
    "CF-Client-Version": "a-6.35-4471",
    "Content-Type": "application/json; charset=UTF-8",
    "Accept": "application/json",
    "Accept-Encoding": "identity",
}
# Only the `.2` anycast siblings speak H2 with the key Cloudflare hands out at
# registration. Of those, 199.2 is pinned: the others were measurably slower or
# dropped handshakes in the evening.
WARP_ENDPOINTS = ("162.159.198.2", "162.159.199.2", "162.159.197.2", "162.159.196.2")
WARP_ENDPOINT = "162.159.199.2"
WARP_SNI = "speed.cloudflare.com"
WARP_MARK = "0x20000000"

# Root of the plugin tree: `<plugin>` for sources and `<app>` for an installed
# copy. Both layouts contain `src/kich_dpi` or `lib/kich_dpi` respectively.
SOURCE_ROOT = Path(os.environ.get("KICH_DPI_ROOT") or Path(__file__).resolve().parents[2])
