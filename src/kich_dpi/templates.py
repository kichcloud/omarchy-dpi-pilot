"""Static templates rendered by the installer and unit generator."""
from __future__ import annotations

LAUNCHER_TEMPLATE = '''#!/usr/bin/env python3
# Installed by kich-dpi. A small shim: the app itself lives in ../lib.
import os
import sys

root = {root!r}
sys.path.insert(0, os.path.join(root, "lib"))
os.environ["KICH_DPI_ROOT"] = root

from kich_dpi.cli import main
if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''

UNIT_GUARDS = """ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=-{home}/.config/kich-dpi -{home}/.local/state/kich-dpi
PrivateTmp=yes
"""

UNIT_HARDENING = """ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LimitNOFILE=65535
"""

UNIT_TEMPLATE = """# Installed by kich-dpi (Omarchy plugin). Removed by `kich-dpi remove`.
[Unit]
Description=DPI bypass for Omarchy (kich-dpi)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/kich-dpi/engine/current/nfqws2

[Service]
Type=simple
User={user}
Group={group}
Environment=HOME={home}
ExecStart=/usr/bin/python3 -I /opt/kich-dpi/app/bin/kich-dpi _run
ExecStopPost=/usr/bin/python3 -I /opt/kich-dpi/app/bin/kich-dpi _fw-down
Restart=on-failure
RestartSec=3
TimeoutStopSec=6
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
{guards}
PrivateDevices=yes
ProtectKernelTunables=yes
{hardening}

[Install]
WantedBy=multi-user.target
"""

POLKIT_TEMPLATE = """// Installed by kich-dpi. Allows the session user to manage our two units.
polkit.addRule(function(action, subject) {{
  if (action.id !== "org.freedesktop.systemd1.manage-units") return;
  if (subject.user !== "{user}") return;
  var unit = action.lookup("unit");
  if (unit === "{unit}" || unit === "{warp_unit}") return polkit.Result.YES;
}});
"""

WARP_UNIT_TEMPLATE = """# Installed by kich-dpi (Omarchy plugin). Removed by `kich-dpi remove`.
[Unit]
Description=WARP MASQUE tunnel for Omarchy (kich-dpi)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/kich-dpi/mihomo
ConditionPathExists={home}/.config/kich-dpi/warp.yaml

[Service]
Type=simple
User={user}
Group={group}
Environment=HOME={home}
WorkingDirectory={home}/.local/state/kich-dpi
ExecStartPre=/opt/kich-dpi/mihomo -t -f {home}/.config/kich-dpi/warp.yaml -d {home}/.local/state/kich-dpi
ExecStart=/opt/kich-dpi/app/bin/kich-dpi-warp-run
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
{guards}
PrivateDevices=no
DeviceAllow=/dev/net/tun rw
ProtectKernelTunables=no
{hardening}

[Install]
WantedBy=multi-user.target
"""

WARP_RUN_TEMPLATE = '''#!/usr/bin/python3
# Installed by kich-dpi. Starts mihomo only while the WARP toggle is on.
import json
import os
import sys

STATE = {state!r}
MIHOMO = "/opt/kich-dpi/mihomo"
CONFIG = {config!r}
DATA = {data!r}

try:
    with open(STATE, encoding="utf-8") as fh:
        wanted = bool(json.load(fh).get("warp", True))
except (OSError, ValueError):
    wanted = True
if not wanted:
    sys.exit(0)
os.execv(MIHOMO, [MIHOMO, "-f", CONFIG, "-d", DATA])
'''

# Discord voice: discovery/STUN use UDP 19294-19344 and 50000-50100,
# while the voice handshake may fall back to non-standard TLS ports.
DISCORD_VOICE_UDP_PORTS = "19294-19344,50000-50100"
DISCORD_VOICE_TCP_PORTS = "2053,2083,2087,2096,8443"

NFT_SCRIPT = """table inet {table} {{
  set warp_ep {{
    type ipv4_addr
    elements = {{ {warp_ips} }}
  }}
  chain predefrag {{
    type filter hook output priority -401; policy accept;
    meta mark and {mark} != 0 notrack comment "kich-dpi generated"
  }}
  chain out {{
    type filter hook postrouting priority 101; policy accept;
    meta oiftype 65534 return comment "skip tunnels"
    ip daddr @warp_ep return comment "skip WARP endpoints"
    meta mark and {mark} != 0 return
    tcp dport {{ 80, 443 }} ct original packets 1-16 queue num {queue} bypass
    tcp dport {{ 2053, 2083, 2087, 2096, 8443 }} ct original packets 1-16 queue num {queue} bypass
    udp dport 443 ct original packets 1-6 queue num {queue} bypass
    udp dport {{ 19294-19344, 50000-50100 }} ct original packets 1-16 queue num {queue} bypass
  }}
  chain in {{
    type filter hook prerouting priority -101; policy accept;
    meta iiftype 65534 return comment "skip tunnels"
    ip saddr @warp_ep return comment "skip WARP endpoints"
    meta mark and {mark} != 0 return
    tcp sport {{ 80, 443 }} ct reply packets 1-12 queue num {queue} bypass
    udp sport 443 ct reply packets 1-4 queue num {queue} bypass
  }}
}}
"""


def unit_text(template, home, **fields):
    return template.format(
        home=home, guards=UNIT_GUARDS.format(home=home),
        hardening=UNIT_HARDENING, **fields,
    )
