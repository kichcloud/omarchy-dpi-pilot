"""nftables and ip-rule setup for the DPI bypass."""
from __future__ import annotations

from . import constants as C
from . import core
from .templates import NFT_SCRIPT


def fw_rule(action):
    return ["ip", "rule", action, "fwmark", "%s/%s" % (C.FWMARK, C.FWMARK),
            "lookup", "main", "priority", str(C.DPI_RULE_PRIORITY)]


def fw_up():
    script = NFT_SCRIPT.format(table=C.TABLE, mark=C.FWMARK, queue=C.QUEUE,
                               warp_ips=", ".join(C.WARP_ENDPOINTS))
    core.run(["nft", "delete", "table", "inet", C.TABLE])
    cp = core.run(["nft", "-f", "-"], input=script)
    if cp.returncode != 0:
        raise core.Fail("nft: " + core.unit_error(cp, "", 500))
    core.run(fw_rule("del"))
    cp = core.run(fw_rule("add"))
    if cp.returncode != 0:
        raise core.Fail("ip rule: " + core.unit_error(cp, "", 500))


def fw_down():
    core.run(["nft", "delete", "table", "inet", C.TABLE], timeout=10)
    core.run(fw_rule("del"), timeout=10)


def cmd_fw_down():
    fw_down()
    return 0
