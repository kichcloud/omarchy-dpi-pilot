"""WARP (mihomo MASQUE): account, generated config, status and checks."""
from __future__ import annotations

import os
import shutil
import sys
import time

from . import constants as C
from . import core
from . import warp_account as _account
from . import warp_format as _format
from . import warp_network as _network
from . import warp_service as _service
from .warp_format import (
    cidr_of, domain_payload, strip_endpoint, warp_config_text, yaml_str,
)

_self = sys.modules[__name__]


def warp_available():
    return _service.warp_available(_self)


def warp_systemctl(*args, timeout=25):
    return _service.warp_systemctl(_self, *args, timeout=timeout)


def warp_unit_state():
    return _service.warp_unit_state(_self)


def warp_account():
    return _account.warp_account(_self)


def wg_account():
    return _account.wg_account(_self)


def migrate_account(home, uid=None, gid=None):
    return _account.migrate_account(_self, home, uid, gid)


def save_warp_account(account):
    return _account.save_warp_account(_self, account)


def save_wg_account(account):
    return _account.save_wg_account(_self, account)


def cf_error(code, raw):
    return _account.cf_error(_self, code, raw)


def cf_request(path, payload, token="", method="POST"):
    return _account.cf_request(_self, path, payload, token, method)


def warp_keys():
    return _account.warp_keys(_self)


def warp_enroll_fields(updated, account):
    return _account.warp_enroll_fields(_self, updated, account)


def warp_patch(identifier, token, key, name):
    return _account.warp_patch(_self, identifier, token, key, name)


def warp_register():
    return _account.warp_register(_self)


def warp_enroll(account):
    return _account.warp_enroll(_self, account)


def wg_public_key(private_key):
    return _account.wg_public_key(_self, private_key)


def warp_wg_enroll_fields(reg, private_key):
    return _account.warp_wg_enroll_fields(_self, reg, private_key)


def warp_register_wg():
    return _account.warp_register_wg(_self)


def install_rule_lists():
    return _service.install_rule_lists(_self)


def ensure_user_lists():
    return _service.ensure_user_lists(_self)


def warp_network(probe=True):
    return _network.warp_network(_self, probe)


def warp_network_signature():
    return _network.network_signature(_self)


def wg_endpoint_healthy(endpoint, account):
    return _network.wg_endpoint_healthy(_self, endpoint, account)


def wg_profile():
    return _network.wg_profile(_self)


def warp_config_text(account, network=None):
    return _format.warp_config_text(account, network)


def warp_build_inputs():
    return _service.warp_build_inputs(_self)


def warp_build_stamp(account=None):
    return _service.warp_build_stamp(_self, account)


def warp_build(account=None, force=False):
    return _service.warp_build(_self, account, force)


def warp_status(_states=None):
    return _service.warp_status(_self, _states)


def remote_exists(url):
    return _service.remote_exists(_self, url)


def mihomo_version():
    return _service.mihomo_version(_self)


def warp_check_data():
    return _service.warp_check_data(_self)


def cmd_warp_config(force=False):
    return _service.cmd_warp_config(_self, force)


def cmd_warp_on():
    return _service.cmd_warp_on(_self)


def cmd_warp_off():
    return _service.cmd_warp_off(_self)


def cmd_warp_toggle():
    return _service.cmd_warp_toggle(_self)


def cmd_warp_register(force=False):
    return _service.cmd_warp_register(_self, force)


def cmd_warp_check():
    return _service.cmd_warp_check(_self)
