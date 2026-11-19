import importlib.machinery
import ipaddress
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parent
BIN = ROOT / "kich-dpi"


def load():
    loader = importlib.machinery.SourceFileLoader("kich_dpi", str(BIN))
    spec = importlib.util.spec_from_loader("kich_dpi", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class CandidatesTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_default_strategy_avoids_disorder(self):
        # The shipped fallback must not be a strategy that breaks direct TLS.
        self.assertEqual(self.mod.default_spec()["action"], "fakedsplit")
        self.assertNotEqual(self.mod.default_spec()["action"], "multidisorder")

    def test_eighteen_unique_candidates(self):
        rows = self.mod.candidates()
        self.assertEqual(len(rows), 18)
        names = [row["name"] for row in rows]
        self.assertEqual(len(set(names)), len(names))
        ids = [self.mod.strategy_id(row) for row in rows]
        self.assertEqual(len(set(ids)), len(ids))

    def test_every_candidate_has_valid_primitives(self):
        for row in self.mod.candidates():
            self.assertIn(row["action"], {
                "multisplit", "multidisorder", "fakedsplit", "fakeddisorder",
            })
            self.assertTrue(row["pos"])
            if row["fake"] is None:
                self.assertIn(row["action"], {"fakedsplit", "fakeddisorder"})
            else:
                self.assertGreaterEqual(row["repeats"], 1)

    def test_config_limits_desync_to_target_hosts(self):
        from unittest import mock
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "dpi-domains.txt"
            path.write_text("discord.com\nyoutube.com\n", encoding="utf-8")
            with mock.patch.object(mod, "DPI_DOMAINS_FILE", path):
                text = mod.render_config(mod.candidates()[0])
        self.assertEqual(text.count("--hostlist-domains=discord.com,youtube.com"), 3)
        self.assertIn("--filter-l7=tls\n--hostlist-domains=discord.com,youtube.com", text)

    def test_empty_domain_list_keeps_global_bypass(self):
        from unittest import mock
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "dpi-domains.txt"
            path.write_text("# no selective hosts\n", encoding="utf-8")
            with mock.patch.object(mod, "DPI_DOMAINS_FILE", path):
                text = mod.render_config(mod.candidates()[0])
        self.assertNotIn("--hostlist-domains", text)

    def test_config_has_three_profiles(self):
        for row in self.mod.candidates():
            text = self.mod.render_config(row)
            self.assertIn("--qnum=230", text)
            self.assertIn("--fwmark=0x10000000", text)
            self.assertIn("--filter-tcp=80", text)
            self.assertIn("--filter-tcp=443", text)
            self.assertIn("--filter-udp=443", text)
            self.assertEqual(text.count("--new"), 2)
            self.assertIn("zapret-antidpi.lua", text)
            self.assertNotIn("--dry-run", text)

    def test_fake_and_split_only_variants(self):
        rows = {row["action"]: row for row in self.mod.candidates()}
        tls = lambda row: self.mod.render_config(row).split("--filter-tcp=443", 1)[1].split("--new", 1)[0]
        self.assertIn("fake:blob=", tls(rows["multisplit"]))
        self.assertIn("pattern=tls_google", tls(rows["fakedsplit"]))
        self.assertNotIn("fake:blob=", tls(rows["fakedsplit"]))

    def test_dry_run_against_real_engine(self):
        engine = os.environ.get("KICH_DPI_ENGINE_DIR")
        if not engine:
            self.skipTest("KICH_DPI_ENGINE_DIR is not set")
        self.mod.ENGINE_DIR = pathlib.Path(engine)
        binary = self.mod.engine_bin()
        if not binary.exists():
            self.skipTest("no nfqws2 in %s" % engine)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "test.conf"
            for row in self.mod.candidates():
                path.write_text(self.mod.render_config(row, dry_run=True), encoding="utf-8")
                cp = subprocess.run([str(binary), "@" + str(path)],
                                    capture_output=True, text=True)
                self.assertEqual(cp.returncode, 0,
                                 "%s failed: %s" % (row["name"], cp.stdout + cp.stderr))


class EngineExtractTest(unittest.TestCase):
    def test_extracts_only_needed_files_and_links_current(self):
        mod = load()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            mod.ENGINE_DIR = tmp / "engine"
            mod.ENGINE_DIR.mkdir(parents=True)
            archive = tmp / "zapret2-v9.9.9.tar.gz"

            with tarfile.open(archive, "w:gz") as tf:
                def add(name, data=b"x"):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))

                root = "zapret2-v9.9.9/"
                add(root + "binaries/linux-x86_64/nfqws2", b"#!/bin/sh\n")
                add(root + "lua/zapret-lib.lua", b"-- lib\n")
                add(root + "lua/zapret-antidpi.lua", b"-- anti\n")
                add(root + "files/fake/zero.bin", b"\0")
                add(root + "docs/readme.md", b"unneeded")
                add("../escape", b"bad")

            mod.machine_arch = lambda: "x86_64"
            target = mod.extract_engine(archive, "v9.9.9")

            self.assertTrue((target / "nfqws2").exists())
            self.assertTrue((target / "lua" / "zapret-lib.lua").exists())
            self.assertTrue((target / "files" / "fake" / "zero.bin").exists())
            self.assertFalse((target / "docs").exists())
            self.assertFalse((tmp / "escape").exists())
            self.assertEqual(os.readlink(mod.ENGINE_DIR / "current"), "v9.9.9")
            self.assertTrue(os.access(target / "nfqws2", os.X_OK))

    def test_rejects_archive_without_binary(self):
        mod = load()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            mod.ENGINE_DIR = tmp / "engine"
            mod.ENGINE_DIR.mkdir(parents=True)
            archive = tmp / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                info = tarfile.TarInfo("zapret2-v1/lua/zapret-lib.lua")
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
            mod.machine_arch = lambda: "x86_64"
            with self.assertRaises(mod.Fail):
                mod.extract_engine(archive, "v1")


class WarpTest(unittest.TestCase):
    ACCOUNT = {
        "private_key": "cHJpdg==",
        "public_key": "cHVi",
        "endpoint_pub_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH\n-----END PUBLIC KEY-----",
        "id": "abcdef123456",
        "access_token": "token",
        "name": "omarchy-test",
        "ipv4": "172.16.0.2",
        "ipv6": "2606:4700:110:8a36::2",
    }

    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = pathlib.Path(self.tmp.name)
        # The real paths point into /opt and $HOME; keep every test in a sandbox.
        self.mod.BUNDLED_RULES = ROOT
        self.mod.WARP_RULES = base / "rules"
        self.mod.WARP_USER_DOMAINS = base / "direct-domains.txt"
        self.mod.WARP_USER_PROCESSES = base / "direct-processes.txt"
        self.mod.install_rule_lists()

    def test_config_is_valid_and_keeps_ru_traffic_direct(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")
        data = yaml.safe_load(self.mod.warp_config_text(self.ACCOUNT))
        self.assertTrue(data["tun"]["enable"])
        self.assertEqual(data["tun"]["device"], "kichwarp")
        # One pinned gateway: rotating between endpoints dropped handshakes.
        self.assertEqual(len(data["proxies"]), 1)
        proxy = data["proxies"][0]
        self.assertEqual(proxy["name"], "WARP")
        self.assertEqual(proxy["type"], "masque")
        self.assertEqual(proxy["port"], 443)
        self.assertEqual(proxy["network"], "quic")
        self.assertEqual(proxy["server"], self.mod.WARP_ENDPOINT)
        # YouTube's IPv4 egress is throttled here; its IPv6 path is clean.
        self.assertEqual(proxy["ip-version"], "ipv6-prefer")
        # QUIC has to ride the tunnel too, otherwise browsers stall on it.
        self.assertTrue(proxy["udp"])
        self.assertNotIn("BEGIN", proxy["public-key"])
        self.assertNotIn("proxy-groups", data)
        self.assertEqual(data["routing-mark"], 0x20000000)
        # Diagnostics dial the tunnel through this local proxy, not the TUN.
        self.assertEqual(data["mixed-port"], self.mod.WARP_MIXED_PORT)
        self.assertEqual(data["bind-address"], "127.0.0.1")
        # No process rules: tracking owners would be pure overhead.
        self.assertEqual(data["find-process-mode"], "off")
        self.assertEqual(data["rule-providers"]["ru-domain"]["behavior"], "domain")
        self.assertEqual(data["rule-providers"]["ru-ip"]["behavior"], "ipcidr")
        self.assertTrue(pathlib.Path(data["rule-providers"]["ru-domain"]["path"]).is_file())
        self.assertIn("RULE-SET,ru-domain,DIRECT", data["rules"])
        self.assertIn("RULE-SET,ru-ip,DIRECT", data["rules"])
        # `no-resolve` would skip this rule for every domain connection, so a
        # Russian host missing from the domain list leaked into the tunnel.
        self.assertNotIn("RULE-SET,ru-ip,DIRECT,no-resolve", data["rules"])
        self.assertIn("AND,((NETWORK,udp),(DST-PORT,443)),WARP", data["rules"])
        self.assertIn("NETWORK,udp,DIRECT", data["rules"])
        self.assertEqual(data["rules"][-1], "MATCH,WARP")

    def test_user_lists_add_rules_and_turn_on_process_matching(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")
        self.mod.WARP_USER_DOMAINS.write_text("# своё\nmy.example\n", encoding="utf-8")
        self.mod.WARP_USER_PROCESSES.write_text("telegram\n", encoding="utf-8")
        self.mod.install_rule_lists()
        data = yaml.safe_load(self.mod.warp_config_text(self.ACCOUNT))
        self.assertEqual(data["find-process-mode"], "strict")
        self.assertEqual(data["rules"][0], "PROCESS-NAME,telegram,DIRECT")
        self.assertIn("RULE-SET,direct-domains,DIRECT", data["rules"])
        # mihomo reads the generated copy, where every entry carries `+.`.
        payload = pathlib.Path(data["rule-providers"]["direct-domains"]["path"])
        self.assertEqual(payload, self.mod.WARP_RULES / "direct-domains.txt")
        self.assertEqual(payload.read_text(encoding="utf-8"), "+.my.example\n")

    def test_domain_lists_use_suffix_matching(self):
        # A bare entry matches one exact host, so subdomains slipped to WARP.
        payload = (self.mod.WARP_RULES / "ru-domain.txt").read_text(encoding="utf-8")
        self.assertIn("\n+.yandex.net\n", payload)
        self.assertIn("\n+.ya.ru\n", payload)
        self.assertNotIn("\nyandex.net\n", payload)
        for line in payload.splitlines():
            if not line or line.startswith("#"):
                continue
            self.assertTrue(line.startswith("+."), line)
        self.assertEqual(self.mod.domain_payload("a.ru\n\n# x\n+.b.ru\n"),
                         "+.a.ru\n\n# x\n+.b.ru\n")

    def test_comma_in_process_name_is_rejected(self):
        self.mod.WARP_USER_PROCESSES.write_text("bad,name\n", encoding="utf-8")
        with self.assertRaises(self.mod.Fail):
            self.mod.warp_config_text(self.ACCOUNT)

    def test_rule_lists_ship_with_the_plugin(self):
        domains = self.mod.list_lines(ROOT / "ru-domain.txt")
        ips = self.mod.list_lines(ROOT / "ru-ip.txt")
        self.assertIn("gosuslugi.ru", domains)
        self.assertGreater(len(domains), 40)
        self.assertNotIn("#", domains[0])
        self.assertGreater(len(ips), 5000)
        for item in ips[::200]:
            ipaddress.ip_network(item)

    def test_user_lists_are_created_once(self):
        mod = self.mod
        mod.ensure_user_lists()
        self.assertTrue(mod.WARP_USER_DOMAINS.is_file())
        self.assertTrue(mod.WARP_USER_PROCESSES.is_file())
        mod.WARP_USER_DOMAINS.write_text("kept.example\n", encoding="utf-8")
        mod.ensure_user_lists()
        self.assertEqual(mod.WARP_USER_DOMAINS.read_text(encoding="utf-8"), "kept.example\n")

    def test_build_asks_for_the_system_part_when_lists_are_missing(self):
        from unittest import mock
        mod = self.mod
        with mock.patch.object(mod, "warp_account", lambda: dict(self.ACCOUNT)), \
             mock.patch.object(mod, "WARP_CONFIG",
                               pathlib.Path(self.tmp.name) / "warp.yaml"), \
             mock.patch.object(mod, "BUNDLED_RULES", pathlib.Path(self.tmp.name) / "none"):
            with self.assertRaises(mod.Fail) as ctx:
                mod.warp_build()
        self.assertIn("обновите", str(ctx.exception))

    def test_warp_check_dials_the_proxy_port(self):
        from unittest import mock
        mod = self.mod
        trace = "ip=104.28.0.1\nwarp=on\ncolo=DME\n"
        calls = []

        def fake(argv, **kwargs):
            calls.append(list(argv))
            if argv[:2] == ["ip", "route"]:
                return subprocess.CompletedProcess(argv, 0, "1.1.1.1 dev kichwarp table 2022\n", "")
            return subprocess.CompletedProcess(argv, 0, trace, "")

        buf = io.StringIO()
        with mock.patch.object(mod.subprocess, "run", side_effect=fake), \
             mock.patch.object(mod, "WARP_CHECK_FILE",
                               pathlib.Path(self.tmp.name) / "warp-check.json"), \
             mock.patch.object(mod.sys, "stdout", buf):
            mod.cmd_warp_check()

        curl = [call for call in calls if call[0] == "curl"][0]
        self.assertIn("-x", curl)
        self.assertIn("http://127.0.0.1:%d" % mod.WARP_MIXED_PORT, curl)
        result = json.loads(buf.getvalue())["check"]
        self.assertTrue(result["ok"])
        self.assertEqual(result["colo"], "DME")
        # The tunnel works and the kernel really sends traffic through it.
        self.assertTrue(result["tun"])

    def test_warp_check_reports_a_route_that_bypasses_the_tunnel(self):
        from unittest import mock
        mod = self.mod
        trace = "ip=104.28.0.1\nwarp=on\ncolo=DME\n"

        def fake(argv, **kwargs):
            if argv[:2] == ["ip", "route"]:
                return subprocess.CompletedProcess(argv, 0, "1.1.1.1 dev enp8s0 src 192.168.0.5\n", "")
            return subprocess.CompletedProcess(argv, 0, trace, "")

        buf = io.StringIO()
        with mock.patch.object(mod.subprocess, "run", side_effect=fake), \
             mock.patch.object(mod, "WARP_CHECK_FILE",
                               pathlib.Path(self.tmp.name) / "warp-check.json"), \
             mock.patch.object(mod.sys, "stdout", buf):
            mod.cmd_warp_check()
        result = json.loads(buf.getvalue())["check"]
        self.assertTrue(result["ok"])
        self.assertFalse(result["tun"])

    def test_warp_unit_validates_the_config_before_start(self):
        text = self.mod.unit_text(self.mod.WARP_UNIT_TEMPLATE, "/home/u", user="u", group="g")
        lines = text.splitlines()
        pre = [i for i, line in enumerate(lines) if line.startswith("ExecStartPre=")]
        start = [i for i, line in enumerate(lines) if line.startswith("ExecStart=")]
        self.assertTrue(pre, "WARP unit must validate the generated YAML")
        self.assertIn(" -t ", lines[pre[0]])
        self.assertLess(pre[0], start[0])

    def test_warp_unit_starts_through_the_state_aware_wrapper(self):
        text = self.mod.unit_text(self.mod.WARP_UNIT_TEMPLATE, "/home/u", user="u", group="g")
        self.assertIn("ExecStart=/opt/kich-dpi/app/bin/kich-dpi-warp-run", text)
        self.assertNotIn("ExecStart=/opt/kich-dpi/mihomo -f", text)

    def test_unit_templates_render_shared_hardening(self):
        shared = (
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "PrivateTmp=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            "LimitNOFILE=65535",
        )
        for template in (self.mod.UNIT_TEMPLATE, self.mod.WARP_UNIT_TEMPLATE):
            lines = self.mod.unit_text(template, "/home/u", user="u", group="g").splitlines()
            self.assertFalse([line for line in lines if "{" in line])
            for line in shared:
                self.assertIn(line, lines)
        self.assertIn("PrivateDevices=yes", self.mod.unit_text(
            self.mod.UNIT_TEMPLATE, "/home/u", user="u", group="g").splitlines())
        self.assertIn("DeviceAllow=/dev/net/tun rw", self.mod.unit_text(
            self.mod.WARP_UNIT_TEMPLATE, "/home/u", user="u", group="g").splitlines())


    def test_missing_account_is_rejected(self):
        with self.assertRaises(self.mod.Fail):
            self.mod.warp_config_text({})

    def test_endpoint_and_cidr_normalisation(self):
        self.assertEqual(self.mod.strip_endpoint("162.159.198.2:443"), "162.159.198.2")
        self.assertEqual(self.mod.strip_endpoint("[2606:4700::1]:443"), "2606:4700::1")
        self.assertEqual(self.mod.cidr_of("172.16.0.2", 4), "172.16.0.2/32")
        self.assertEqual(self.mod.cidr_of("2606:4700::2", 6), "2606:4700::2/128")
        self.assertEqual(self.mod.cidr_of("bad", 4), "")

    def test_no_usque_conflict_guard(self):
        # A third-party tunnel must never block toggling WARP on or off.
        self.assertNotIn("usque", BIN.read_text(encoding="utf-8").lower())

    def test_config_passes_mihomo_validation(self):
        binary = os.environ.get("KICH_DPI_MIHOMO")
        if not binary or not pathlib.Path(binary).exists():
            self.skipTest("KICH_DPI_MIHOMO is not set")
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        private_key, public_key = self.mod.warp_keys()
        _, gateway = self.mod.warp_keys()
        account = dict(self.ACCOUNT, private_key=private_key, public_key=public_key,
                       endpoint_pub_key=gateway)
        # mihomo only accepts rule-provider paths under $HOME or its own data
        # directory, so the config and the lists share the sandbox here.
        tmp = self.tmp.name
        config = pathlib.Path(tmp) / "warp.yaml"
        config.write_text(self.mod.warp_config_text(account), encoding="utf-8")
        cp = subprocess.run([binary, "-t", "-f", str(config), "-d", tmp],
                            capture_output=True, text=True, timeout=60)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)

    def test_nft_skips_warp_endpoints(self):
        script = self.mod.NFT_SCRIPT.format(
            table="kich_dpi", mark="0x10000000",
            queue=230, warp_ips=", ".join(self.mod.WARP_ENDPOINTS))
        for endpoint in self.mod.WARP_ENDPOINTS:
            self.assertIn(endpoint, script)
        self.assertIn("ip daddr @warp_ep return", script)
        self.assertIn("ip saddr @warp_ep return", script)
        # mihomo's own sockets are queued like everything else: the fwmark rule
        # keeps their desynced packets out of the TUN, so RU sites mihomo dials
        # DIRECT keep their bypass while WARP is up.
        self.assertNotIn(self.mod.WARP_MARK, script)

    def test_fw_rule_keeps_stamped_packets_off_the_tunnel(self):
        from unittest import mock
        mod = self.mod
        calls = []

        def run(argv, **kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(mod.subprocess, "run", side_effect=run):
            mod.fw_up()
            mod.fw_down()

        stamp = "0x10000000/0x10000000"
        add = ["ip", "rule", "add", "fwmark", stamp, "lookup", "main",
               "priority", str(mod.DPI_RULE_PRIORITY)]
        dele = ["ip", "rule", "del", "fwmark", stamp, "lookup", "main",
                "priority", str(mod.DPI_RULE_PRIORITY)]
        self.assertIn(add, calls)
        self.assertIn(dele, calls)
        # Stale rules from an earlier run must not stack up.
        self.assertLess(calls.index(dele), calls.index(add))
        # mihomo's own policy rules start at 9000.
        self.assertLess(mod.DPI_RULE_PRIORITY, 9000)


class SetupRestartTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_restarts_only_what_was_up(self):
        from unittest import mock
        calls = []

        def fake(action, *args, **kwargs):
            calls.append(action)
            return subprocess.CompletedProcess(action, 0, "", "")

        with mock.patch.object(self.mod, "systemctl", fake), \
             mock.patch.object(self.mod, "warp_systemctl", fake), \
             mock.patch.object(self.mod, "warp_unit_state", lambda: ("active", "")):
            self.mod.restart_services(True)
        self.assertEqual(calls, ["restart", "restart"])

        calls.clear()
        with mock.patch.object(self.mod, "systemctl", fake), \
             mock.patch.object(self.mod, "warp_systemctl", fake), \
             mock.patch.object(self.mod, "warp_unit_state", lambda: ("inactive", "")):
            self.mod.restart_services(False)
        self.assertEqual(calls, [])


class WarpConfigRefreshTest(unittest.TestCase):
    """An update must not leave the old template's config behind."""

    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        home = pathlib.Path(self.tmp.name)
        (home / ".config" / "kich-dpi").mkdir(parents=True)
        (home / ".local" / "state" / "kich-dpi").mkdir(parents=True)
        self.home = home
        self.config = home / ".config" / "kich-dpi" / "warp.yaml"
        self.account = home / ".local" / "state" / "kich-dpi" / "account.json"
        self.user = SimpleNamespace(pw_name="kich", pw_dir=str(home))

    def test_does_nothing_when_warp_is_not_in_use(self):
        from unittest import mock
        calls = []
        with mock.patch.object(self.mod.subprocess, "run",
                               side_effect=lambda *a, **k: calls.append(a)):
            self.assertEqual(self.mod.refresh_warp_config(self.user), "")
        self.assertEqual(calls, [])

    def test_renders_as_the_owner_of_home(self):
        from unittest import mock
        self.config.write_text("mixed-port: 0\n", encoding="utf-8")
        self.account.write_text("{}", encoding="utf-8")
        argv = []

        def fake(args, **kwargs):
            argv.extend(args)
            return subprocess.CompletedProcess(args, 0, "{}", "")

        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake):
            self.assertEqual(self.mod.refresh_warp_config(self.user), "")
        self.assertEqual(argv[:3], ["runuser", "-u", "kich"])
        self.assertIn("HOME=%s" % self.home, argv)
        self.assertEqual(argv[-1], "warp-config")
        # The freshly installed copy, not the repo checkout.
        self.assertEqual(argv[-2], str(self.mod.APP_DIR / "bin" / "kich-dpi"))

    def test_reports_a_failed_render_without_failing_the_update(self):
        from unittest import mock
        self.config.write_text("mixed-port: 0\n", encoding="utf-8")
        self.account.write_text("{}", encoding="utf-8")
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=subprocess.CompletedProcess(
                                   ["runuser"], 1, "", "нет списков правил")):
            note = self.mod.refresh_warp_config(self.user)
        self.assertIn("нет списков правил", note) 


class ProbeSanityTest(unittest.TestCase):
    """Strategy generation must measure the DPI path, not the WARP tunnel."""

    def setUp(self):
        self.mod = load()

    def test_default_device_parses_the_main_route(self):
        self.assertEqual(self.mod.default_device(
            "default via 192.168.0.1 dev enp8s0 proto dhcp src 192.168.0.113"),
            "enp8s0")
        self.assertEqual(self.mod.default_device(""), "")

    def test_direct_probe_binds_the_physical_interface(self):
        from unittest import mock
        seen = []

        def fake_probe(url, timeout, interface=""):
            seen.append(interface)
            return True, 204, 10, ""

        with mock.patch.object(self.mod, "direct_device", return_value="enp8s0"), \
             mock.patch.object(self.mod, "http_probe", side_effect=fake_probe), \
             mock.patch.object(self.mod.time, "sleep"):
            result = self.mod.probe(direct=True)
        self.assertTrue(result["direct"])
        self.assertEqual(set(seen), {"enp8s0"})

    def test_sanity_fails_when_a_control_host_does_not_answer(self):
        from unittest import mock

        def fake_probe(url, timeout, interface=""):
            ok = any(host in url for host in
                     ("ya.ru", "aur.archlinux.org", "gosuslugi.ru",
                      "proxyapi.ru", "opencode.ai"))
            return ok, (200 if ok else 0), 15, "" if ok else "timeout"

        with mock.patch.object(self.mod, "direct_device", return_value="enp8s0"), \
             mock.patch.object(self.mod, "http_probe", side_effect=fake_probe):
            result = self.mod.sanity()
        self.assertFalse(result["ok"])
        self.assertEqual([row["label"] for row in result["results"] if not row["ok"]],
                         ["example"])

    def test_sanity_guards_the_aur(self):
        """AUR aborts with `unrecognized name` on tcp_md5 fooling, so a
        strategy may only be kept if AUR still answers directly."""
        urls = [url for _key, url in self.mod.SANITY_TARGETS]
        self.assertIn("https://aur.archlinux.org/", urls)

    def test_sanity_guards_gosuslugi(self):
        """The usual fake+split variants cut government sites off."""
        urls = [url for _key, url in self.mod.SANITY_TARGETS]
        self.assertIn("https://www.gosuslugi.ru/", urls)

    def test_sanity_guards_proxyapi(self):
        """Losing the provider API must not count as a working strategy."""
        urls = [url for _key, url in self.mod.SANITY_TARGETS]
        self.assertIn("https://api.proxyapi.ru/", urls)
        self.assertIn("https://console.proxyapi.ru/", urls)

    def test_sanity_guards_opencode(self):
        urls = [url for _key, url in self.mod.SANITY_TARGETS]
        self.assertIn("https://opencode.ai/inference/openai/v1/models", urls)


class PriorityHealthTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_critical_services_outrank_google(self):
        def health(discord, youtube, google, api, opencode, ms=100):
            result = {"ms": ms, "results": [
                {"key": "discord", "ok": discord},
                {"key": "youtube", "ok": youtube},
                {"key": "google", "ok": google},
            ]}
            check = {"ok": True, "results": [
                {"label": "api-proxyapi", "ok": api},
                {"label": "opencode", "ok": opencode},
            ]}
            return self.mod.priority_health(result, check)

        critical = health(True, True, False, True, True)
        cosmetic = health(False, False, True, False, False)
        self.assertGreater(critical, cosmetic)
        self.assertEqual(critical[0], 6 + 6 + 5 + 5)
        self.assertEqual(cosmetic[0], 1)

    def test_sanity_retries_a_single_failed_probe(self):
        from unittest import mock
        calls = []

        def fake_probe(url, timeout, interface=""):
            calls.append(url)
            return (True, 200, 10, "") if len(calls) > 1 else (False, 0, 15, "timeout")

        with mock.patch.object(self.mod, "direct_device", return_value=""), \
             mock.patch.object(self.mod, "http_probe", side_effect=fake_probe), \
             mock.patch.object(self.mod.time, "sleep"):
            result = self.mod.sanity()
        self.assertTrue(result["ok"])
        # One retry for the single failed target, no retries for the rest.
        self.assertEqual(len(calls), len(self.mod.SANITY_TARGETS) + 1)


class AccountMigrationTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = pathlib.Path(self.tmp.name)
        self.old_dir = self.home / ".local" / "share" / "kich-dpi"
        self.old = self.old_dir / "account.json"
        self.new = self.home / ".local" / "state" / "kich-dpi" / "account.json"

    def test_moves_the_old_share_account_into_state(self):
        self.old_dir.mkdir(parents=True)
        self.old.write_text('{"id": "old"}', encoding="utf-8")
        self.mod.migrate_account(self.home)
        self.assertFalse(self.old_dir.exists())
        self.assertEqual(self.new.read_text(encoding="utf-8"), '{"id": "old"}')
        self.assertEqual(self.new.stat().st_mode & 0o777, 0o600)

    def test_does_not_overwrite_an_already_migrated_account(self):
        self.old_dir.mkdir(parents=True)
        self.old.write_text('{"id": "old"}', encoding="utf-8")
        self.new.parent.mkdir(parents=True)
        self.new.write_text('{"id": "new"}', encoding="utf-8")
        self.mod.migrate_account(self.home)
        self.assertEqual(self.new.read_text(encoding="utf-8"), '{"id": "new"}')

    def test_main_migrates_before_dispatch(self):
        from unittest import mock
        self.old_dir.mkdir(parents=True)
        account = {"private_key": "k", "endpoint_pub_key": "p",
                   "id": "i", "access_token": "t"}
        self.old.write_text(json.dumps(account), encoding="utf-8")
        self.mod.HOME = self.home
        self.mod.WARP_ACCOUNT = self.new
        buf = io.StringIO()
        with mock.patch.object(self.mod.sys, "stdout", buf):
            self.mod.main(["kich-dpi", "no-such-command"])
        self.assertFalse(json.loads(buf.getvalue())["ok"])
        self.assertEqual(json.loads(self.new.read_text(encoding="utf-8"))["id"], "i")


class StateTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.tmp.name)
        self.mod.CONFIG_DIR = base / "config"
        self.mod.STATE_DIR = base / "state"
        self.mod.ACTIVE_FILE = self.mod.CONFIG_DIR / "active.json"
        self.mod.STATE_FILE = self.mod.CONFIG_DIR / "state.json"
        self.mod.STRATEGIES_FILE = self.mod.CONFIG_DIR / "strategies.json"
        self.mod.CHECK_FILE = self.mod.STATE_DIR / "check.json"
        self.mod.PROGRESS_FILE = self.mod.STATE_DIR / "progress.json"
        self.mod.WARP_ACCOUNT = base / "account.json"
        self.mod.WARP_CONFIG = self.mod.CONFIG_DIR / "warp.yaml"
        self.mod.WARP_CHECK_FILE = self.mod.STATE_DIR / "warp-check.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_status_shape_without_engine(self):
        from unittest import mock
        self.mod.engine_info = lambda: ("", False)
        self.mod.unit_state = lambda *a, **k: ("inactive", "not-found")
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=subprocess.CompletedProcess(["systemctl"], 1, "", "")):
            data = self.mod.status_data()
        for key in ("ok", "installed", "running", "generating", "strategies", "check"):
            self.assertIn(key, data)
        self.assertFalse(data["installed"])
        self.assertFalse(data["running"])

    def test_merge_strategies_dedupes_and_sorts(self):
        rows = [
            {"id": "a", "name": "A", "passed": 1, "total": 3, "ms": 500},
            {"id": "b", "name": "B", "passed": 3, "total": 3, "ms": 900},
            {"id": "c", "name": "C", "passed": 2, "total": 3, "ms": 300},
        ]
        self.mod.merge_strategies(rows)
        saved = json.loads(self.mod.STRATEGIES_FILE.read_text())
        self.assertEqual([r["id"] for r in saved], ["b", "c", "a"])

        self.mod.merge_strategies([
            {"id": "a", "name": "A2", "passed": 3, "total": 3, "ms": 100},
        ])
        saved = json.loads(self.mod.STRATEGIES_FILE.read_text())
        self.assertEqual(saved[0]["id"], "a")
        self.assertEqual(saved[0]["name"], "A2")
        self.assertEqual(len(saved), 3)

        # A candidate that fails the new sanity check must lose its old score.
        self.mod.merge_strategies([
            {"id": "a", "name": "A2", "passed": 0, "total": 3, "ms": 10 ** 9},
        ])
        saved = json.loads(self.mod.STRATEGIES_FILE.read_text())
        self.assertEqual(saved[-1]["id"], "a")
        self.assertEqual(saved[-1]["passed"], 0)

    def test_merge_uses_weighted_health_over_plain_passes(self):
        self.mod.merge_strategies([
            {"id": "low", "name": "Low", "passed": 3, "ms": 100, "health": 1},
            {"id": "high", "name": "High", "passed": 2, "ms": 500, "health": 17},
        ])
        saved = json.loads(self.mod.STRATEGIES_FILE.read_text())
        self.assertEqual(saved[0]["id"], "high")

    def test_apply_spec_writes_active(self):
        self.mod.systemctl = lambda *a, **k: subprocess.CompletedProcess(
            ["systemctl"], 0, "", "")
        row = self.mod.candidates()[0]
        self.mod.apply_spec(row, start=True)
        active = json.loads(self.mod.ACTIVE_FILE.read_text())
        self.assertEqual(active["spec"], row)
        self.assertEqual(active["name"], row["name"])
        self.assertEqual(active["id"], self.mod.strategy_id(row))

    def test_wanted_state_is_persistent(self):
        self.assertTrue(self.mod.wanted_flags()["dpi"])
        self.mod.set_wanted("dpi", False)
        self.assertFalse(self.mod.wanted_flags()["dpi"])
        self.assertTrue(self.mod.wanted_flags()["warp"])
        self.mod.set_wanted("warp", False)
        self.assertFalse(self.mod.wanted_flags()["warp"])

    def test_apply_spec_marks_bypass_as_wanted(self):
        self.mod.systemctl = lambda *a, **k: subprocess.CompletedProcess(
            ["systemctl"], 0, "", "")
        self.mod.set_wanted("dpi", False)
        self.mod.apply_spec(self.mod.candidates()[0], start=True)
        self.assertTrue(self.mod.wanted_flags()["dpi"])

    def test_progress_older_than_half_hour_is_not_running(self):
        self.mod.write_json(self.mod.PROGRESS_FILE, {
            "running": True, "started": 1, "done": 4, "total": 18,
        })
        data = self.mod.progress_data()
        self.assertFalse(data["running"])
        self.assertIn("error", data)


class ReleaseInfoTest(unittest.TestCase):
    """A 403 from the GitHub API must fall back to the redirect, not block updates."""

    def setUp(self):
        self.mod = load()

    def test_api_rate_limit_uses_redirect(self):
        import urllib.error
        from unittest import mock

        errors = []

        def fake_urlopen(req, timeout=0):
            if "api.github.com" in req.full_url:
                err = urllib.error.HTTPError(
                    req.full_url, 403, "rate limit exceeded", {}, None)
                errors.append(err)
                raise err
            return _FakeResponse("https://github.com/bol-van/zapret2/releases/tag/v1.0.7")

        class _FakeResponse:
            def __init__(self, url):
                self._url = url

            def geturl(self):
                return self._url

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=fake_urlopen):
            tag, url, digest = self.mod.release_info()
        self.assertEqual(tag, "v1.0.7")
        self.assertEqual(url, "https://github.com/bol-van/zapret2/releases/download/v1.0.7/zapret2-v1.0.7.tar.gz")
        self.assertEqual(digest, "")
        for err in errors:
            err.close()

    def test_non_403_error_propagates(self):
        import urllib.error
        from unittest import mock

        errors = []

        def fake_urlopen(req, timeout=0):
            err = urllib.error.HTTPError(req.full_url, 500, "server error", {}, None)
            errors.append(err)
            raise err

        with mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(urllib.error.HTTPError):
                self.mod.release_info()
        for err in errors:
            err.close()


class BatchedStatusTest(unittest.TestCase):
    """A status poll must coalesce systemctl into a single spawn."""

    def setUp(self):
        self.mod = load()

    def test_parses_multi_unit_show_output(self):
        from unittest import mock
        units = [self.mod.UNIT, self.mod.WARP_UNIT, self.mod.CONFLICT_UNIT]
        out = ("%s\nactive\nenabled\n\n"
               "%s\ninactive\nnot-found\n\n"
               "%s\nactive\n\n" % (units[0], units[1], units[2]))
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, out, "")) as run:
            states = self.mod.batched_unit_states(units)
        self.assertEqual(states[units[0]], ("active", "enabled"))
        self.assertEqual(states[units[1]], ("inactive", "not-found"))
        self.assertEqual(states[units[2]], ("active", "not-found"))  # 2-line block
        self.assertEqual(run.call_count, 1)

    def test_status_data_uses_single_subprocess(self):
        from unittest import mock
        with mock.patch.object(self.mod.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            data = self.mod.status_data()
        self.assertEqual(run.call_count, 1)
        self.assertTrue(data["ok"])


class WarpEnablementTest(unittest.TestCase):
    """Toggles persist in a state file and never call manage-unit-files."""

    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mod.STATE_FILE = pathlib.Path(self.tmp.name) / "state.json"

    def test_warp_off_stops_and_remembers(self):
        from unittest import mock
        calls = []

        def fake(*args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with mock.patch.object(self.mod, "warp_systemctl", fake), \
             mock.patch.object(self.mod, "warp_status", lambda: {}), \
             mock.patch.object(self.mod, "out", lambda payload: None):
            self.mod.cmd_warp_off()
        self.assertEqual(calls, [("stop",)])
        self.assertFalse(self.mod.wanted_flags()["warp"])

    def test_warp_on_restarts_and_remembers(self):
        from unittest import mock
        calls = []

        def fake(*args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with mock.patch.object(self.mod, "warp_available", lambda: True), \
             mock.patch.object(self.mod, "warp_account", lambda: {"id": "test"}), \
             mock.patch.object(self.mod, "warp_build", lambda account: None), \
             mock.patch.object(self.mod, "warp_systemctl", fake), \
             mock.patch.object(self.mod, "warp_status", lambda: {}), \
             mock.patch.object(self.mod, "out", lambda payload: None):
            self.mod.cmd_warp_on()
        self.assertEqual(calls, [("restart",)])
        self.assertTrue(self.mod.wanted_flags()["warp"])


class DpiToggleTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mod.STATE_FILE = pathlib.Path(self.tmp.name) / "state.json"

    def test_on_uses_start_and_off_uses_stop(self):
        from unittest import mock
        calls = []

        def fake(*args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with mock.patch.object(self.mod, "installed", lambda: True), \
             mock.patch.object(self.mod, "systemctl", fake), \
             mock.patch.object(self.mod, "status_data", lambda: {}), \
             mock.patch.object(self.mod, "out", lambda payload: None):
            self.mod.cmd_on()
            self.assertTrue(self.mod.wanted_flags()["dpi"])
            self.mod.cmd_off()
            self.assertFalse(self.mod.wanted_flags()["dpi"])
        self.assertEqual(calls, [("start",), ("stop",)])


class DoctorPolkitTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_private_directory_is_not_reported_as_missing_rule(self):
        from unittest import mock
        with mock.patch.object(self.mod.os, "access", lambda path, mode: False), \
             mock.patch.object(self.mod, "POLKIT_PATH",
                               pathlib.Path("/no/such/49-kich-dpi.rules")):
            ok, detail = self.mod.polkit_rule_state()
        self.assertTrue(ok)
        self.assertIn("root", detail)

    def test_missing_rule_is_reported_when_directory_is_readable(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            rule = pathlib.Path(tmp) / "49-kich-dpi.rules"
            with mock.patch.object(self.mod.os, "access", lambda path, mode: True), \
                 mock.patch.object(self.mod, "POLKIT_PATH", rule):
                ok, detail = self.mod.polkit_rule_state()
            self.assertFalse(ok)
            self.assertEqual(detail, str(rule))

            rule.write_text("// installed\n", encoding="utf-8")
            with mock.patch.object(self.mod.os, "access", lambda path, mode: True), \
                 mock.patch.object(self.mod, "POLKIT_PATH", rule):
                ok, detail = self.mod.polkit_rule_state()
            self.assertTrue(ok)
            self.assertEqual(detail, str(rule))


class PolkitRuleTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_rule_allows_enable_and_disable(self):
        text = self.mod.POLKIT_TEMPLATE.format(
            user="u", unit=self.mod.UNIT, warp_unit=self.mod.WARP_UNIT)
        self.assertIn("org.freedesktop.systemd1.manage-units", text)
        self.assertNotIn('action.id === "org.freedesktop.systemd1.manage-unit-files"', text)
        self.assertEqual(text.count("action.id"), 1)
        self.assertIn('unit === "%s"' % self.mod.UNIT, text)
        self.assertIn('unit === "%s"' % self.mod.WARP_UNIT, text)


class SetupEnablementTest(unittest.TestCase):
    """Units stay enabled; the user's choice lives in state.json."""

    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _install(self, enabled):
        from unittest import mock
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            if argv[:2] == ["systemctl", "is-enabled"]:
                out = "enabled\n" if enabled.get(argv[2], True) else "disabled\n"
                return subprocess.CompletedProcess(argv, 0, out, "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        user = SimpleNamespace(pw_name="u", pw_dir=self.tmp.name,
                               pw_uid=1000, pw_gid=1000)
        with mock.patch.object(self.mod.grp, "getgrgid",
                               lambda gid: SimpleNamespace(gr_name="users")), \
             mock.patch.object(self.mod, "write_text", lambda *a, **k: None), \
             mock.patch.object(self.mod, "WARP_RUN",
                               pathlib.Path(self.tmp.name) / "warp-run"), \
             mock.patch.object(self.mod.subprocess, "run", fake_run), \
             mock.patch.object(self.mod.shutil, "rmtree", lambda *a, **k: None), \
             mock.patch.object(self.mod, "migrate_account", lambda *a, **k: None):
            self.mod.install_system(user)
        return calls

    def test_setup_always_enables_both_units(self):
        calls = self._install({self.mod.UNIT: False, self.mod.WARP_UNIT: False})
        self.assertIn(["systemctl", "enable", self.mod.UNIT], calls)
        self.assertIn(["systemctl", "enable", self.mod.WARP_UNIT], calls)

    def test_setup_migrates_old_choice_into_state(self):
        self._install({self.mod.UNIT: False, self.mod.WARP_UNIT: True})
        state = json.loads((pathlib.Path(self.tmp.name) / ".config" / "kich-dpi"
                            / "state.json").read_text())
        self.assertFalse(state["dpi"])
        self.assertTrue(state["warp"])


class DoctorServiceTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def _doctor(self, running, failed, active):
        from unittest import mock
        warp = {"available": True, "registered": True, "account": "x",
                "running": running, "failed": failed, "active": active}
        state = {"failed": failed, "active": active, "running": running,
                 "active_name": "strategy", "conflict": False, "warp": warp}
        captured = {}

        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, "v1.0.7\n", "")

        with mock.patch.object(self.mod, "status_data", lambda: state), \
             mock.patch.object(self.mod.subprocess, "run", fake_run), \
             mock.patch.object(self.mod, "out", captured.update):
            self.mod.cmd_doctor()
        return {row["name"]: row for row in captured["checks"]}

    def test_stopped_services_are_not_healthy(self):
        checks = self._doctor(False, False, "inactive")
        self.assertFalse(checks["служба"]["ok"])
        self.assertIn("остановлена", checks["служба"]["detail"])
        self.assertFalse(checks["служба WARP"]["ok"])
        self.assertEqual(checks["служба WARP"]["detail"], "остановлена (inactive)")

    def test_failed_service_is_named_as_failed(self):
        checks = self._doctor(False, True, "failed")
        self.assertFalse(checks["служба"]["ok"])
        self.assertIn("failed", checks["служба"]["detail"])

    def test_running_services_are_healthy(self):
        checks = self._doctor(True, False, "active")
        self.assertTrue(checks["служба"]["ok"])
        self.assertTrue(checks["служба WARP"]["ok"])


if __name__ == "__main__":
    unittest.main()
