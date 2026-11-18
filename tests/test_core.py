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

ROOT = pathlib.Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "kich-dpi"


def load():
    loader = importlib.machinery.SourceFileLoader("kich_dpi", str(BIN))
    spec = importlib.util.spec_from_loader("kich_dpi", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class CandidatesTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_twelve_unique_candidates(self):
        rows = self.mod.candidates()
        self.assertEqual(len(rows), 12)
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
        self.mod.BUNDLED_RULES = ROOT / "data" / "rules"
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
        self.assertEqual(proxy["network"], "h2")
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
        self.assertIn("RULE-SET,ru-ip,DIRECT,no-resolve", data["rules"])
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
        data = yaml.safe_load(self.mod.warp_config_text(self.ACCOUNT))
        self.assertEqual(data["find-process-mode"], "strict")
        self.assertEqual(data["rules"][0], "PROCESS-NAME,telegram,DIRECT")
        self.assertIn("RULE-SET,direct-domains,DIRECT", data["rules"])
        self.assertEqual(data["rule-providers"]["direct-domains"]["path"],
                         str(self.mod.WARP_USER_DOMAINS))

    def test_comma_in_process_name_is_rejected(self):
        self.mod.WARP_USER_PROCESSES.write_text("bad,name\n", encoding="utf-8")
        with self.assertRaises(self.mod.Fail):
            self.mod.warp_config_text(self.ACCOUNT)

    def test_rule_lists_ship_with_the_plugin(self):
        domains = self.mod.list_lines(ROOT / "data" / "rules" / "ru-domain.txt")
        ips = self.mod.list_lines(ROOT / "data" / "rules" / "ru-ip.txt")
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

    def test_conflict_detection_reports_active_usque(self):
        from unittest import mock
        mod = self.mod
        with mock.patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess(
                ["systemctl"], 0, "active\n", "")):
            self.assertTrue(mod.warp_conflict())
        with mock.patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess(
                ["systemctl"], 3, "inactive\n", "")):
            self.assertEqual(mod.warp_conflict(), "")

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
        (home / ".local" / "share" / "kich-dpi").mkdir(parents=True)
        self.home = home
        self.config = home / ".config" / "kich-dpi" / "warp.yaml"
        self.account = home / ".local" / "share" / "kich-dpi" / "account.json"
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


class StateTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.tmp.name)
        self.mod.CONFIG_DIR = base / "config"
        self.mod.STATE_DIR = base / "state"
        self.mod.ACTIVE_FILE = self.mod.CONFIG_DIR / "active.json"
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
        self.mod.installed_version = lambda: ""
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

    def test_apply_spec_writes_active(self):
        self.mod.systemctl = lambda *a, **k: subprocess.CompletedProcess(
            ["systemctl"], 0, "", "")
        row = self.mod.candidates()[0]
        self.mod.apply_spec(row, start=True)
        active = json.loads(self.mod.ACTIVE_FILE.read_text())
        self.assertEqual(active["spec"], row)
        self.assertEqual(active["name"], row["name"])
        self.assertEqual(active["id"], self.mod.strategy_id(row))

    def test_progress_older_than_half_hour_is_not_running(self):
        self.mod.write_json(self.mod.PROGRESS_FILE, {
            "running": True, "started": 1, "done": 4, "total": 12,
        })
        data = self.mod.progress_data()
        self.assertFalse(data["running"])
        self.assertIn("error", data)


class ScoreTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_more_passes_beat_faster_fewer(self):
        fast_one = {"passed": 1, "ms": 100}
        slow_three = {"passed": 3, "ms": 5000}
        self.assertGreater(self.mod.score(slow_three), self.mod.score(fast_one))

    def test_lower_latency_wins_on_tie(self):
        slow = {"passed": 2, "ms": 2000}
        fast = {"passed": 2, "ms": 400}
        self.assertGreater(self.mod.score(fast), self.mod.score(slow))


if __name__ == "__main__":
    unittest.main()
