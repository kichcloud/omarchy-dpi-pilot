"""Hermetic tests for the kich-dpi Python package.

Every test imports the package from ``src/`` instead of loading the root
launcher. All paths the code can touch (HOME, /opt, /etc, systemd units) are
patched to a temporary tree, so a test run never changes the machine.
"""
import gzip
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
BIN = ROOT / "kich-dpi"
sys.path.insert(0, str(ROOT / "src"))

from kich_dpi import constants as C  # noqa: E402
from kich_dpi import (cli, core, engine, ownership, repair, status,  # noqa: E402
                      strategies, warp, warp_network)


def completed(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


class SandboxTest(unittest.TestCase):
    """Patch every path used by the package into one temporary tree."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = pathlib.Path(tmp.name)
        self.home = self.base / "home"
        self.config = self.home / ".config" / C.ENGINE_SLUG
        self.state = self.home / ".local" / "state" / C.ENGINE_SLUG
        self.config.mkdir(parents=True)
        self.state.mkdir(parents=True)
        paths = {
            "HOME": self.home,
            "CONFIG_DIR": self.config,
            "STATE_DIR": self.state,
            "ENGINE_ROOT": self.base / "opt",
            "ENGINE_DIR": self.base / "opt" / "engine",
            "APP_DIR": self.base / "opt" / "app",
            "UNIT_PATH": self.base / "etc" / C.UNIT,
            "WARP_UNIT_PATH": self.base / "etc" / C.WARP_UNIT,
            "POLKIT_PATH": self.base / "etc" / "49-kich-dpi.rules",
            "SYSCTL_PATH": self.base / "etc" / "90-kich-dpi.conf",
            "MIHOMO": self.base / "opt" / "mihomo",
            "WARP_RUN": self.base / "opt" / "app" / "bin" / "kich-dpi-warp-run",
            "BUNDLED_RULES": ROOT,
            "WARP_RULES": self.state / "rules",
            "DPI_DOMAINS_FILE": self.config / "dpi-domains.txt",
            "ACTIVE_FILE": self.config / "active.json",
            "STATE_FILE": self.config / "state.json",
            "STRATEGIES_FILE": self.config / "strategies.json",
            "WARP_CONFIG": self.config / "warp.yaml",
            "WARP_USER_DOMAINS": self.config / "direct-domains.txt",
            "WARP_USER_PROCESSES": self.config / "direct-processes.txt",
            "CHECK_FILE": self.state / "check.json",
            "PROGRESS_FILE": self.state / "progress.json",
            "WARP_CHECK_FILE": self.state / "warp-check.json",
            "WARP_ACCOUNT": self.state / "account.json",
            "WARP_WG_ACCOUNT": self.state / "wg-account.json",
            "WARP_BUILD_STAMP": self.state / "warp-build.json",
            "WARP_PROBE_CACHE": self.state / "warp-probes.json",
        }
        for name, value in paths.items():
            patcher = mock.patch.object(C, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.paths = paths


class PackageLayoutTest(SandboxTest):
    """The monolith is gone: the launcher only dispatches into the package."""

    def test_all_modules_are_importable(self):
        for module in (cli, engine, repair, status, strategies, warp):
            self.assertIs(module.core, core)
            self.assertIs(module.C, C)
        self.assertIs(core.C, C)

    def test_root_launcher_only_imports_and_dispatches(self):
        text = BIN.read_text(encoding="utf-8")
        self.assertIn("sys.path.insert(0, os.path.join(root, \"src\"))", text)
        self.assertIn("from kich_dpi.cli import main", text)
        self.assertIn('if __name__ == "__main__":', text)
        self.assertIn("sys.exit(main(sys.argv))", text)


class CandidatesTest(SandboxTest):
    def test_default_strategy_avoids_disorder(self):
        self.assertEqual(strategies.default_spec()["action"], "fakedsplit")
        self.assertNotEqual(strategies.default_spec()["action"], "multidisorder")

    def test_eighteen_unique_candidates(self):
        rows = strategies.candidates()
        self.assertEqual(len(rows), 18)
        names = [row["name"] for row in rows]
        self.assertEqual(len(set(names)), len(names))
        ids = [strategies.strategy_id(row) for row in rows]
        self.assertEqual(len(set(ids)), len(ids))

    def test_every_candidate_has_valid_primitives(self):
        for row in strategies.candidates():
            self.assertIn(row["action"], {
                "multisplit", "multidisorder", "fakedsplit", "fakeddisorder",
            })
            self.assertTrue(row["pos"])
            self.assertIn(row["fool"], strategies.FOOLING)
            if row["fake"] is None:
                self.assertIn(row["action"], {"fakedsplit", "fakeddisorder"})
            else:
                self.assertGreaterEqual(row["repeats"], 1)

    def test_config_limits_desync_to_target_hosts(self):
        C.DPI_DOMAINS_FILE.write_text("discord.com\nyoutube.com\n", encoding="utf-8")
        text = strategies.render_config(strategies.candidates()[0])
        self.assertEqual(text.count("--hostlist-domains=discord.com,youtube.com"), 3)
        self.assertIn("--filter-l7=tls\n--hostlist-domains=discord.com,youtube.com", text)

    def test_empty_domain_list_keeps_global_bypass(self):
        C.DPI_DOMAINS_FILE.write_text("# no selective hosts\n", encoding="utf-8")
        text = strategies.render_config(strategies.candidates()[0])
        self.assertNotIn("--hostlist-domains=discord.com", text)
        self.assertIn("--hostlist-domains=discord.media", text)

    def test_config_has_six_profiles(self):
        for row in strategies.candidates():
            text = strategies.render_config(row)
            self.assertIn("--qnum=%d" % C.QUEUE, text)
            self.assertIn("--fwmark=%s" % C.FWMARK, text)
            self.assertIn("--filter-tcp=80", text)
            self.assertIn("--filter-tcp=443", text)
            self.assertIn("--filter-udp=443", text)
            self.assertEqual(text.count("--new"), 5)
            self.assertIn("zapret-antidpi.lua", text)
            self.assertNotIn("--dry-run", text)

    def test_config_covers_discord_voice(self):
        text = strategies.render_config(strategies.candidates()[0])
        self.assertIn("--filter-udp=19294-19344,50000-50100", text)
        self.assertIn("--filter-l7=discord\n--payload=discord_ip_discovery", text)
        self.assertIn("--filter-l7=stun\n--payload=stun", text)
        self.assertEqual(text.count("--lua-desync=fake:blob=quic_google:repeats=6"), 3)
        self.assertIn("--filter-tcp=2053,2083,2087,2096,8443", text)
        self.assertIn("--hostlist-domains=discord.media\n--payload=tls_client_hello", text)
        self.assertIn("--lua-desync=multisplit:seqovl=681:pos=1:seqovl_pattern=tls_google", text)

    def test_fake_and_split_only_variants(self):
        rows = {row["action"]: row for row in strategies.candidates()}

        def tls(row):
            return strategies.render_config(row).split("--filter-tcp=443", 1)[1].split("--new", 1)[0]

        self.assertIn("fake:blob=", tls(rows["multisplit"]))
        self.assertIn("pattern=tls_google", tls(rows["fakedsplit"]))
        self.assertNotIn("fake:blob=", tls(rows["fakedsplit"]))

    def test_dry_run_against_real_engine(self):
        directory = os.environ.get("KICH_DPI_ENGINE_DIR")
        if not directory:
            self.skipTest("KICH_DPI_ENGINE_DIR is not set")
        with mock.patch.object(C, "ENGINE_DIR", pathlib.Path(directory)):
            binary = core.engine_bin()
            if not binary.exists():
                self.skipTest("no nfqws2 in %s" % directory)
            conf = self.base / "test.conf"
            for row in strategies.candidates():
                conf.write_text(strategies.render_config(row, dry_run=True), encoding="utf-8")
                cp = subprocess.run([str(binary), "@" + str(conf)],
                                    capture_output=True, text=True)
                self.assertEqual(cp.returncode, 0,
                                 "%s failed: %s" % (row["name"], cp.stdout + cp.stderr))


class GenerationRestoreTest(SandboxTest):
    def test_best_baseline_keeps_the_desired_flag_and_service_state(self):
        fallback = strategies.default_spec()
        best = (strategies.candidates()[0], {"passed": 1, "total": 3, "ms": 90},
                (1, -90))
        progress = {}
        with mock.patch.object(core, "set_wanted") as set_wanted, \
             mock.patch.object(core, "systemctl") as systemctl, \
             mock.patch.object(strategies, "apply_spec") as apply_spec:
            kept = strategies.restore_after_generation(
                best, {}, (2, -80), None, fallback, False, True, progress)
        self.assertTrue(kept)
        set_wanted.assert_not_called()
        systemctl.assert_not_called()
        apply_spec.assert_called_once_with(fallback, start=False)


class EngineExtractTest(SandboxTest):
    def _archive(self, path, with_binary=True):
        with tarfile.open(path, "w:gz") as tf:
            def add(name, data=b"x"):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

            root = "zapret2-v9.9.9/"
            if with_binary:
                add(root + "binaries/linux-x86_64/nfqws2", b"#!/bin/sh\n")
            add(root + "lua/zapret-lib.lua", b"-- lib\n")
            add(root + "lua/zapret-antidpi.lua", b"-- anti\n")
            add(root + "files/fake/zero.bin", b"\0")
            add(root + "docs/readme.md", b"unneeded")
            add("../escape", b"bad")

    def test_extracts_only_needed_files_and_links_current(self):
        archive = self.base / "zapret2-v9.9.9.tar.gz"
        self._archive(archive)
        with mock.patch.object(core, "machine_arch", lambda: "x86_64"):
            target = engine.extract_engine(archive, "v9.9.9")
        self.assertTrue((target / "nfqws2").exists())
        self.assertTrue((target / "lua" / "zapret-lib.lua").exists())
        self.assertTrue((target / "files" / "fake" / "zero.bin").exists())
        self.assertFalse((target / "docs").exists())
        self.assertFalse((self.base / "escape").exists())
        self.assertEqual(os.readlink(C.ENGINE_DIR / "current"), "v9.9.9")
        self.assertTrue(os.access(target / "nfqws2", os.X_OK))

    def test_failed_rename_restores_the_previous_engine(self):
        archive = self.base / "zapret2-v9.9.9.tar.gz"
        self._archive(archive)
        target, current = self._installed()
        real = pathlib.Path.rename

        def rename(self, dst):
            if self.name == ".v9.9.9.new":
                raise OSError("rename failed")
            return real(self, dst)

        with mock.patch.object(core, "machine_arch", lambda: "x86_64"), \
             mock.patch.object(pathlib.Path, "rename", rename):
            with self.assertRaises(OSError):
                engine.extract_engine(archive, "v9.9.9")
        self.assertEqual((target / "nfqws2").read_bytes(), b"old")
        self.assertEqual(os.readlink(current), "v9.9.9")

    def test_failed_symlink_swap_restores_the_previous_engine(self):
        archive = self.base / "zapret2-v9.9.9.tar.gz"
        self._archive(archive)
        target, current = self._installed()
        with mock.patch.object(core, "machine_arch", lambda: "x86_64"), \
             mock.patch.object(os, "replace", side_effect=OSError("swap failed")):
            with self.assertRaises(OSError):
                engine.extract_engine(archive, "v9.9.9")
        self.assertEqual((target / "nfqws2").read_bytes(), b"old")
        self.assertEqual(os.readlink(current), "v9.9.9")
        self.assertFalse((C.ENGINE_DIR / ".v9.9.9.old").exists())

    def _installed(self, tag="v9.9.9"):
        C.ENGINE_DIR.mkdir(parents=True, exist_ok=True)
        target = C.ENGINE_DIR / tag
        target.mkdir(parents=True)
        (target / "nfqws2").write_bytes(b"old")
        current = C.ENGINE_DIR / "current"
        current.symlink_to(tag)
        return target, current

    def test_rejects_archive_without_binary(self):
        archive = self.base / "bad.tar.gz"
        self._archive(archive, with_binary=False)
        with mock.patch.object(core, "machine_arch", lambda: "x86_64"):
            with self.assertRaises(core.Fail):
                engine.extract_engine(archive, "v1")

    def test_nft_skips_warp_endpoints(self):
        script = engine.NFT_SCRIPT.format(
            table=C.TABLE, mark=C.FWMARK, queue=C.QUEUE,
            warp_ips=", ".join(C.WARP_ENDPOINTS))
        for endpoint in C.WARP_ENDPOINTS:
            self.assertIn(endpoint, script)
        self.assertIn("ip daddr @warp_ep return", script)
        self.assertIn("ip saddr @warp_ep return", script)
        self.assertNotIn(C.WARP_MARK, script)
        self.assertIn("tcp dport { 2053, 2083, 2087, 2096, 8443 }", script)
        self.assertIn("udp dport { 19294-19344, 50000-50100 }", script)

    def test_fw_rule_keeps_stamped_packets_off_the_tunnel(self):
        calls = []

        def run(argv, **kwargs):
            calls.append([str(a) for a in argv])
            return completed(argv)

        with mock.patch.object(core, "run", side_effect=run):
            engine.fw_up()
            engine.fw_down()
        stamp = "%s/%s" % (C.FWMARK, C.FWMARK)
        add = ["ip", "rule", "add", "fwmark", stamp, "lookup", "main",
               "priority", str(C.DPI_RULE_PRIORITY)]
        dele = ["ip", "rule", "del", "fwmark", stamp, "lookup", "main",
                "priority", str(C.DPI_RULE_PRIORITY)]
        self.assertIn(add, calls)
        self.assertIn(dele, calls)
        self.assertLess(calls.index(dele), calls.index(add))
        self.assertEqual(C.DPI_RULE_PRIORITY, 8999)

    def test_pinned_constants_are_not_just_imported_values(self):
        # Read the source too: changing both the constant and this test would
        # otherwise keep the pin invisible.
        constants = (ROOT / "src/kich_dpi/constants.py").read_text(encoding="utf-8")
        self.assertIn("DPI_RULE_PRIORITY = 8999", constants)
        self.assertIn('WARP_ENDPOINT = "162.159.199.2"', constants)
        self.assertIn('VERSION = "0.8.0"', constants)
        manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], "0.8.0")
        self.assertEqual(C.VERSION, manifest["version"])


class MihomoInstallTest(SandboxTest):
    """install_mihomo must record its stamp and never crash after installing."""

    def _archive(self):
        path = self.base / "mihomo.gz"
        with gzip.open(path, "wb") as fh:
            fh.write(b"#!/bin/sh\nexit 0\n")
        return path

    def _run(self, output="Mihomo Meta v1.19.0 linux amd64\n"):
        calls = []

        def run(argv, **kwargs):
            calls.append([str(a) for a in argv])
            return completed(argv, 0, output, "")

        return calls, run

    def test_install_records_the_installed_version(self):
        C.ENGINE_ROOT.mkdir(parents=True, exist_ok=True)
        calls, run = self._run()
        with mock.patch.dict(os.environ,
                             {"KICH_DPI_MIHOMO_ARCHIVE": str(self._archive())}), \
             mock.patch.object(core, "machine_arch", lambda: "x86_64"), \
             mock.patch.object(core, "run", side_effect=run):
            version = engine.install_mihomo()
        self.assertEqual(version, "custom")
        stamp = json.loads((C.ENGINE_ROOT / "mihomo.json").read_text(encoding="utf-8"))
        self.assertEqual(stamp["version"], "custom")
        self.assertGreater(stamp["installed"], 0)
        self.assertTrue(C.MIHOMO.is_file())
        self.assertEqual(C.MIHOMO.stat().st_mode & 0o777, 0o755)

    def test_second_install_does_not_touch_disk_or_spawn(self):
        C.ENGINE_ROOT.mkdir(parents=True, exist_ok=True)
        _, run = self._run()
        with mock.patch.dict(os.environ,
                             {"KICH_DPI_MIHOMO_ARCHIVE": str(self._archive())}), \
             mock.patch.object(core, "machine_arch", lambda: "x86_64"), \
             mock.patch.object(core, "run", side_effect=run):
            engine.install_mihomo()
        before = {path.name: path.read_bytes() for path in C.ENGINE_ROOT.iterdir()
                  if path.is_file()}
        with mock.patch.object(core, "run",
                               side_effect=AssertionError("must not spawn")):
            again = engine.install_mihomo()
        after = {path.name: path.read_bytes() for path in C.ENGINE_ROOT.iterdir()
                 if path.is_file()}
        self.assertEqual(again, "custom")
        self.assertEqual(before, after)

    def test_missing_stamp_is_healed_from_the_binary(self):
        C.ENGINE_ROOT.mkdir(parents=True, exist_ok=True)
        C.MIHOMO.write_bytes(b"#!/bin/sh\n")
        C.MIHOMO.chmod(0o755)
        with mock.patch.object(
                core, "run",
                return_value=completed([], 0, "Mihomo Meta v1.18.8 linux\n", "")):
            version = engine.install_mihomo()
        self.assertEqual(version, "1.18.8")
        stamp = json.loads((C.ENGINE_ROOT / "mihomo.json").read_text(encoding="utf-8"))
        self.assertEqual(stamp["version"], "1.18.8")


class InstallTest(SandboxTest):
    def test_install_app_copies_package_rules_and_launcher(self):
        app = self.base / "app"
        with mock.patch.object(C, "APP_DIR", app):
            engine.install_app()
        lib = app / "lib" / "kich_dpi"
        self.assertTrue((lib / "cli.py").is_file())
        self.assertTrue((lib / "constants.py").is_file())
        self.assertFalse((lib / "__pycache__").exists())
        launcher = app / "bin" / "kich-dpi"
        self.assertTrue(launcher.is_file())
        self.assertEqual(launcher.stat().st_mode & 0o777, 0o755)
        self.assertIn("from kich_dpi.cli import main", launcher.read_text(encoding="utf-8"))
        self.assertTrue((app / "data" / "rules" / "ru-domain.txt").is_file())
        self.assertTrue((app / "data" / "rules" / "ru-ip.txt").is_file())

    def _install(self, enabled):
        calls = []

        def run(argv, **kwargs):
            argv = [str(a) for a in argv]
            calls.append(argv)
            out = ""
            if argv[:2] == ["systemctl", "show"]:
                out = "\n\n".join(
                    "%s\ninactive\n%s" % (
                        unit, "enabled" if enabled.get(unit, True) else "disabled")
                    for unit in (C.UNIT, C.WARP_UNIT)) + "\n"
            elif argv[:3] == ["systemctl", "is-enabled", C.UNIT]:
                out = "enabled\n" if enabled.get(C.UNIT, True) else "disabled\n"
            elif argv[:3] == ["systemctl", "is-enabled", C.WARP_UNIT]:
                out = "enabled\n" if enabled.get(C.WARP_UNIT, True) else "disabled\n"
            return completed(argv, 0, out, "")

        user = SimpleNamespace(pw_name="u", pw_dir=str(self.home),
                               pw_uid=1000, pw_gid=1000)
        with mock.patch.object(engine.grp, "getgrgid",
                               lambda gid: SimpleNamespace(gr_name="users")), \
             mock.patch.object(engine, "merge_config_into_state",
                               lambda home, uid, gid: self.state), \
             mock.patch.object(engine.shutil, "rmtree", lambda *a, **k: None), \
             mock.patch.object(warp, "migrate_account", lambda *a, **k: None), \
             mock.patch.object(core, "write_text", lambda *a, **k: None), \
             mock.patch.object(core, "run", side_effect=run):
            engine.install_system(user)
        return calls

    def test_setup_always_enables_both_units(self):
        calls = self._install({C.UNIT: False, C.WARP_UNIT: False})
        self.assertIn(["systemctl", "enable", C.UNIT], calls)
        self.assertIn(["systemctl", "enable", C.WARP_UNIT], calls)

    def test_second_setup_is_a_noop_when_nothing_changed(self):
        calls = []
        state = {"sysctl": ""}
        user = SimpleNamespace(pw_name="u", pw_dir=str(self.home),
                               pw_uid=1000, pw_gid=1000)

        def run(argv, **kwargs):
            argv = [str(a) for a in argv]
            calls.append(argv)
            if argv[:2] == ["systemctl", "show"]:
                out = "\n\n".join("%s\ninactive\nenabled" % unit
                                  for unit in (C.UNIT, C.WARP_UNIT)) + "\n"
                return completed(argv, 0, out, "")
            if argv[:2] == ["systemctl", "is-enabled"]:
                return completed(argv, 0, "enabled\n", "")
            if argv[:2] == ["sysctl", "-n"]:
                return completed(argv, 0, state["sysctl"], "")
            if argv[:3] == ["sysctl", "-q", "-w"]:
                state["sysctl"] = "1"
            return completed(argv)

        def write_text(path, text, mode=0o644):
            path = pathlib.Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            path.chmod(mode)

        patches = (
            mock.patch.object(engine.grp, "getgrgid",
                              lambda gid: SimpleNamespace(gr_name="users")),
            mock.patch.object(engine, "merge_config_into_state",
                              lambda home, uid, gid: self.state),
            mock.patch.object(engine.shutil, "rmtree", lambda *a, **k: None),
            mock.patch.object(warp, "migrate_account", lambda *a, **k: None),
            mock.patch.object(core, "write_text", side_effect=write_text),
            mock.patch.object(core, "run", side_effect=run),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        engine.install_system(user)
        calls.clear()
        engine.install_system(user)
        self.assertNotIn(["systemctl", "daemon-reload"], calls)
        self.assertNotIn(["systemctl", "enable", C.UNIT], calls)
        self.assertNotIn(["systemctl", "enable", C.WARP_UNIT], calls)
        self.assertNotIn(["sysctl", "-q", "-w",
                          "net.netfilter.nf_conntrack_tcp_be_liberal=1"], calls)

    def test_install_queries_unit_state_once(self):
        calls = self._install({C.UNIT: True, C.WARP_UNIT: True})
        self.assertEqual(len([c for c in calls if c[:2] == ["systemctl", "show"]]), 1)
        self.assertEqual([c for c in calls if c[:2] == ["systemctl", "is-enabled"]], [])

    def test_setup_migrates_old_choice_into_state(self):
        self._install({C.UNIT: False, C.WARP_UNIT: True})
        data = json.loads((self.state / "state.json").read_text(encoding="utf-8"))
        self.assertFalse(data["dpi"])
        self.assertTrue(data["warp"])

    def test_restarts_only_what_was_up(self):
        calls = []

        def fake(action, *args, **kwargs):
            calls.append(action)
            return completed(action)

        with mock.patch.object(core, "systemctl", fake), \
             mock.patch.object(warp, "warp_systemctl", fake), \
             mock.patch.object(warp, "warp_unit_state", lambda: ("active", "")):
            engine.restart_services(True)
        self.assertEqual(calls, ["restart", "restart"])
        calls.clear()
        with mock.patch.object(core, "systemctl", fake), \
             mock.patch.object(warp, "warp_systemctl", fake), \
             mock.patch.object(warp, "warp_unit_state", lambda: ("inactive", "")):
            engine.restart_services(False)
        self.assertEqual(calls, [])

    def test_restart_services_skips_when_unchanged(self):
        with mock.patch.object(core, "systemctl") as dpi_call, \
             mock.patch.object(warp, "warp_systemctl") as warp_call, \
             mock.patch.object(warp, "warp_unit_state",
                               return_value=("active", "enabled")):
            engine.restart_services(True, changed=False)
        dpi_call.assert_not_called()
        warp_call.assert_not_called()

    def test_finish_update_skips_refresh_when_unchanged(self):
        user = SimpleNamespace(pw_name="kich", pw_dir=str(self.home))
        with mock.patch.object(engine.installer, "refresh_warp_config",
                               side_effect=self.fail) as refresh, \
             mock.patch.object(core, "systemctl") as dpi_call, \
             mock.patch.object(warp, "warp_systemctl") as warp_call, \
             mock.patch.object(warp, "warp_unit_state",
                               return_value=("active", "enabled")):
            self.assertEqual(engine.finish_system_update(user, True, False), "")
        refresh.assert_not_called()
        dpi_call.assert_not_called()
        warp_call.assert_not_called()

    def test_refresh_does_nothing_when_warp_is_not_in_use(self):
        with mock.patch.object(core, "run",
                               side_effect=lambda *a, **k: self.fail("unexpected command")):
            self.assertEqual(engine.refresh_warp_config(
                SimpleNamespace(pw_name="kich", pw_dir=str(self.home))), "")

    def test_refresh_renders_as_the_owner_of_home(self):
        C.WARP_CONFIG.write_text("mixed-port: 0\n", encoding="utf-8")
        C.WARP_ACCOUNT.write_text("{}", encoding="utf-8")
        argv = []

        def run(args, **kwargs):
            argv.extend(str(a) for a in args)
            return completed(args, 0, "{}", "")

        with mock.patch.object(core, "run", side_effect=run):
            self.assertEqual(engine.refresh_warp_config(
                SimpleNamespace(pw_name="kich", pw_dir=str(self.home))), "")
        self.assertEqual(argv[:3], ["runuser", "-u", "kich"])
        self.assertIn("HOME=%s" % self.home, argv)
        self.assertEqual(argv[-1], "warp-config")
        self.assertEqual(argv[-2], str(C.APP_DIR / "bin" / "kich-dpi"))

    def test_refresh_reports_a_failed_render_without_failing_the_update(self):
        C.WARP_CONFIG.write_text("mixed-port: 0\n", encoding="utf-8")
        C.WARP_ACCOUNT.write_text("{}", encoding="utf-8")
        cp = completed(["runuser"], 1, "", "нет списков правил")
        with mock.patch.object(core, "run", return_value=cp):
            note = engine.refresh_warp_config(
                SimpleNamespace(pw_name="kich", pw_dir=str(self.home)))
        self.assertIn("нет списков правил", note)


class ReleaseInfoTest(unittest.TestCase):
    """A 403 from GitHub must fall back to the redirect, not block updates."""

    @staticmethod
    def _response(url):
        class FakeResponse:
            def __init__(self, value):
                self._url = value

            def geturl(self):
                return self._url

            def read(self):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return FakeResponse(url)

    def test_api_rate_limit_uses_redirect(self):
        errors = []

        def urlopen(req, timeout=0):
            if "api.github.com" in req.full_url:
                err = urllib.error.HTTPError(
                    req.full_url, 403, "rate limit exceeded", {}, None)
                errors.append(err)
                raise err
            return self._response("https://github.com/bol-van/zapret2/releases/tag/v1.0.7")

        with mock.patch.object(urllib.request, "urlopen", side_effect=urlopen):
            tag, url, digest = engine.release_info()
        self.assertEqual(tag, "v1.0.7")
        self.assertEqual(url, "https://github.com/bol-van/zapret2/releases/download/"
                              "v1.0.7/zapret2-v1.0.7.tar.gz")
        self.assertEqual(digest, "")
        for err in errors:
            err.close()

    def test_non_403_error_propagates(self):
        errors = []

        def urlopen(req, timeout=0):
            err = urllib.error.HTTPError(req.full_url, 500, "server error", {}, None)
            errors.append(err)
            raise err

        with mock.patch.object(urllib.request, "urlopen", side_effect=urlopen):
            with self.assertRaises(urllib.error.HTTPError):
                engine.release_info()
        for err in errors:
            err.close()


class WarpTest(SandboxTest):
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
        super().setUp()
        warp.install_rule_lists()

    def test_config_is_valid_and_keeps_ru_traffic_direct(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")
        data = yaml.safe_load(warp.warp_config_text(self.ACCOUNT))
        self.assertTrue(data["tun"]["enable"])
        self.assertEqual(data["tun"]["device"], C.WARP_DEVICE)
        # One pinned gateway: rotating endpoints dropped handshakes.
        self.assertEqual(len(data["proxies"]), 1)
        proxy = data["proxies"][0]
        self.assertEqual(proxy["name"], "WARP")
        self.assertEqual(proxy["type"], "masque")
        self.assertEqual(proxy["port"], 443)
        self.assertEqual(proxy["network"], "quic")
        self.assertEqual(proxy["server"], C.WARP_ENDPOINT)
        self.assertEqual(proxy["ip-version"], "ipv6-prefer")
        self.assertTrue(proxy["udp"])
        self.assertNotIn("BEGIN", proxy["public-key"])
        self.assertNotIn("proxy-groups", data)
        self.assertEqual(data["routing-mark"], int(C.WARP_MARK, 16))
        self.assertEqual(data["mixed-port"], C.WARP_MIXED_PORT)
        self.assertEqual(data["bind-address"], "127.0.0.1")
        self.assertEqual(data["find-process-mode"], "off")
        self.assertEqual(data["rule-providers"]["ru-domain"]["behavior"], "domain")
        self.assertEqual(data["rule-providers"]["ru-ip"]["behavior"], "ipcidr")
        self.assertTrue(pathlib.Path(data["rule-providers"]["ru-domain"]["path"]).is_file())
        self.assertIn("RULE-SET,ru-domain,DIRECT", data["rules"])
        self.assertIn("RULE-SET,ru-ip,DIRECT", data["rules"])
        # `no-resolve` would skip this rule for every domain connection.
        self.assertNotIn("RULE-SET,ru-ip,DIRECT,no-resolve", data["rules"])
        self.assertIn("AND,((NETWORK,udp),(DST-PORT,443)),WARP", data["rules"])
        self.assertIn("NETWORK,udp,DIRECT", data["rules"])
        self.assertEqual(data["rules"][-1], "MATCH,WARP")

    def test_user_lists_add_rules_and_turn_on_process_matching(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")
        C.WARP_USER_DOMAINS.write_text("# своё\nmy.example\n", encoding="utf-8")
        C.WARP_USER_PROCESSES.write_text("telegram\n", encoding="utf-8")
        warp.install_rule_lists()
        data = yaml.safe_load(warp.warp_config_text(self.ACCOUNT))
        self.assertEqual(data["find-process-mode"], "strict")
        self.assertEqual(data["rules"][0], "PROCESS-NAME,telegram,DIRECT")
        self.assertIn("RULE-SET,direct-domains,DIRECT", data["rules"])
        payload = pathlib.Path(data["rule-providers"]["direct-domains"]["path"])
        self.assertEqual(payload, C.WARP_RULES / "direct-domains.txt")
        self.assertEqual(payload.read_text(encoding="utf-8"), "+.my.example\n")

    def test_domain_lists_use_suffix_matching(self):
        payload = (C.WARP_RULES / "ru-domain.txt").read_text(encoding="utf-8")
        self.assertIn("\n+.yandex.net\n", payload)
        self.assertIn("\n+.ya.ru\n", payload)
        self.assertNotIn("\nyandex.net\n", payload)
        for line in payload.splitlines():
            if not line or line.startswith("#"):
                continue
            self.assertTrue(line.startswith("+."), line)
        self.assertEqual(warp.domain_payload("a.ru\n\n# x\n+.b.ru\n"),
                         "+.a.ru\n\n# x\n+.b.ru\n")

    def test_comma_in_process_name_is_rejected(self):
        C.WARP_USER_PROCESSES.write_text("bad,name\n", encoding="utf-8")
        with self.assertRaises(core.Fail):
            warp.warp_config_text(self.ACCOUNT)

    def test_network_profile_describes_the_real_link(self):
        def run(argv, **kwargs):
            args = [str(a) for a in argv]
            if args[:4] == ["ip", "-4", "route", "show"] and "default" in args:
                return completed(args, 0, "default via 192.168.5.1 dev eth9 "
                                 "proto dhcp src 192.168.5.20 metric 100\n")
            if args[:3] == ["ip", "-4", "addr", "show"]:
                return completed(args, 0, "2: eth9: inet 192.168.5.20/24 brd "
                                 "192.168.5.255 scope global eth9\n")
            if "-4" in args and "link" in args:
                return completed(args, 0, "192.168.5.0/24 proto kernel scope "
                                 "link src 192.168.5.20\n")
            if "-6" in args:
                return completed(args, 0, "")
            if args and args[0] == "resolvectl":
                return completed(args, 0, "Global: 9.9.9.9\neth9: 192.168.5.1\n")
            return completed(args, 1, "", "unexpected command")

        reachable = {C.WARP_ENDPOINTS[0]}
        with mock.patch.object(core, "run", side_effect=run), \
             mock.patch.object(warp_network, "tcp_open", lambda *a, **k: True), \
             mock.patch.object(warp_network, "endpoint_healthy",
                               side_effect=lambda w, host: host in reachable), \
             mock.patch.object(warp_network, "interface_mtu", lambda w, d: 1400):
            profile = warp.warp_network()
        self.assertEqual(profile["interface"], "eth9")
        self.assertEqual(profile["gateway"], "192.168.5.1")
        self.assertEqual(profile["address"], "192.168.5.20")
        self.assertEqual(profile["networks4"], ["192.168.5.0/24"])
        self.assertEqual(profile["mtu"], 1400)
        self.assertEqual(profile["dns"], ["9.9.9.9", "192.168.5.1"])
        self.assertFalse(profile["ipv6"])
        # The pinned gateway is blocked here, so a sibling must be selected.
        self.assertEqual(profile["endpoint"], C.WARP_ENDPOINTS[0])
        self.assertEqual(profile["endpoints"], [C.WARP_ENDPOINTS[0]])

    def test_config_follows_the_detected_network(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")
        profile = {
            "interface": "eth9", "gateway": "192.168.5.1", "address": "192.168.5.20",
            "networks4": ["192.168.5.0/24"], "networks6": [], "mtu": 1200,
            "ipv6": False, "dns": ["9.9.9.9", "192.168.5.1"],
            "endpoint": "162.159.198.2", "endpoints": ["162.159.198.2"],
        }
        text = warp.warp_config_text(self.ACCOUNT, profile)
        data = yaml.safe_load(text)
        proxy = data["proxies"][0]
        self.assertEqual(proxy["server"], "162.159.198.2")
        self.assertEqual(proxy["ip-version"], "ipv4-only")
        self.assertNotIn("ipv6", proxy)
        self.assertEqual(data["tun"]["mtu"], 1200)
        self.assertNotIn("inet6-address", data["tun"])
        self.assertFalse(data["dns"]["ipv6"])
        self.assertIn("192.168.5.0/24", data["tun"]["route-exclude-address"])
        self.assertNotIn("192.168.0.0/16", data["tun"]["route-exclude-address"])
        self.assertIn("IP-CIDR,192.168.5.0/24,DIRECT,no-resolve", data["rules"])
        self.assertNotIn("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", data["rules"])
        self.assertEqual(data["dns"]["default-nameserver"], ["9.9.9.9", "192.168.5.1"])
        self.assertEqual(data["dns"]["nameserver"], ["https://9.9.9.9/dns-query"])
        self.assertIn("Network: eth9 via 192.168.5.1", text)

    def test_wireguard_profile_avoids_the_dme_node(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")
        profile = {
            "interface": "eth9", "gateway": "192.168.5.1", "address": "192.168.5.20",
            "networks4": ["192.168.5.0/24"], "networks6": [], "mtu": 1280,
            "ipv6": True, "dns": ["9.9.9.9"], "endpoint": C.WARP_ENDPOINT,
            "endpoints": [C.WARP_ENDPOINT],
            "wg_endpoint": "8.47.69.189", "wg_port": 1701,
            "wg_private_key": "cHJpdg==", "wg_public_key": "cHVi",
            "wg_ipv4": "172.16.0.2/32",
        }
        text = warp.warp_config_text(self.ACCOUNT, profile)
        data = yaml.safe_load(text)
        proxy = data["proxies"][0]
        self.assertEqual(proxy["type"], "wireguard")
        self.assertEqual(proxy["peers"][0]["server"], "8.47.69.189")
        self.assertEqual(proxy["peers"][0]["port"], 1701)
        self.assertNotIn("network", proxy)
        self.assertFalse(data["ipv6"])
        self.assertIn("8.47.69.189/32", data["tun"]["route-exclude-address"])
        self.assertIn("# WARP over WireGuard", text)

    def _profile(self):
        return {"interface": "eth0", "gateway": "192.168.5.1",
                "address": "192.168.5.20"}

    def test_cached_endpoint_skips_the_mihomo_probe(self):
        profile = self._profile()
        core.write_json(C.WARP_PROBE_CACHE, {
            "version": 1, "time": int(time.time()),
            "path": warp_network.path_key(profile),
            "endpoints": {C.WARP_ENDPOINT: True},
        })
        with mock.patch.object(warp_network, "network_signature",
                               lambda w: dict(profile)), \
             mock.patch.object(warp_network, "tcp_open",
                               side_effect=AssertionError("must not probe")), \
             mock.patch.object(warp_network, "endpoint_healthy",
                               side_effect=AssertionError("must not probe")):
            result = warp.warp_network()
        self.assertEqual(result["endpoint"], C.WARP_ENDPOINT)
        self.assertEqual(result["endpoints"], [C.WARP_ENDPOINT])

    def test_tcp_failure_skips_the_mihomo_probe(self):
        with mock.patch.object(warp_network, "network_signature",
                               lambda w: self._profile()), \
             mock.patch.object(warp_network, "tcp_open", lambda *a, **k: False), \
             mock.patch.object(warp_network, "endpoint_healthy",
                               side_effect=AssertionError("must not probe")):
            result = warp.warp_network()
        self.assertEqual(result["endpoints"], [])
        self.assertEqual(result["endpoint"], C.WARP_ENDPOINT)

    def test_stale_cache_forces_a_fresh_probe(self):
        profile = self._profile()
        core.write_json(C.WARP_PROBE_CACHE, {
            "version": 1, "time": int(time.time()) - 3600,
            "path": warp_network.path_key(profile),
            "endpoints": {C.WARP_ENDPOINT: True},
        })
        with mock.patch.object(warp_network, "network_signature",
                               lambda w: dict(profile)), \
             mock.patch.object(warp_network, "tcp_open", lambda *a, **k: True), \
             mock.patch.object(warp_network, "endpoint_healthy",
                               return_value=False) as probe:
            result = warp.warp_network()
        self.assertEqual(result["endpoints"], [])
        self.assertEqual(probe.call_count, 2)

    def test_wg_profile_uses_a_cached_endpoint(self):
        account = {"private_key": "cHJpdg==", "public_key": "cHVi",
                   "id": "wg-id", "ipv4": "172.16.0.2"}
        chosen = C.WARP_WG_ENDPOINTS[1]
        core.write_json(C.WARP_PROBE_CACHE, {
            "version": 1, "time": int(time.time()), "path": "wg",
            "wg": {endpoint: endpoint == chosen
                   for endpoint in C.WARP_WG_ENDPOINTS},
        })
        with mock.patch.object(warp, "wg_account", lambda: account), \
             mock.patch.object(warp_network, "wg_endpoint_healthy",
                               side_effect=AssertionError("must not probe")):
            profile = warp.wg_profile()
        self.assertEqual(profile["wg_endpoint"], chosen.rsplit(":", 1)[0])

    def test_wg_probe_tries_only_one_backup(self):
        account = {"private_key": "cHJpdg==", "public_key": "cHVi",
                   "id": "wg-id", "ipv4": "172.16.0.2"}
        with mock.patch.object(warp, "wg_account", lambda: account), \
             mock.patch.object(warp_network, "wg_endpoint_healthy",
                               return_value=False) as probe:
            profile = warp.wg_profile()
        self.assertEqual(profile, {})
        self.assertEqual(probe.call_count, 2)

    def test_wg_profile_picks_the_first_healthy_endpoint(self):
        account = {"private_key": "cHJpdg==", "public_key": "cHVi",
                   "id": "wg-id", "access_token": "token", "ipv4": "172.16.0.2"}
        chosen = C.WARP_WG_ENDPOINTS[1]

        def healthy(_warp, endpoint, _account):
            return endpoint == chosen

        with mock.patch.object(warp, "wg_account", lambda: account), \
             mock.patch.object(warp_network, "wg_endpoint_healthy", healthy):
            profile = warp.wg_profile()
        self.assertEqual(profile["wg_endpoint"], chosen.rsplit(":", 1)[0])
        self.assertEqual(profile["wg_port"], int(chosen.rsplit(":", 1)[1]))
        self.assertEqual(profile["wg_ipv4"], "172.16.0.2/32")

    def test_wg_registration_saves_the_device(self):
        reg = {
            "id": "wg-id", "token": "wg-token",
            "config": {
                "peers": [{"public_key": "peer-key"}],
                "interface": {"addresses": {"v4": "172.16.0.2", "v6": "fd00::2"}},
            },
        }
        saved = {}

        with mock.patch.object(warp, "cf_request", lambda *a, **k: reg), \
             mock.patch.object(warp, "save_wg_account", lambda a: saved.update(a)):
            account = warp.warp_register_wg()
        self.assertEqual(saved, account)
        self.assertEqual(account["public_key"], "peer-key")
        self.assertEqual(account["ipv4"], "172.16.0.2")
        self.assertEqual(account["access_token"], "wg-token")

    def test_build_passes_the_profile_to_the_generator(self):
        profile = {"endpoint": "162.159.198.2", "networks4": ["10.9.0.0/24"]}
        seen = {}

        def record(account, network):
            seen["network"] = network
            return "generated"

        with mock.patch.object(warp, "warp_account", lambda: dict(self.ACCOUNT)), \
             mock.patch.object(warp, "warp_network", lambda *a, **k: profile), \
             mock.patch.object(warp, "warp_config_text", side_effect=record), \
             mock.patch.object(core, "write_text", side_effect=lambda *a, **k: None):
            warp.warp_build()
        self.assertEqual(seen["network"], profile)

    def test_build_merges_the_wireguard_profile(self):
        profile = {"endpoint": C.WARP_ENDPOINT, "networks4": ["10.9.0.0/24"]}
        wg = {"wg_endpoint": "8.47.69.189", "wg_port": 1701,
              "wg_private_key": "cHJpdg==", "wg_public_key": "cHVi",
              "wg_ipv4": "172.16.0.2/32"}
        seen = {}

        def record(account, network):
            seen["network"] = network
            return "generated"

        with mock.patch.object(warp, "warp_account", lambda: dict(self.ACCOUNT)), \
             mock.patch.object(warp, "warp_network", lambda *a, **k: profile), \
             mock.patch.object(warp, "wg_profile", lambda: wg), \
             mock.patch.object(warp, "warp_config_text", side_effect=record), \
             mock.patch.object(core, "write_text", side_effect=lambda *a, **k: None):
            warp.warp_build()
        self.assertEqual(seen["network"], dict(profile, **wg))

    def test_build_skips_masque_probes_when_wireguard_is_healthy(self):
        profile = {"endpoint": C.WARP_ENDPOINT, "networks4": ["10.9.0.0/24"]}
        wg = {"wg_endpoint": "8.47.69.189", "wg_port": 1701,
              "wg_private_key": "cHJpdg==", "wg_public_key": "cHVi",
              "wg_ipv4": "172.16.0.2/32"}
        seen = {}

        def network(*args, **kwargs):
            seen["probe"] = kwargs.get("probe", args[0] if args else True)
            return dict(profile)

        with mock.patch.object(warp, "warp_account", lambda: dict(self.ACCOUNT)), \
             mock.patch.object(warp, "wg_profile", lambda: wg), \
             mock.patch.object(warp, "warp_network", side_effect=network), \
             mock.patch.object(warp, "warp_config_text", lambda a, n: "generated"), \
             mock.patch.object(core, "write_text", side_effect=lambda *a, **k: None):
            warp.warp_build()
        self.assertIs(seen["probe"], False)

    def test_build_keeps_masque_probes_without_wireguard(self):
        profile = {"endpoint": C.WARP_ENDPOINT, "networks4": ["10.9.0.0/24"]}
        seen = {}

        def network(*args, **kwargs):
            seen["probe"] = kwargs.get("probe", args[0] if args else True)
            return dict(profile)

        with mock.patch.object(warp, "warp_account", lambda: dict(self.ACCOUNT)), \
             mock.patch.object(warp, "wg_profile", lambda: {}), \
             mock.patch.object(warp, "warp_network", side_effect=network), \
             mock.patch.object(warp, "warp_config_text", lambda a, n: "generated"), \
             mock.patch.object(core, "write_text", side_effect=lambda *a, **k: None):
            warp.warp_build()
        self.assertIs(seen["probe"], True)

    def test_config_is_reused_when_the_stamp_still_matches(self):
        account = dict(self.ACCOUNT)
        core.write_json(C.WARP_ACCOUNT, account, 0o600)
        core.write_json(C.WARP_WG_ACCOUNT, {}, 0o600)
        text = "# generated\n"
        C.WARP_CONFIG.write_text(text, encoding="utf-8")
        C.WARP_RULES.mkdir(parents=True, exist_ok=True)
        for name in ("ru-domain.txt", "ru-ip.txt", "direct-domains.txt"):
            (C.WARP_RULES / name).write_text("", encoding="utf-8")
        signature = {"interface": "eth9", "gateway": "192.168.5.1",
                     "address": "192.168.5.20", "networks4": ["192.168.5.0/24"],
                     "networks6": [], "mtu": 1400, "ipv6": False, "dns": ["9.9.9.9"]}
        for path in (C.WARP_USER_DOMAINS, C.WARP_USER_PROCESSES):
            path.write_text("", encoding="utf-8")

        def unexpected(*args, **kwargs):
            self.fail("unchanged config must not be regenerated")

        with mock.patch.object(warp, "warp_network_signature", lambda: signature):
            inputs = warp.warp_build_inputs()
            core.write_json(C.WARP_BUILD_STAMP, {
                "version": 1, "account": account["id"], "wg_account": "",
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "inputs": inputs,
            }, 0o600)
            with mock.patch.object(warp, "warp_network", side_effect=unexpected), \
                 mock.patch.object(warp, "wg_profile", side_effect=unexpected), \
                 mock.patch.object(warp, "warp_config_text", side_effect=unexpected), \
                 mock.patch.object(core, "out", lambda payload: None):
                warp.cmd_warp_config()
        self.assertEqual(C.WARP_CONFIG.read_text(encoding="utf-8"), text)

    def test_changed_user_list_forces_a_config_rebuild(self):
        account = dict(self.ACCOUNT)
        core.write_json(C.WARP_ACCOUNT, account, 0o600)
        core.write_json(C.WARP_WG_ACCOUNT, {}, 0o600)
        text = "# generated\n"
        C.WARP_CONFIG.write_text(text, encoding="utf-8")
        C.WARP_RULES.mkdir(parents=True, exist_ok=True)
        for name in ("ru-domain.txt", "ru-ip.txt", "direct-domains.txt"):
            (C.WARP_RULES / name).write_text("", encoding="utf-8")
        C.WARP_USER_PROCESSES.write_text("", encoding="utf-8")
        C.WARP_USER_DOMAINS.write_text("", encoding="utf-8")
        signature = {"interface": "eth9"}

        with mock.patch.object(warp, "warp_network_signature", lambda: signature):
            inputs = warp.warp_build_inputs()
            core.write_json(C.WARP_BUILD_STAMP, {
                "version": 1, "account": account["id"], "wg_account": "",
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "inputs": inputs,
            }, 0o600)
            C.WARP_USER_DOMAINS.write_text("example.org\n", encoding="utf-8")
            with mock.patch.object(warp, "warp_network",
                                   lambda *a, **k: {"endpoint": C.WARP_ENDPOINT}), \
                 mock.patch.object(warp, "wg_profile", lambda: {}), \
                 mock.patch.object(warp, "warp_config_text",
                                   lambda a, n: "rebuilt\n"), \
                 mock.patch.object(core, "out", lambda payload: None):
                warp.cmd_warp_config()
            built = core.read_dict(C.WARP_BUILD_STAMP)
        self.assertEqual(C.WARP_CONFIG.read_text(encoding="utf-8"), "rebuilt\n")
        self.assertNotEqual(built.get("inputs"), inputs)

    def test_forced_config_rebuilds_even_with_a_matching_stamp(self):
        account = dict(self.ACCOUNT)
        core.write_json(C.WARP_ACCOUNT, account, 0o600)
        core.write_json(C.WARP_WG_ACCOUNT, {}, 0o600)
        profile = {"endpoint": C.WARP_ENDPOINT}
        with mock.patch.object(warp, "warp_network", lambda *a, **k: profile), \
             mock.patch.object(warp, "wg_profile", lambda: {}), \
             mock.patch.object(warp, "warp_config_text", lambda a, n: "rebuilt\n"), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_config(force=True)
        self.assertEqual(C.WARP_CONFIG.read_text(encoding="utf-8"), "rebuilt\n")

    def test_register_is_a_noop_when_both_accounts_exist(self):
        core.write_json(C.WARP_ACCOUNT, dict(self.ACCOUNT), 0o600)
        core.write_json(C.WARP_WG_ACCOUNT, {
            "id": "wg-id", "private_key": "cHJpdg==", "public_key": "cHVi",
            "access_token": "token", "ipv4": "172.16.0.2",
        }, 0o600)
        built = []

        def unexpected(*args, **kwargs):
            self.fail("existing accounts must not be re-registered")

        with mock.patch.object(warp, "warp_enroll", side_effect=unexpected), \
             mock.patch.object(warp, "warp_register", side_effect=unexpected), \
             mock.patch.object(warp, "warp_register_wg", side_effect=unexpected), \
             mock.patch.object(warp, "warp_build",
                               lambda account, force=False: built.append(force)), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_register()
        self.assertEqual(built, [False])

    def test_rule_lists_ship_with_the_plugin(self):
        domains = core.list_lines(ROOT / "ru-domain.txt")
        ips = core.list_lines(ROOT / "ru-ip.txt")
        self.assertIn("gosuslugi.ru", domains)
        self.assertGreater(len(domains), 40)
        self.assertNotIn("#", domains[0])
        self.assertGreater(len(ips), 5000)
        for item in ips[::200]:
            ipaddress.ip_network(item)

    def test_user_lists_are_created_once(self):
        warp.ensure_user_lists()
        self.assertTrue(C.WARP_USER_DOMAINS.is_file())
        self.assertTrue(C.WARP_USER_PROCESSES.is_file())
        C.WARP_USER_DOMAINS.write_text("kept.example\n", encoding="utf-8")
        warp.ensure_user_lists()
        self.assertEqual(C.WARP_USER_DOMAINS.read_text(encoding="utf-8"), "kept.example\n")

    def test_build_asks_for_the_system_part_when_lists_are_missing(self):
        with mock.patch.object(warp, "warp_account", lambda: dict(self.ACCOUNT)), \
             mock.patch.object(C, "BUNDLED_RULES", self.base / "none"):
            with self.assertRaises(core.Fail) as ctx:
                warp.warp_build()
        self.assertIn("обновите", str(ctx.exception))

    def test_warp_check_dials_the_proxy_port(self):
        result, calls = {}, []
        trace = "ip=104.28.0.1\nwarp=on\ncolo=DME\n"

        def run(argv, **kwargs):
            argv = [str(a) for a in argv]
            calls.append(argv)
            if argv[:2] == ["ip", "route"]:
                return completed(argv, 0, "1.1.1.1 dev %s table 2022\n" % C.WARP_DEVICE, "")
            return completed(argv, 0, trace, "")

        with mock.patch.object(core.subprocess, "run", side_effect=run), \
             mock.patch.object(core, "out", lambda data: result.update(data)):
            warp.cmd_warp_check()
        curl = [call for call in calls if call[0] == "curl"][0]
        self.assertIn("-x", curl)
        self.assertIn("http://127.0.0.1:%d" % C.WARP_MIXED_PORT, curl)
        check = result["check"]
        self.assertTrue(check["ok"])
        self.assertEqual(check["colo"], "DME")
        self.assertTrue(check["tun"])

    def test_warp_check_reports_a_route_that_bypasses_the_tunnel(self):
        result, calls = {}, []
        trace = "ip=104.28.0.1\nwarp=on\ncolo=DME\n"

        def run(argv, **kwargs):
            argv = [str(a) for a in argv]
            calls.append(argv)
            if argv[:2] == ["ip", "route"]:
                return completed(argv, 0, "1.1.1.1 dev enp8s0 src 192.168.0.5\n", "")
            return completed(argv, 0, trace, "")

        with mock.patch.object(core.subprocess, "run", side_effect=run), \
             mock.patch.object(core, "out", lambda data: result.update(data)):
            warp.cmd_warp_check()
        check = result["check"]
        self.assertTrue(check["ok"])
        self.assertFalse(check["tun"])

    def test_warp_unit_validates_the_config_before_start(self):
        text = engine.unit_text(engine.WARP_UNIT_TEMPLATE, "/home/u", user="u", group="g")
        lines = text.splitlines()
        pre = [i for i, line in enumerate(lines) if line.startswith("ExecStartPre=")]
        start = [i for i, line in enumerate(lines) if line.startswith("ExecStart=")]
        self.assertTrue(pre)
        self.assertIn(" -t ", lines[pre[0]])
        self.assertLess(pre[0], start[0])

    def test_warp_unit_starts_through_the_state_aware_wrapper(self):
        text = engine.unit_text(engine.WARP_UNIT_TEMPLATE, "/home/u", user="u", group="g")
        self.assertIn("ExecStart=/opt/kich-dpi/app/bin/kich-dpi-warp-run", text)
        self.assertNotIn("ExecStart=/opt/kich-dpi/mihomo -f", text)

    def test_unit_templates_render_shared_hardening(self):
        shared = (
            "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            "LimitNOFILE=65535",
        )
        for template in (engine.UNIT_TEMPLATE, engine.WARP_UNIT_TEMPLATE):
            lines = engine.unit_text(template, "/home/u", user="u", group="g").splitlines()
            self.assertFalse([line for line in lines if "{" in line])
            for line in shared:
                self.assertIn(line, lines)
        self.assertIn("PrivateDevices=yes", engine.unit_text(
            engine.UNIT_TEMPLATE, "/home/u", user="u", group="g").splitlines())
        self.assertIn("DeviceAllow=/dev/net/tun rw", engine.unit_text(
            engine.WARP_UNIT_TEMPLATE, "/home/u", user="u", group="g").splitlines())

    def test_missing_account_is_rejected(self):
        with self.assertRaises(core.Fail):
            warp.warp_config_text({})

    def test_endpoint_and_cidr_normalisation(self):
        self.assertEqual(warp.strip_endpoint("162.159.198.2:443"), "162.159.198.2")
        self.assertEqual(warp.strip_endpoint("[2606:4700::1]:443"), "2606:4700::1")
        self.assertEqual(warp.cidr_of("172.16.0.2", 4), "172.16.0.2/32")
        self.assertEqual(warp.cidr_of("2606:4700::2", 6), "2606:4700::2/128")
        self.assertEqual(warp.cidr_of("bad", 4), "")

    def test_no_usque_conflict_guard(self):
        sources = [BIN.read_text(encoding="utf-8").lower()]
        sources += [p.read_text(encoding="utf-8").lower()
                    for p in (ROOT / "src" / "kich_dpi").glob("*.py")]
        for text in sources:
            self.assertNotIn("usque", text)

    def test_config_passes_mihomo_validation(self):
        binary = os.environ.get("KICH_DPI_MIHOMO")
        if not binary or not pathlib.Path(binary).exists():
            self.skipTest("KICH_DPI_MIHOMO is not set")
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        private_key, public_key = warp.warp_keys()
        _, gateway = warp.warp_keys()
        account = dict(self.ACCOUNT, private_key=private_key, public_key=public_key,
                       endpoint_pub_key=gateway)
        # mihomo only accepts rule-provider paths under the same root as config.
        C.WARP_CONFIG.write_text(warp.warp_config_text(account), encoding="utf-8")
        cp = subprocess.run([binary, "-t", "-f", str(C.WARP_CONFIG), "-d", str(self.base)],
                            capture_output=True, text=True, timeout=60)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)


class WarpEnablementTest(SandboxTest):
    def _recorder(self, active):
        calls = []
        state = {"active": active}

        def fake(*args, **kwargs):
            action = args[0]
            calls.append(args)
            if action == "start":
                state["active"] = True
            if action == "stop":
                state["active"] = False
            return completed(args)

        def unit_state():
            return ("active" if state["active"] else "inactive", "enabled")

        return calls, fake, unit_state

    def test_warp_unit_state_uses_one_systemctl_show(self):
        C.WARP_UNIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        C.WARP_UNIT_PATH.write_text("[Unit]\n", encoding="utf-8")
        out = "%s\nactive\nenabled\n" % C.WARP_UNIT
        with mock.patch.object(core.subprocess, "run",
                               return_value=completed([], 0, out, "")) as run:
            state = warp.warp_unit_state()
        self.assertEqual(state, ("active", "enabled"))
        self.assertEqual(run.call_count, 1)
        self.assertIn("show", run.call_args.args[0])

    def test_warp_off_reads_the_unit_once_and_reuses_it_for_status(self):
        reads = []

        def unit_state():
            reads.append(1)
            return ("active", "enabled")

        seen = {}

        def status(**kwargs):
            seen.update(kwargs)
            return {}

        with mock.patch.object(warp, "warp_unit_state", unit_state), \
             mock.patch.object(warp, "warp_systemctl", lambda *a, **k: completed(a)), \
             mock.patch.object(warp, "warp_status", status), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_off()
        self.assertEqual(len(reads), 1)
        self.assertEqual(seen["_states"][C.WARP_UNIT], ("inactive", "enabled"))

    def test_warp_on_reads_the_unit_once_when_healthy(self):
        reads = []

        def unit_state():
            reads.append(1)
            return ("active", "enabled")

        stamps = [{"version": 1, "account": "test"}] * 2
        seen = {}

        def status(**kwargs):
            seen.update(kwargs)
            return {}

        with mock.patch.object(warp, "warp_available", lambda: True), \
             mock.patch.object(warp, "warp_account", lambda: {"id": "test"}), \
             mock.patch.object(warp, "warp_build", lambda account: None), \
             mock.patch.object(warp, "warp_build_stamp", side_effect=stamps), \
             mock.patch.object(warp, "warp_check_data", lambda: {"ok": True}), \
             mock.patch.object(warp, "warp_unit_state", unit_state), \
             mock.patch.object(warp, "warp_systemctl", lambda *a, **k: completed(a)), \
             mock.patch.object(warp, "warp_status", status), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_on()
        self.assertEqual(len(reads), 1)
        self.assertEqual(seen["_states"][C.WARP_UNIT], ("active", "enabled"))

    def test_warp_off_stops_and_remembers(self):
        calls, fake, unit_state = self._recorder(True)

        with mock.patch.object(warp, "warp_systemctl", fake), \
             mock.patch.object(warp, "warp_unit_state", unit_state), \
             mock.patch.object(warp, "warp_status", lambda *a, **k: {}), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_off()
        self.assertEqual([c[0] for c in calls], ["stop"])
        self.assertFalse(core.wanted_flags()["warp"])

    def test_warp_on_restarts_and_remembers(self):
        calls, fake, unit_state = self._recorder(True)

        with mock.patch.object(warp, "warp_available", lambda: True), \
             mock.patch.object(warp, "warp_account", lambda: {"id": "test"}), \
             mock.patch.object(warp, "warp_build", lambda account: None), \
             mock.patch.object(warp, "warp_check_data", lambda: {"ok": False}), \
             mock.patch.object(warp, "warp_unit_state", unit_state), \
             mock.patch.object(warp, "warp_systemctl", fake), \
             mock.patch.object(warp, "warp_status", lambda *a, **k: {}), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_on()
        self.assertEqual([c[0] for c in calls], ["restart"])
        self.assertTrue(core.wanted_flags()["warp"])

    def test_repeated_warp_on_leaves_a_healthy_tunnel_alone(self):
        calls, fake, unit_state = self._recorder(True)
        C.WARP_CONFIG.write_text("mixed-port: 17890\n", encoding="utf-8")
        stamp = {"version": 1, "account": "test"}

        with mock.patch.object(warp, "warp_available", lambda: True), \
             mock.patch.object(warp, "warp_account", lambda: {"id": "test"}), \
             mock.patch.object(warp, "warp_build", lambda account: None), \
             mock.patch.object(warp, "warp_build_stamp",
                               side_effect=[stamp, stamp]), \
             mock.patch.object(warp, "warp_check_data", lambda: {"ok": True}), \
             mock.patch.object(warp, "warp_unit_state", unit_state), \
             mock.patch.object(warp, "warp_systemctl", fake), \
             mock.patch.object(warp, "warp_status", lambda *a, **k: {}), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_on()
        self.assertEqual(calls, [])

    def test_warp_on_restarts_an_unhealthy_tunnel_with_the_same_config(self):
        calls, fake, unit_state = self._recorder(True)
        C.WARP_CONFIG.write_text("mixed-port: 17890\n", encoding="utf-8")
        stamp = {"version": 1, "account": "test"}

        with mock.patch.object(warp, "warp_available", lambda: True), \
             mock.patch.object(warp, "warp_account", lambda: {"id": "test"}), \
             mock.patch.object(warp, "warp_build", lambda account: None), \
             mock.patch.object(warp, "warp_build_stamp",
                               side_effect=[stamp, stamp]), \
             mock.patch.object(warp, "warp_check_data", lambda: {"ok": False}), \
             mock.patch.object(warp, "warp_unit_state", unit_state), \
             mock.patch.object(warp, "warp_systemctl", fake), \
             mock.patch.object(warp, "warp_status", lambda *a, **k: {}), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_on()
        self.assertEqual([c[0] for c in calls], ["restart"])

    def test_repeated_warp_off_does_not_stop_an_inactive_unit(self):
        calls, fake, unit_state = self._recorder(False)

        with mock.patch.object(warp, "warp_unit_state", unit_state), \
             mock.patch.object(warp, "warp_systemctl", fake), \
             mock.patch.object(warp, "warp_status", lambda *a, **k: {}), \
             mock.patch.object(core, "out", lambda payload: None):
            warp.cmd_warp_off()
        self.assertEqual(calls, [])


class DpiToggleTest(SandboxTest):
    def test_is_running_reads_only_the_active_state(self):
        with mock.patch.object(core, "installed", lambda: True), \
             mock.patch.object(core.subprocess, "run",
                               return_value=completed([], 0, "active\n", "")) as run:
            self.assertTrue(core.is_running())
        self.assertEqual(run.call_count, 1)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ["systemctl", "is-active"])
        self.assertNotIn("is-enabled", argv)

    def _systemctl_recorder(self):
        calls = []
        state = {"active": False}

        def fake(*args, **kwargs):
            action = args[0]
            calls.append(args)
            if action == "is-active":
                return completed(args, 0, "active\n" if state["active"] else "inactive\n")
            if action == "is-enabled":
                return completed(args, 0, "enabled\n")
            if action == "start":
                state["active"] = True
            if action == "stop":
                state["active"] = False
            return completed(args)

        return calls, fake

    def test_on_uses_start_and_off_uses_stop(self):
        calls, fake = self._systemctl_recorder()

        with mock.patch.object(core, "installed", lambda: True), \
             mock.patch.object(core, "systemctl", fake), \
             mock.patch.object(status, "status_data", lambda: {}), \
             mock.patch.object(core, "out", lambda payload: None):
            strategies.cmd_on()
            self.assertTrue(core.wanted_flags()["dpi"])
            strategies.cmd_off()
            self.assertFalse(core.wanted_flags()["dpi"])
        self.assertEqual([c for c in calls if c[0] in ("start", "stop")],
                         [("start",), ("stop",)])

    def test_repeated_on_and_off_do_not_touch_the_unit(self):
        calls, fake = self._systemctl_recorder()

        with mock.patch.object(core, "installed", lambda: True), \
             mock.patch.object(core, "systemctl", fake), \
             mock.patch.object(status, "status_data", lambda: {}), \
             mock.patch.object(core, "out", lambda payload: None):
            strategies.cmd_on()
            strategies.cmd_on()
            strategies.cmd_off()
            strategies.cmd_off()
        self.assertEqual([c for c in calls if c[0] in ("start", "stop")],
                         [("start",), ("stop",)])


class ProbeSanityTest(SandboxTest):
    def test_default_device_parses_the_main_route(self):
        self.assertEqual(core.default_device(
            "default via 192.168.0.1 dev enp8s0 proto dhcp src 192.168.0.113"), "enp8s0")
        self.assertEqual(core.device_from_route(""), "")

    def test_direct_probe_binds_the_physical_interface(self):
        seen = []

        def fake_probes(urls, timeout, interface=""):
            seen.append(interface)
            return [(True, 204, 10, "") for _url in urls]

        with mock.patch.object(core, "curl_available", lambda: True), \
             mock.patch.object(core, "direct_device", return_value="enp8s0"), \
             mock.patch.object(strategies, "http_probes", side_effect=fake_probes):
            result = strategies.probe(direct=True)
        self.assertTrue(result["direct"])
        self.assertEqual(set(seen), {"enp8s0"})

    def test_probe_uses_one_curl_for_three_targets(self):
        stdout = "200 0.100000\n204 0.050000\n200 0.200000\n"
        with mock.patch.object(core, "curl_available", lambda: True), \
             mock.patch.object(core, "direct_device", return_value=""), \
             mock.patch.object(core, "run",
                               return_value=completed([], 0, stdout, "")) as run:
            result = strategies.probe()
        self.assertEqual(run.call_count, 1)
        argv = run.call_args.args[0]
        for _key, _label, url in C.TARGETS:
            self.assertIn(url, argv)
        self.assertEqual(argv.count("/dev/null"), 3)
        self.assertEqual((result["passed"], result["total"]), (3, 3))

    def test_sanity_fails_when_a_control_host_does_not_answer(self):
        def fake_probes(urls, timeout, interface=""):
            answers = []
            for url in urls:
                ok = "example.com" not in url
                answers.append((ok, 200 if ok else 0, 15, "" if ok else "timeout"))
            return answers

        with mock.patch.object(core, "direct_device", return_value="enp8s0"), \
             mock.patch.object(strategies, "http_probes", side_effect=fake_probes), \
             mock.patch.object(strategies.time, "sleep"):
            result = strategies.sanity()
        self.assertFalse(result["ok"])
        self.assertEqual([row["label"] for row in result["results"] if not row["ok"]],
                         ["example"])

    def test_sanity_uses_one_curl_for_all_controls(self):
        calls = []

        def fake_probes(urls, timeout, interface=""):
            calls.append(list(urls))
            return [(True, 200, 10, "") for _url in urls]

        with mock.patch.object(core, "direct_device", return_value=""), \
             mock.patch.object(strategies, "http_probes", side_effect=fake_probes):
            result = strategies.sanity()
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(calls[0]), len(strategies.SANITY_TARGETS))

    def test_sanity_guards_critical_direct_hosts(self):
        urls = [url for _key, url in strategies.SANITY_TARGETS]
        for url in ("https://aur.archlinux.org/", "https://www.gosuslugi.ru/",
                    "https://api.proxyapi.ru/", "https://console.proxyapi.ru/",
                    "https://opencode.ai/inference/openai/v1/models"):
            self.assertIn(url, urls)

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
            return strategies.priority_health(result, check)

        critical = health(True, True, False, True, True)
        cosmetic = health(False, False, True, False, False)
        self.assertGreater(critical, cosmetic)
        self.assertEqual(critical[0], 6 + 6 + 5 + 5)
        self.assertEqual(cosmetic[0], 1)

    def test_sanity_retries_a_single_failed_probe(self):
        calls = []
        first = strategies.SANITY_TARGETS[0][1]

        def fake_probes(urls, timeout, interface=""):
            calls.append(list(urls))
            answers = []
            for url in urls:
                if url == first and len(calls) == 1:
                    answers.append((False, 0, 15, "timeout"))
                else:
                    answers.append((True, 200, 10, ""))
            return answers

        with mock.patch.object(core, "direct_device", return_value=""), \
             mock.patch.object(strategies, "http_probes", side_effect=fake_probes), \
             mock.patch.object(strategies.time, "sleep"):
            result = strategies.sanity()
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], [first])


class AccountMigrationTest(SandboxTest):
    def setUp(self):
        super().setUp()
        self.old_dir = self.home / ".local" / "share" / C.ENGINE_SLUG
        self.old = self.old_dir / "account.json"

    def test_moves_the_old_share_account_into_state(self):
        self.old_dir.mkdir(parents=True)
        self.old.write_text('{"id": "old"}', encoding="utf-8")
        warp.migrate_account(self.home)
        self.assertFalse(self.old_dir.exists())
        self.assertEqual(C.WARP_ACCOUNT.read_text(encoding="utf-8"), '{"id": "old"}')
        self.assertEqual(C.WARP_ACCOUNT.stat().st_mode & 0o777, 0o600)

    def test_does_not_overwrite_an_already_migrated_account(self):
        self.old_dir.mkdir(parents=True)
        self.old.write_text('{"id": "old"}', encoding="utf-8")
        C.WARP_ACCOUNT.write_text('{"id": "new"}', encoding="utf-8")
        warp.migrate_account(self.home)
        self.assertEqual(C.WARP_ACCOUNT.read_text(encoding="utf-8"), '{"id": "new"}')

    def test_main_migrates_before_dispatch(self):
        self.old_dir.mkdir(parents=True)
        account = {"private_key": "k", "endpoint_pub_key": "p",
                   "id": "i", "access_token": "t"}
        self.old.write_text(json.dumps(account), encoding="utf-8")
        captured = {}
        with mock.patch.object(core, "out", captured.update):
            cli.main(["kich-dpi", "no-such-command"])
        self.assertFalse(captured["ok"])
        self.assertEqual(json.loads(C.WARP_ACCOUNT.read_text(encoding="utf-8"))["id"], "i")


class StateTest(SandboxTest):
    def test_merge_strategies_dedupes_and_sorts(self):
        rows = [
            {"id": "a", "name": "A", "passed": 1, "total": 3, "ms": 500},
            {"id": "b", "name": "B", "passed": 3, "total": 3, "ms": 900},
            {"id": "c", "name": "C", "passed": 2, "total": 3, "ms": 300},
        ]
        strategies.merge_strategies(rows)
        saved = json.loads(C.STRATEGIES_FILE.read_text(encoding="utf-8"))
        self.assertEqual([r["id"] for r in saved], ["b", "c", "a"])

        strategies.merge_strategies([
            {"id": "a", "name": "A2", "passed": 3, "total": 3, "ms": 100},
        ])
        saved = json.loads(C.STRATEGIES_FILE.read_text(encoding="utf-8"))
        self.assertEqual(saved[0]["id"], "a")
        self.assertEqual(saved[0]["name"], "A2")
        self.assertEqual(len(saved), 3)

        strategies.merge_strategies([
            {"id": "a", "name": "A2", "passed": 0, "total": 3, "ms": 10 ** 9},
        ])
        saved = json.loads(C.STRATEGIES_FILE.read_text(encoding="utf-8"))
        self.assertEqual(saved[-1]["id"], "a")
        self.assertEqual(saved[-1]["passed"], 0)

    def test_merge_uses_weighted_health_over_plain_passes(self):
        strategies.merge_strategies([
            {"id": "low", "name": "Low", "passed": 3, "ms": 100, "health": 1},
            {"id": "high", "name": "High", "passed": 2, "ms": 500, "health": 17},
        ])
        saved = json.loads(C.STRATEGIES_FILE.read_text(encoding="utf-8"))
        self.assertEqual(saved[0]["id"], "high")

    def test_apply_spec_writes_active(self):
        row = strategies.candidates()[0]
        with mock.patch.object(core, "systemctl", lambda *a, **k: completed(a)):
            strategies.apply_spec(row, start=True)
        active = json.loads(C.ACTIVE_FILE.read_text(encoding="utf-8"))
        self.assertEqual(active["spec"], row)
        self.assertEqual(active["name"], row["name"])
        self.assertEqual(active["id"], strategies.strategy_id(row))

    def test_wanted_state_is_persistent(self):
        self.assertTrue(core.wanted_flags()["dpi"])
        core.set_wanted("dpi", False)
        self.assertFalse(core.wanted_flags()["dpi"])
        self.assertTrue(core.wanted_flags()["warp"])
        core.set_wanted("warp", False)
        self.assertFalse(core.wanted_flags()["warp"])

    def test_apply_spec_marks_bypass_as_wanted(self):
        core.set_wanted("dpi", False)
        with mock.patch.object(core, "systemctl", lambda *a, **k: completed(a)):
            strategies.apply_spec(strategies.candidates()[0], start=True)
        self.assertTrue(core.wanted_flags()["dpi"])

    def test_generate_reuses_a_fresh_measurement(self):
        core.write_json(C.ACTIVE_FILE, {"id": "abc"}, 0o644)
        check = {"time": 1, "passed": 3, "total": 3, "results": []}
        core.write_json(C.PROGRESS_FILE, {
            "running": False, "finished": int(strategies.time.time()),
            "active_id": "abc", "wanted_dpi": True,
            "best_summary": {"name": "best", "passed": 3, "total": 3, "ms": 100},
            "final": check,
        })

        def unexpected(*args, **kwargs):
            self.fail("fresh measurement must not be repeated")

        with mock.patch.object(core, "installed", lambda: True), \
             mock.patch.object(core, "curl_available", lambda: True), \
             mock.patch.object(core, "is_running", lambda: True), \
             mock.patch.object(strategies, "generation_baseline", side_effect=unexpected), \
             mock.patch.object(core, "out", lambda payload: None):
            strategies.cmd_generate()

    def test_progress_older_than_half_hour_is_not_running(self):
        core.write_json(C.PROGRESS_FILE, {
            "running": True, "started": 1, "done": 4, "total": 18,
        })
        data = status.progress_data()
        self.assertFalse(data["running"])
        self.assertIn("error", data)

    def test_progress_survives_a_hand_edited_started_field(self):
        core.write_json(C.PROGRESS_FILE, {"running": True, "started": "oops"})
        data = status.progress_data()
        self.assertFalse(data["running"])

    def test_strategy_rows_survive_hand_edited_numbers(self):
        rows = status.strategy_rows([
            {"id": "a", "passed": "oops", "total": None, "ms": "1.5", "time": ""},
            {"id": "b", "passed": 2, "total": 3, "ms": 10, "time": 1},
        ])
        self.assertEqual([r["id"] for r in rows], ["b", "a"])
        self.assertEqual(rows[0]["passed"], 2)
        self.assertEqual(rows[1]["passed"], 0)
        self.assertEqual(rows[1]["ms"], 1)

    def test_status_data_survives_a_corrupt_strategies_file(self):
        core.write_json(C.STRATEGIES_FILE, [{"id": "x", "passed": "oops"}])
        states = {unit: ("inactive", "disabled")
                  for unit in (C.UNIT, C.WARP_UNIT, status.CONFLICT_UNIT)}
        with mock.patch.object(core, "engine_info", lambda: ("", False)), \
             mock.patch.object(core, "batched_unit_states", lambda units: states):
            data = status.status_data()
        self.assertEqual(data["strategies"][0]["passed"], 0)

    def test_merge_strategies_survives_hand_edited_numbers(self):
        core.write_json(C.STRATEGIES_FILE, [{"id": "old", "passed": "oops",
                                            "ms": "nope"}])
        strategies.merge_strategies([{"id": "new", "passed": 3, "ms": 5}])
        self.assertEqual([r["id"] for r in core.read_list(C.STRATEGIES_FILE)],
                         ["new", "old"])


class StatusTest(SandboxTest):
    def test_status_shape_without_engine(self):
        states = {unit: ("inactive", "not-found")
                  for unit in (C.UNIT, C.WARP_UNIT, status.CONFLICT_UNIT)}
        with mock.patch.object(core, "engine_info", lambda: ("", False)), \
             mock.patch.object(core, "batched_unit_states", lambda units: states):
            data = status.status_data()
        for key in ("ok", "installed", "running", "generating", "strategies", "check",
                    "warp", "conflict", "progress"):
            self.assertIn(key, data)
        self.assertFalse(data["installed"])
        self.assertFalse(data["running"])

    def test_strategies_command_reads_only_saved_rows(self):
        saved = [
            {"id": "a", "name": "A", "passed": 2, "total": 3, "ms": 50, "time": 1},
            {"id": "b", "name": "B", "passed": 4, "total": 4, "ms": 90, "time": 2},
            "ignored",
        ]
        captured = {}

        def forbidden(*args, **kwargs):
            raise AssertionError("status should not be rebuilt for strategies")

        with mock.patch.object(core, "read_list", return_value=saved), \
             mock.patch.object(core, "batched_unit_states", forbidden), \
             mock.patch.object(core, "engine_info", forbidden), \
             mock.patch.object(core, "out", captured.update):
            status.cmd_strategies()
        self.assertEqual([row["id"] for row in captured["strategies"]],
                         ["b", "a"])
        self.assertEqual(set(captured), {"ok", "strategies"})

    def test_batched_unit_states_uses_one_subprocess(self):
        units = [C.UNIT, C.WARP_UNIT, status.CONFLICT_UNIT]
        out = ("%s\nactive\nenabled\n\n"
               "%s\ninactive\nnot-found\n\n"
               "%s\nactive\n\n" % tuple(units))
        with mock.patch.object(core.subprocess, "run",
                               return_value=completed([], 0, out, "")) as run:
            states = core.batched_unit_states(units)
        self.assertEqual(states[units[0]], ("active", "enabled"))
        self.assertEqual(states[units[1]], ("inactive", "not-found"))
        self.assertEqual(states[units[2]], ("active", "not-found"))
        self.assertEqual(run.call_count, 1)

    def test_status_data_uses_single_subprocess(self):
        with mock.patch.object(core.subprocess, "run",
                               return_value=completed([], 0, "", "")) as run:
            data = status.status_data()
        self.assertEqual(run.call_count, 1)
        self.assertTrue(data["ok"])
        self.assertFalse(data["installed"])

    def test_status_exposes_desired_state_for_the_panel(self):
        core.write_json(C.STATE_FILE, {"version": 1, "dpi": False, "warp": True})
        with mock.patch.object(core.subprocess, "run",
                               return_value=completed([], 0, "", "")):
            data = status.status_data()
        self.assertEqual(data["wanted"], {"dpi": False, "warp": True})

    def _doctor(self, running, failed, active):
        warp_state = {"available": True, "registered": True, "account": "x",
                      "running": running, "failed": failed, "active": active}
        state = {"failed": failed, "active": active, "running": running,
                 "active_name": "strategy", "conflict": False, "warp": warp_state}
        captured = {}

        with mock.patch.object(status, "status_data", lambda: state), \
             mock.patch.object(core, "engine_info", lambda: ("", False)), \
             mock.patch.object(core, "run",
                               lambda *a, **k: completed(a, 0, "v1.0.7\n", "")), \
             mock.patch.object(core, "out", captured.update):
            status.cmd_doctor()
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

    def test_intentionally_disabled_services_are_healthy(self):
        state = {
            "failed": False, "active": "inactive", "running": False,
            "active_name": "", "conflict": False,
            "wanted": {"dpi": False, "warp": False},
            "warp": {"available": True, "registered": True, "account": "x",
                     "running": False, "failed": False, "active": "inactive"},
        }
        with mock.patch.object(status, "status_data", lambda: state), \
             mock.patch.object(core, "engine_info", lambda: ("", False)), \
             mock.patch.object(core, "run",
                               lambda *a, **k: completed(a, 0, "", "")), \
             mock.patch.object(status, "polkit_rule_state", lambda: (True, "")):
            checks, _ = status.doctor_checks()
        rows = {row["name"]: row for row in checks}
        self.assertTrue(rows["служба"]["ok"])
        self.assertEqual(rows["служба"]["detail"], "отключена намеренно")
        self.assertTrue(rows["служба WARP"]["ok"])
        self.assertEqual(rows["служба WARP"]["detail"], "отключена намеренно")

    def test_private_directory_is_not_reported_as_missing_rule(self):
        with mock.patch.object(status.os, "access", lambda path, mode: False), \
             mock.patch.object(C, "POLKIT_PATH",
                               pathlib.Path("/no/such/49-kich-dpi.rules")):
            ok, detail = status.polkit_rule_state()
        self.assertTrue(ok)
        self.assertIn("root", detail)

    def test_missing_rule_is_reported_when_directory_is_readable(self):
        rule = self.base / "49-kich-dpi.rules"
        with mock.patch.object(status.os, "access", lambda path, mode: True), \
             mock.patch.object(C, "POLKIT_PATH", rule):
            ok, detail = status.polkit_rule_state()
            self.assertFalse(ok)
            self.assertEqual(detail, str(rule))

            rule.write_text("// installed\n", encoding="utf-8")
            ok, detail = status.polkit_rule_state()
            self.assertTrue(ok)
            self.assertEqual(detail, str(rule))

    def test_polkit_rule_allows_enable_and_disable(self):
        text = engine.POLKIT_TEMPLATE.format(
            user="u", unit=C.UNIT, warp_unit=C.WARP_UNIT)
        self.assertIn("org.freedesktop.systemd1.manage-units", text)
        self.assertNotIn('action.id === "org.freedesktop.systemd1.manage-unit-files"', text)
        self.assertEqual(text.count("action.id"), 1)
        self.assertIn('unit === "%s"' % C.UNIT, text)
        self.assertIn('unit === "%s"' % C.WARP_UNIT, text)


class CheckAllTest(SandboxTest):
    """One button runs only the probes for services the user wants on."""

    ROWS = (
        ("движок", True), ("служба", True), ("mihomo", True),
        ("аккаунт WARP", True), ("служба WARP", True),
    )

    def _run(self, wanted_dpi=True, wanted_warp=True, installed=True):
        captured = {}
        calls = []

        def dpi_check():
            calls.append("dpi")
            return {"time": 1, "passed": 3, "total": 3, "results": []}

        def warp_check():
            calls.append("warp")
            return {"time": 1, "ok": True, "ip": "2a09::1", "error": ""}

        rows = [{"name": name, "ok": ok, "detail": ""}
                for name, ok in self.ROWS]
        with mock.patch.object(core, "wanted_flags", lambda: {
                "dpi": wanted_dpi, "warp": wanted_warp}), \
             mock.patch.object(core, "installed", lambda: installed), \
             mock.patch.object(strategies, "run_check", dpi_check), \
             mock.patch.object(warp, "warp_check_data", warp_check), \
             mock.patch.object(status, "doctor_checks", lambda: (rows, {})), \
             mock.patch.object(core, "out", captured.update):
            status.cmd_check_all()
        return calls, captured

    def test_both_enabled_checks_both_engines(self):
        calls, result = self._run()
        self.assertEqual(calls, ["dpi", "warp"])
        self.assertEqual(result["check"]["passed"], 3)
        self.assertTrue(result["warp_check"]["ok"])
        self.assertEqual(result["doctor"],
                         {"passed": 5, "total": 5, "failed": []})

    def test_warp_off_checks_dpi_only(self):
        calls, result = self._run(wanted_warp=False)
        self.assertEqual(calls, ["dpi"])
        self.assertIsNone(result["warp_check"])
        self.assertEqual(result["doctor"]["total"], 2)

    def test_dpi_off_checks_warp_only(self):
        calls, result = self._run(wanted_dpi=False)
        self.assertEqual(calls, ["warp"])
        self.assertIsNone(result["check"])
        self.assertEqual(result["doctor"]["total"], 5)

    def test_both_off_still_runs_system_diagnostics(self):
        calls, result = self._run(wanted_dpi=False, wanted_warp=False)
        self.assertEqual(calls, [])
        self.assertEqual(result["doctor"]["total"], 2)
        self.assertTrue(result["ok"])

    def test_missing_engine_skips_dpi_but_reports_system(self):
        calls, result = self._run(installed=False)
        self.assertEqual(calls, ["warp"])
        self.assertIsNone(result["check"])

    def test_failed_doctor_rows_are_reported(self):
        rows = [{"name": "nfqws2", "ok": False, "detail": "нет бинарника"},
                {"name": "curl", "ok": True, "detail": ""}]
        captured = {}
        with mock.patch.object(core, "wanted_flags", lambda: {
                "dpi": False, "warp": False}), \
             mock.patch.object(status, "doctor_checks", lambda: (rows, {})), \
             mock.patch.object(core, "out", captured.update):
            status.cmd_check_all()
        self.assertEqual(captured["doctor"]["failed"], ["nfqws2"])
        self.assertEqual(captured["doctor"]["passed"], 1)


class RepairTest(SandboxTest):
    def setUp(self):
        super().setUp()
        C.DPI_DOMAINS_FILE.write_text("# comment\nyoutube.com\n", encoding="utf-8")
        self.hosts = self.base / "hosts"
        self.hosts_backup = self.base / "hosts.bak"
        self.hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
        for name, value in (("REPAIR_HOSTS", self.hosts),
                            ("REPAIR_HOSTS_BACKUP", self.hosts_backup)):
            patcher = mock.patch.object(C, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.probe_result = {"time": 1, "passed": 3, "total": 3, "results": []}
        C.WARP_CONFIG.write_text("# existing config\n", encoding="utf-8")

    def _run(self, *, installed=True, media_reachable=True, uid=1000, running=True,
             dpi_rc=0, dpi_err="", account=None, checks=(), warp_rc=0, warp_err="",
             wanted_dpi=True, wanted_warp=True, warp_active="active",
             warp_build=None):
        checks = list(checks)
        last_check = [{}]
        clock = [0.0]
        calls = []
        captured = {}

        def record(name, value):
            def call(*args, **kwargs):
                calls.append((name, args, kwargs))
                return value(*args, **kwargs) if callable(value) else value
            return call

        def next_check():
            if checks:
                last_check[0] = checks.pop(0)
            return last_check[0]

        def advance(_seconds):
            clock[0] += 1

        dpi_cp = completed(["systemctl"], dpi_rc, "", dpi_err)
        warp_cp = completed(["systemctl"], warp_rc, "", warp_err)
        with mock.patch.object(core, "installed", record("installed", installed)), \
             mock.patch.object(core, "wanted_flags", record(
                 "wanted_flags", lambda: {"dpi": wanted_dpi, "warp": wanted_warp})), \
             mock.patch.object(core, "tcp_reachable",
                               record("tcp_reachable", media_reachable)), \
             mock.patch.object(core, "is_running", record("is_running", running)), \
             mock.patch.object(core, "systemctl", record("systemctl", dpi_cp)), \
             mock.patch.object(core, "write_json", record("write_json", None)), \
             mock.patch.object(warp, "warp_systemctl", record("warp_systemctl", warp_cp)), \
             mock.patch.object(warp, "warp_unit_state",
                               record("warp_unit_state", lambda: (warp_active, ""))), \
             mock.patch.object(warp, "warp_build", record("warp_build", warp_build)), \
             mock.patch.object(warp, "warp_account", record("warp_account", account)), \
             mock.patch.object(warp, "warp_check_data",
                               record("warp_check_data", next_check)), \
             mock.patch.object(strategies, "probe", record("probe", self.probe_result)), \
             mock.patch.object(repair, "os", SimpleNamespace(geteuid=lambda: uid)), \
             mock.patch.object(repair, "time", SimpleNamespace(
                 monotonic=lambda: clock[0], sleep=record("sleep", advance))), \
             mock.patch.object(repair, "chown_for_user", record("chown_for_user", None)), \
             mock.patch.object(core, "out", captured.update):
            error = ""
            try:
                repair.cmd_repair()
            except core.Fail as exc:
                error = str(exc)
        self.calls = calls
        return captured, error

    def _call_args(self, name):
        return [args for label, args, _ in self.calls if label == name]

    def test_adds_missing_discord_domains(self):
        result, error = self._run()
        text = C.DPI_DOMAINS_FILE.read_text(encoding="utf-8")
        self.assertIn("discord.gg", text)
        self.assertIn("discordapp.net", text)
        self.assertTrue(any("домены Discord" in f for f in result["fixes"]))
        self.assertEqual(error, "")

    def test_second_run_is_idempotent(self):
        first, _ = self._run()
        second, _ = self._run()
        self.assertEqual(second["fixes"], [])
        self.assertEqual(second["blocked"],
                         ["WARP: нет учётной записи — зарегистрируйте туннель"])

    def test_pins_media_hosts_and_keeps_a_backup(self):
        result, _ = self._run(media_reachable=False, uid=0)
        text = C.REPAIR_HOSTS.read_text(encoding="utf-8")
        self.assertIn(C.REPAIR_HOSTS_MARKER, text)
        for ip in C.REPAIR_MEDIA_GOOD_IPS:
            self.assertIn("%s %s" % (ip, " ".join(C.REPAIR_MEDIA_DOMAINS)), text)
        self.assertEqual(C.REPAIR_HOSTS_BACKUP.read_text(encoding="utf-8"),
                         "127.0.0.1 localhost\n")
        self.assertTrue(any("закреплены" in f for f in result["fixes"]))

    def test_skips_pinning_that_was_already_applied(self):
        self.hosts.write_text("127.0.0.1 localhost\n%s\n" % C.REPAIR_HOSTS_MARKER,
                              encoding="utf-8")
        result, _ = self._run(media_reachable=False, uid=0)
        self.assertEqual(self._call_args("tcp_reachable"), [])
        self.assertFalse(any("закреплены" in f for f in result["fixes"]))
        self.assertFalse(C.REPAIR_HOSTS_BACKUP.exists())

    def test_domains_write_is_atomic_on_failure(self):
        before = C.DPI_DOMAINS_FILE.read_bytes()
        with mock.patch.object(os, "replace", side_effect=OSError("disk full")):
            result, error = self._run()
        self.assertEqual(error, "")
        self.assertEqual(C.DPI_DOMAINS_FILE.read_bytes(), before)
        self.assertTrue(any("dpi-domains.txt: disk full" in b
                            for b in result["blocked"]))
        leftovers = [p.name for p in self.config.iterdir() if p.suffix == ".tmp"]
        self.assertEqual(leftovers, [])

    def test_hosts_write_is_atomic_on_failure(self):
        before = self.hosts.read_bytes()
        with mock.patch.object(os, "replace", side_effect=OSError("disk full")):
            result, _ = self._run(media_reachable=False, uid=0)
        self.assertEqual(self.hosts.read_bytes(), before)
        self.assertNotIn(C.REPAIR_HOSTS_MARKER, self.hosts.read_text(encoding="utf-8"))
        self.assertTrue(any("/etc/hosts: disk full" in b for b in result["blocked"]))

    def test_repair_preserves_file_modes(self):
        os.chmod(C.DPI_DOMAINS_FILE, 0o600)
        os.chmod(self.hosts, 0o640)
        self._run(media_reachable=False, uid=0)
        self.assertEqual(C.DPI_DOMAINS_FILE.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.hosts.stat().st_mode & 0o777, 0o640)

    def test_repeated_repair_keeps_hosts_byte_identical(self):
        self._run(media_reachable=False, uid=0)
        first = self.hosts.read_bytes()
        self._run(media_reachable=False, uid=0)
        self.assertEqual(self.hosts.read_bytes(), first)

    def test_media_pin_needs_root(self):
        result, _ = self._run(media_reachable=False, uid=1000)
        self.assertTrue(any("требует root" in b for b in result["blocked"]))
        self.assertNotIn(C.REPAIR_HOSTS_MARKER, C.REPAIR_HOSTS.read_text(encoding="utf-8"))

    def test_restarts_dpi_when_the_hostlist_changed(self):
        result, _ = self._run()
        self.assertEqual(self._call_args("systemctl"), [("restart",)])
        self.assertIn("DPI перезапущен", result["fixes"])

    def test_starts_dpi_that_is_down_without_changes(self):
        C.DPI_DOMAINS_FILE.write_text("\n".join(C.REPAIR_DISCORD_DOMAINS) + "\n",
                                      encoding="utf-8")
        result, _ = self._run(running=False)
        self.assertEqual(self._call_args("systemctl"), [("start",)])
        self.assertIn("DPI запущен", result["fixes"])

    def test_reports_a_failed_dpi_restart(self):
        result, _ = self._run(dpi_rc=1, dpi_err="unit failed\n")
        self.assertTrue(any(b.startswith("DPI: unit failed") for b in result["blocked"]))

    def test_rebuilds_a_missing_warp_config(self):
        C.WARP_CONFIG.unlink()
        def rebuild(_account):
            C.WARP_CONFIG.write_text("# rebuilt\n", encoding="utf-8")

        result, _ = self._run(account={"id": "abc"},
                              checks=[{"ok": False}, {"ok": True}],
                              warp_build=rebuild)
        self.assertTrue(C.WARP_CONFIG.exists())
        self.assertTrue(any("конфиг WARP создан" in f for f in result["fixes"]))

    def test_reports_a_warp_unit_skipped_by_systemd(self):
        result, _ = self._run(account={"id": "abc"}, checks=[{"ok": False}],
                              warp_active="inactive")
        self.assertTrue(any("не активна" in b for b in result["blocked"]))
        self.assertFalse(any("WARP перезапущен" in f for f in result["fixes"]))

    def test_waits_for_a_slow_warp_proxy(self):
        result, _ = self._run(account={"id": "abc"},
                              checks=[{"ok": False}, {"ok": False},
                                      {"ok": True, "colo": "DME"}])
        self.assertIn("WARP перезапущен · подключён", result["fixes"])
        self.assertEqual(result["blocked"], [])
        self.assertTrue(self._call_args("sleep"))

    def test_reports_when_the_warp_port_never_opens(self):
        result, _ = self._run(account={"id": "abc"}, media_reachable=False,
                              checks=[{"ok": False}])
        self.assertTrue(any("порт WARP не открылся" in b for b in result["blocked"]))

    def test_restarts_a_stalled_warp_tunnel(self):
        result, _ = self._run(account={"id": "abc"},
                              checks=[{"ok": False}, {"ok": True, "ip": "1.2.3.4"}])
        self.assertEqual(self._call_args("warp_systemctl"), [("restart",)])
        self.assertEqual(len(self._call_args("warp_check_data")), 2)
        self.assertIn("WARP перезапущен · подключён", result["fixes"])
        self.assertEqual(result["warp_check"], {"ok": True, "ip": "1.2.3.4"})

    def test_keeps_the_failed_check_when_warp_restart_fails(self):
        failed = {"ok": False, "error": "нет ответа"}
        result, _ = self._run(account={"id": "abc"}, checks=[failed],
                              warp_rc=1, warp_err="denied\n")
        self.assertTrue(any(b.startswith("WARP: denied") for b in result["blocked"]))
        self.assertEqual(result["warp_check"], failed)

    def test_does_not_start_dpi_that_the_user_switched_off(self):
        result, error = self._run(wanted_dpi=False, running=False)
        self.assertEqual(error, "")
        self.assertEqual(self._call_args("systemctl"), [])
        self.assertFalse(any("DPI " in f for f in result["fixes"]))

    def test_does_not_start_warp_that_the_user_switched_off(self):
        result, error = self._run(account={"id": "abc"},
                                  checks=[{"ok": False}], wanted_warp=False)
        self.assertEqual(error, "")
        self.assertEqual(self._call_args("warp_systemctl"), [])
        self.assertEqual(len(self._call_args("warp_check_data")), 0)

    def test_appends_domains_without_concatenating_the_last_line(self):
        C.DPI_DOMAINS_FILE.write_text("discord.com", encoding="utf-8")
        result, error = self._run()
        text = C.DPI_DOMAINS_FILE.read_text(encoding="utf-8")
        self.assertEqual(error, "")
        self.assertIn("discord.com\ndiscordapp.com", text)
        self.assertNotIn("discord.comdiscordapp.com", text)
        self.assertTrue(any("домены Discord" in f for f in result["fixes"]))

    def test_recreates_a_missing_domains_file(self):
        C.DPI_DOMAINS_FILE.unlink()
        result, error = self._run()
        self.assertEqual(error, "")
        self.assertTrue(C.DPI_DOMAINS_FILE.is_file())
        self.assertIn("discord.com", C.DPI_DOMAINS_FILE.read_text(encoding="utf-8"))

    def test_refuses_to_run_without_the_engine(self):
        result, error = self._run(installed=False)
        self.assertEqual(result, {})
        self.assertEqual(error, "сначала установите движок")
        self.assertEqual(self.calls, [("installed", (), {})])

    def test_refreshes_the_probe_cache_for_the_panel(self):
        result, _ = self._run()
        writes = self._call_args("write_json")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0], C.CHECK_FILE)
        self.assertEqual(writes[0][1], self.probe_result)
        self.assertEqual(set(result), {"ok", "fixes", "blocked", "check", "warp_check"})


class CoreHelpersTest(SandboxTest):
    def test_to_int_tolerates_hand_edited_values(self):
        self.assertEqual(core.to_int("4"), 4)
        self.assertEqual(core.to_int("1.9"), 1)
        self.assertEqual(core.to_int(None), 0)
        self.assertEqual(core.to_int("oops", 7), 7)
        self.assertEqual(core.to_int(True), 1)

    def test_identical_write_preserves_the_file(self):
        path = self.base / "same.txt"
        core.write_text(path, "same\n", 0o600)
        before = path.stat()
        core.write_text(path, "same\n", 0o600)
        after = path.stat()
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(after.st_ino, before.st_ino)
        self.assertEqual(after.st_mode & 0o777, 0o600)

    def test_write_json_mode_is_applied_only_when_requested(self):
        path = self.base / "nested" / "account.json"
        core.write_json(path, {"a": 1}, mode=0o600)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"a": 1})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        other = self.base / "state.json"
        core.write_json(other, [1, 2])
        self.assertTrue(other.exists())
        self.assertEqual(other.stat().st_mode & 0o777, 0o644)

    def test_mode_none_preserves_an_existing_file_mode(self):
        path = self.base / "secret.json"
        core.write_json(path, {"a": 1}, mode=0o600)
        core.write_json(path, {"a": 2})
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"a": 2})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_failed_replace_keeps_the_old_bytes_and_no_temp_file(self):
        path = self.base / "state.json"
        core.write_json(path, {"a": 2})
        seen = {}

        def replace(src, dst):
            seen["src"] = pathlib.Path(src)
            raise OSError("disk full")

        with mock.patch.object(os, "replace", side_effect=replace):
            with self.assertRaises(OSError):
                core.write_json(path, {"a": 3})
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"a": 2})
        self.assertTrue(seen["src"].name.startswith("." + path.name + "."))
        self.assertNotEqual(seen["src"].name, "." + path.name + ".tmp")
        self.assertFalse(seen["src"].exists())

    def test_unit_error_and_checked_call_keep_the_old_message_shape(self):
        cp = completed([], 1, "out\n", "err-line\n")
        self.assertEqual(core.unit_error(cp, "fallback"), "err-line")
        self.assertEqual(core.unit_error(cp, "fallback", 4), "line")
        call = mock.Mock(return_value=cp)
        with self.assertRaises(core.Fail) as ctx:
            core.checked_unit_call(call, "restart", "restart failed", 30)
        self.assertEqual(str(ctx.exception), "err-line")
        call.assert_called_once_with("restart", timeout=30)

    def test_active_spec_fallback_factory_is_lazy(self):
        calls = []

        def fallback():
            calls.append(1)
            return {"name": "default"}

        saved = {"name": "saved"}
        self.assertEqual(strategies.active_spec_from({"spec": saved}, fallback), saved)
        self.assertEqual(calls, [])
        self.assertEqual(strategies.active_spec_from({}, fallback), {"name": "default"})
        self.assertEqual(calls, [1])
        self.assertEqual(strategies.active_spec_from({}, {}), {})

    def test_route_device_parsing_is_shared(self):
        text = "default via 192.168.1.1 dev enp8s0 proto static\n"
        self.assertEqual(core.device_from_route(text), "enp8s0")
        self.assertEqual(core.default_device(text), "enp8s0")
        self.assertEqual(core.device_from_route(""), "")

    def test_command_handlers_cover_the_documented_commands(self):
        handlers = cli.command_handlers(["kich-dpi", "use"])
        for command in ("status", "on", "off", "toggle", "restart", "check",
                        "generate", "strategies", "use", "setup", "update",
                        "remove", "logs", "doctor", "repair", "warp-on",
                        "warp-off", "warp-toggle", "warp-register",
                        "warp-check", "warp-config", "_run", "_fw-down"):
            self.assertIn(command, handlers)
        with self.assertRaises(core.Fail) as ctx:
            handlers["use"]()
        self.assertEqual(str(ctx.exception), "использование: use <id>")

    def test_help_is_rendered_from_the_command_table(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out):
            self.assertEqual(cli.main(["kich-dpi", "--help"]), 0)
        self.assertEqual(out.getvalue(), cli.HELP_TEXT)
        self.assertEqual(cli.HELP_TEXT, cli._help_text())
        self.assertIn("  warp-on | warp-off | warp-toggle\n", cli.HELP_TEXT)
        self.assertIn(
            "  warp-config            пересобрать конфиг из текущего шаблона\n",
            cli.HELP_TEXT)

    def test_cli_errors_keep_the_json_envelope_and_zero_exit(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out), \
             mock.patch.object(warp, "migrate_account"):
            self.assertEqual(cli.main(["kich-dpi", "нет-такой-команды"]), 0)
        self.assertEqual(json.loads(out.getvalue()),
                         {"ok": False, "error": "неизвестная команда: нет-такой-команды"})

    def test_internal_commands_return_their_exit_code_without_json(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out), \
             mock.patch.object(warp, "migrate_account"), \
             mock.patch.object(engine, "cmd_run", return_value=7):
            self.assertEqual(cli.main(["kich-dpi", "_run"]), 7)
        self.assertEqual(out.getvalue(), "")

    def test_legacy_enabled_states_maps_masked_to_false(self):
        states = {C.UNIT: "enabled", C.WARP_UNIT: "masked-runtime"}

        def fake_systemctl(*args, **kwargs):
            return completed([], 0, states[kwargs["unit"]] + "\n", "")

        with mock.patch.object(core, "systemctl", side_effect=fake_systemctl):
            result = engine.legacy_enabled_states()
        self.assertEqual(result, {C.UNIT: True, C.WARP_UNIT: False})


class DpiModelJsTest(unittest.TestCase):
    """The panel's pure formatting and action-result rules."""

    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if not cls.node:
            raise unittest.SkipTest("node is not installed")
        cls.model = ROOT / "DpiModel.js"
        if not cls.model.is_file():
            raise unittest.SkipTest("DpiModel.js is not installed")

    def call(self, name, *args):
        script = (
            'const m = require(%s); const a = JSON.parse(%s); '
            'const v = m[%s](...a); '
            'process.stdout.write(JSON.stringify(v === undefined ? null : v))'
        ) % (json.dumps(str(self.model)), json.dumps(json.dumps(list(args))),
             json.dumps(name))
        cp = subprocess.run([self.node, "-e", script], capture_output=True,
                            text=True, timeout=15)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        return json.loads(cp.stdout)

    def test_status_reply_is_stale_after_a_newer_action(self):
        self.assertTrue(self.call("staleReply", 1, 2))
        self.assertFalse(self.call("staleReply", 2, 2))

    def test_compact_address_keeps_short_and_non_ipv6_values(self):
        self.assertEqual(self.call("compactAddress", "1.2.3.4"), "1.2.3.4")
        self.assertEqual(self.call("compactAddress", "abcd::1"), "abcd::1")

    def test_compact_address_elides_a_long_ipv6_address(self):
        value = "2a01:4f8:1c17:4d2b:1234:5678:9abc:def0"
        self.assertEqual(self.call("compactAddress", value), "2a01:4f8:1c17…9abc:def0")

    def test_warp_check_text_expires_after_15_minutes(self):
        check = {"time": 999900, "ok": True,
                 "ip": "2a01:4f8:1c17:4d2b:1234:5678:9abc:def0"}
        self.assertEqual(self.call("warpCheckText", check, 1000000000),
                         "2a01:4f8:1c17…9abc:def0")
        self.assertEqual(self.call("warpCheckText", check, 1002000000), "")

    def test_warp_text_covers_disabled_running_and_failed_states(self):
        self.assertEqual(self.call("warpText", {"available": False}, ""),
                         "mihomo не установлен — нажмите, чтобы доустановить")
        self.assertEqual(self.call("warpText", {"available": True, "running": True}, ""),
                         "Туннель включён")
        self.assertEqual(self.call("warpText", {"available": True, "failed": True}, ""),
                         "Служба не запустилась — смотрите журнал")
        self.assertEqual(self.call("warpText", {"available": True, "registered": True}, ""),
                         "Готов включить туннель")

    def test_state_and_time_texts(self):
        self.assertEqual(self.call("stateText", False, True, False, True), "нет связи")
        self.assertEqual(self.call("stateText", True, False, False, False), "не установлен")
        self.assertEqual(self.call("stateText", True, True, True, False), "ошибка")
        self.assertEqual(self.call("stateText", True, True, False, True), "включён")
        self.assertEqual(self.call("stateText", True, True, False, False), "выключен")
        self.assertEqual(self.call("whenText", {}, 1000000000), "ещё не проверялось")
        self.assertEqual(self.call("whenText", {"time": 999941}, 1000000000), "только что")
        self.assertEqual(self.call("whenText", {"time": 999640}, 1000000000), "6 мин назад")
        self.assertEqual(self.call("whenText", {"time": 996400}, 1000000000), "1 ч назад")

    def test_find_result(self):
        rows = [{"key": "youtube", "ok": True}, {"key": "discord", "ok": False}]
        self.assertEqual(self.call("findResult", rows, "discord"), rows[1])
        self.assertIsNone(self.call("findResult", rows, "google"))

    def test_health_helpers_are_quiet_only_when_enabled_services_work(self):
        now = 1000000000
        recent = {"time": 999900}
        base = {
            "installed": True, "failed": False, "running": True,
            "wanted": {"dpi": True, "warp": True},
            "check": dict(recent, total=3, passed=3),
            "warp": {
                "available": True, "failed": False, "running": True,
                "check": dict(recent, ok=True),
            },
        }
        self.assertFalse(self.call("dpiUnhealthy", base, now))
        self.assertFalse(self.call("warpUnhealthy", base, now))
        self.assertFalse(self.call("hasProblem", base, now))

        failed_dpi = dict(base, check=dict(recent, total=3, passed=2))
        self.assertTrue(self.call("dpiUnhealthy", failed_dpi, now))
        self.assertTrue(self.call("hasProblem", failed_dpi, now))
        self.assertFalse(self.call("dpiUnhealthy", dict(
            failed_dpi, wanted={"dpi": False, "warp": True}), now))
        self.assertFalse(self.call("dpiUnhealthy", dict(
            failed_dpi, check={"time": 0, "total": 3, "passed": 0}), now))
        self.assertTrue(self.call("dpiUnhealthy", dict(base, running=False), now))

        failed_warp = dict(base, warp=dict(
            base["warp"], check=dict(recent, ok=False)))
        self.assertTrue(self.call("warpUnhealthy", failed_warp, now))
        self.assertTrue(self.call("hasProblem", failed_warp, now))
        self.assertFalse(self.call("warpUnhealthy", dict(
            failed_warp, wanted={"dpi": True, "warp": False}), now))
        self.assertFalse(self.call("warpUnhealthy", dict(
            base, warp=dict(base["warp"], check={"time": 0, "ok": False})), now))
        self.assertTrue(self.call("warpUnhealthy", dict(
            base, warp=dict(base["warp"], running=False)), now))
        self.assertTrue(self.call("warpUnhealthy", dict(
            base, warp=dict(base["warp"], available=False)), now))

    def test_diagnostic_line_follows_the_enabled_services(self):
        state = {
            "installed": True,
            "wanted": {"dpi": True, "warp": False},
            "check": {"time": 1, "passed": 3, "total": 3},
            "warp": {"check": {"time": 1, "ok": False}},
        }
        self.assertEqual(self.call("diagnosticLine", state, None), "DPI 3/3")
        only_warp = dict(state, wanted={"dpi": False, "warp": True})
        self.assertEqual(self.call("diagnosticLine", only_warp, None), "WARP ошибка")
        both = dict(state, wanted={"dpi": True, "warp": True})
        self.assertEqual(self.call("diagnosticLine", both, None),
                         "DPI 3/3 · WARP ошибка")
        summary = {"doctor": {"passed": 11, "total": 12, "failed": ["nfqws2"]}}
        self.assertEqual(self.call("diagnosticLine", both, summary),
                         "DPI 3/3 · WARP ошибка · Система 11/12")
        self.assertEqual(self.call("diagnosticLine",
                                   dict(state, installed=False), summary),
                         "Проверки доступны после установки движка")
        fresh = {"check": {"time": 1, "passed": 2, "total": 3},
                 "warp_check": {"time": 1, "ok": True, "ip": "2a09::1"},
                 "doctor": {"passed": 5, "total": 5, "failed": []}}
        self.assertEqual(self.call("diagnosticLine", both, fresh),
                         "DPI 2/3 · WARP ok · Система 5/5")

    def test_diagnostic_problem_only_flags_real_failures(self):
        good = {"check": {"time": 1, "passed": 3, "total": 3},
                "warp_check": {"time": 1, "ok": True},
                "doctor": {"passed": 5, "total": 5, "failed": []}}
        self.assertFalse(self.call("diagnosticProblem", good))
        self.assertEqual(self.call("diagnosticError", good), "")

        bad = dict(good, check={"time": 1, "passed": 2, "total": 3},
                   warp_check={"time": 1, "ok": False, "error": "туннель не отвечает"},
                   doctor={"passed": 4, "total": 5, "failed": ["nfqws2"]})
        self.assertTrue(self.call("diagnosticProblem", bad))
        self.assertEqual(self.call("diagnosticError", bad),
                         "DPI 2/3 · WARP: туннель не отвечает · Система: nfqws2")
        self.assertFalse(self.call("diagnosticProblem", None))

    def test_action_result_keeps_the_combined_check_payload(self):
        payload = {"ok": True, "check": {"passed": 3, "total": 3},
                   "warp_check": None,
                   "doctor": {"passed": 5, "total": 5, "failed": []}}
        result = self.call("actionResult", "check-all", payload, 0, "")
        self.assertEqual(result["checkAll"], payload)
        self.assertEqual(result["flash"], "Всё проверено")
        self.assertEqual(result["error"], "")
        broken = dict(payload, doctor={"passed": 4, "total": 5, "failed": ["curl"]})
        result = self.call("actionResult", "check-all", broken, 0, "")
        self.assertEqual(result["error"], "Система: curl")
        self.assertEqual(result["flash"], "Есть проблемы")
        self.assertTrue(result["refresh"])

    def test_action_result_handles_pkexec_and_plain_errors(self):
        result = self.call("actionResult", "check", None, 126, "")
        self.assertEqual(result["error"], "Отменено")
        self.assertFalse(result["refresh"])
        result = self.call("actionResult", "check", None, 127, "")
        self.assertEqual(result["error"], "Не найден pkexec")
        self.assertFalse(result["refresh"])
        result = self.call("actionResult", "check", None, 1, "boom\nsecond line")
        self.assertEqual(result["error"], "boom")
        self.assertFalse(result["refresh"])
        result = self.call("actionResult", "check", {"ok": False, "error": "нет сети"}, 0, "")
        self.assertEqual(result["error"], "нет сети")
        self.assertFalse(result["refresh"])

    def test_action_result_reuses_status_and_warp_state(self):
        status_payload = {"ok": True, "installed": True}
        result = self.call("actionResult", "toggle", status_payload, 0, "", 0)
        self.assertTrue(result["reuseStatus"])
        warp_state = {"running": True}
        result = self.call("actionResult", "warp", {"ok": True, "warp": warp_state}, 0, "", 0)
        self.assertEqual(result["reuseWarp"], warp_state)
        self.assertTrue(result["followUpWarpCheck"])
        self.assertFalse(result["refresh"])

    def test_action_result_builds_repair_and_install_messages(self):
        result = self.call("actionResult", "repair", {"ok": True, "fixes": ["a", "b"],
                                                      "blocked": ["root"]}, 0, "", 0)
        self.assertEqual(result["flash"], "Исправлено: a · b")
        self.assertEqual(result["error"], "root")
        result = self.call("actionResult", "install", {"ok": True, "warp": False,
                                                       "warp_note": "нет сети"}, 0, "", 0)
        self.assertEqual(result["flash"], "Движок установлен")
        self.assertEqual(result["error"], "mihomo: нет сети")

    def test_invoke_uses_one_name_table(self):
        script = (
            'const m = require(%s); const calls = []; '
            'const d = {toggleBypass(){calls.push("service")}, '
            'toggleWarp(){calls.push("warp")}, '
            'runDiagnostics(){calls.push("check-all")}, '
            'runDoctor(){calls.push("doctor")}, checkWarp(){calls.push("warp-check")}, '
            'runGenerate(){calls.push("generate")}, runRepair(){calls.push("repair")}, '
            'refresh(){calls.push("refresh")}}; '
            '["service", "warp", "check", "doctor", "warp-check", '
            '"generate", "repair", "refresh"].forEach(n => m.invoke(d, n)); '
            'process.stdout.write(JSON.stringify(calls))'
        ) % json.dumps(str(self.model))
        cp = subprocess.run([self.node, "-e", script], capture_output=True,
                            text=True, timeout=15)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(json.loads(cp.stdout),
                         ["service", "warp", "check-all", "doctor", "warp-check",
                          "generate", "repair", "refresh"])

    def test_invoke_ignores_unknown_names_and_missing_targets(self):
        self.assertIsNone(self.call("invoke", None, "service"))
        self.assertIsNone(self.call("invoke", {}, "not-a-command"))


class QmlCliContractTest(unittest.TestCase):
    """Catch a renamed CLI command or a broken merge before the panel breaks."""

    @classmethod
    def setUpClass(cls):
        cls.pilot = (ROOT / "DpiPilot.qml").read_text(encoding="utf-8")
        cls.section = (ROOT / "DpiSection.qml").read_text(encoding="utf-8")
        cls.model = (ROOT / "DpiModel.js").read_text(encoding="utf-8")

    def test_section_drops_status_replies_older_than_an_action(self):
        self.assertIn("property int actionGeneration", self.section)
        self.assertIn("property int statusGeneration", self.section)
        self.assertIn("statusGeneration = actionGeneration", self.section)
        self.assertIn("actionGeneration += 1", self.section)
        self.assertIn("DpiModel.staleReply(root.statusGeneration, "
                      "root.actionGeneration)", self.section)

    def test_merged_widget_owns_both_network_and_dpi(self):
        self.assertIn('moduleName: "kich.dpi-pilot"', self.pilot)
        self.assertIn('ipcTarget: "omarchy.network"', self.pilot)
        self.assertIn('import "NetworkModel.js" as Model', self.pilot)
        self.assertIn("Quickshell.Networking", self.pilot)
        self.assertIn("DpiSection {", self.pilot)
        self.assertIn('target: "kich.dpi-pilot"', self.pilot)
        self.assertIn("active: root.restricted || root.dpiUnhealthy", self.pilot)
        self.assertIn("onDrawerReady: function(d)", self.pilot)
        self.assertIn("onDrawerGone: {", self.pilot)
        self.assertIn("root.dpiPending = []", self.pilot)
        # The popup is lazy-loaded, so the drawer publishes itself upward
        # instead of being referenced by id from the Panel root — and only
        # after the first status reply proves it is ready for IPC actions.
        self.assertIn("signal drawerReady(var drawer)", self.section)
        self.assertNotIn("Component.onCompleted: root.drawerReady(root)",
                         self.section)
        ready = re.search(r"\n    if \(!drawerPublished\) \{(.*?)\n    \}",
                          self.section, re.S)
        self.assertIsNotNone(ready)
        self.assertIn("drawerPublished = true", ready.group(1))
        self.assertIn("root.drawerReady(root)", ready.group(1))

    def test_qml_uses_only_known_commands(self):
        handlers = cli.command_handlers(["kich-dpi"])
        commands = set(re.findall(r'\[(?:root\.)?bin, "([a-z-]+)"', self.section))
        commands |= set(re.findall(r'\["pkexec", bin, "([a-z-]+)"', self.section))
        self.assertTrue(commands)
        self.assertLessEqual(commands, set(handlers))
        for expected in ("status", "toggle", "repair", "generate", "warp-check", "use"):
            self.assertIn(expected, commands)

    def test_ipc_actions_go_through_the_drawer_to_the_model(self):
        self.assertIn("function dpiInvoke(name)", self.pilot)
        run = re.search(r"function dpiRun\(d, name\) \{(.*?)\n  \}",
                        self.pilot, re.S)
        self.assertIsNotNone(run)
        self.assertIn("d.ipc(name)", run.group(1))
        # No second dispatch table in the panel: it would drift from the
        # drawer's guard and from the model's `toggle` alias.
        self.assertNotIn('name === "service"', run.group(1))
        actions = {
            "service": "service", "warp": "warp", "check": "check",
            "doctor": "doctor", "warpCheck": "warp-check",
            "generate": "generate", "repair": "repair", "refresh": "refresh",
        }
        for handler, action in actions.items():
            forwarded = re.search(
                r'function\s+%s\s*\(\)\s*\{\s*root\.dpiInvoke\("([a-z-]+)"\)\s*\}'
                % handler, self.pilot)
            self.assertIsNotNone(forwarded, "%s must forward to dpiInvoke" % handler)
            self.assertEqual(forwarded.group(1), action)
        self.assertIn("function ipc(name)", self.section)
        self.assertIn("DpiModel.invoke(root, name)", self.section)
        # One readiness queue lives in the panel; the drawer must not keep a
        # second one that can be flushed with a still-null status.
        self.assertNotIn("pendingIpc", self.section)
        self.assertIn("function toggle() { root.opened ? root.close() : root.open() }",
                      self.pilot)
        normalized = " ".join(self.model.split())
        self.assertIn('name === "service" || name === "toggle"', normalized)
        self.assertNotIn("invokeDrawer", self.model)

    def test_one_diagnostic_button_replaces_three(self):
        # The drawer-era label is back, but there is still exactly one button
        # and it still runs the state-aware combined check.
        self.assertIn(
            'text: root.actionName === "check-all" ? "Проверка…" : "Проверить"',
            self.section)
        self.assertEqual(self.section.count("root.runDiagnostics()"), 1)
        self.assertIn('[bin, "check-all"]', self.section)
        self.assertIn("function runDiagnostics()", self.section)
        self.assertIn("if (outcome.checkAll) lastCheckAll = outcome.checkAll",
                      self.section)
        for old in ("Проверить сайты", "Проверить WARP", 'text: "Диагностика"',
                    '"Проверить всё"'):
            self.assertNotIn(old, self.section)
        # The result line lives in the always-visible drawer header.
        self.assertIn("root.diagnosticLine]", self.section)
        self.assertIn("DpiModel.joinDetail([root.stateText, root.diagnosticLine])",
                      self.section)
        normalized_model = " ".join(self.model.split())
        self.assertIn('parts.filter(Boolean).join(" · ")', normalized_model)
        self.assertIn("DpiModel.diagnosticLine(st, lastCheckAll)", self.section)
        self.assertIn("DpiModel.diagnosticProblem(lastCheckAll)", self.section)

    def test_strategy_list_is_tucked_behind_advanced(self):
        toggle_at = self.section.index(
            'text: root.advanced ? "Свернуть" : "Дополнительно"')
        strategy_at = self.section.index(
            'PilotText { text: "Стратегии"; color: root.dim }')
        self.assertGreater(strategy_at, toggle_at,
                           "strategies must not sit in the main drawer view")
        self.assertIn("visible: root.advanced",
                      self.section[toggle_at:strategy_at])

    def test_model_action_names_reach_real_cli_commands(self):
        handlers = cli.command_handlers(["kich-dpi"])
        aliases = {"install": "setup", "warp": "warp-toggle"}
        ipc_only = {"service", "refresh"}
        names = set(re.findall(r'name === "([a-z-]+)"', self.model)) - ipc_only
        self.assertTrue(names)
        for name in names:
            self.assertIn(aliases.get(name, name), handlers,
                          "%s has no CLI handler" % name)

    def test_healthy_panel_is_white_and_only_failures_turn_red(self):
        # One shared icon: stock network problem OR a DPI/WARP failure.
        self.assertIn("active: root.restricted || root.dpiUnhealthy", self.pilot)
        self.assertIn("activeColor: bar ? bar.urgent", self.pilot)
        self.assertIn("readonly property bool dpiUnhealthy: dpiDrawerItem",
                      self.pilot)
        # The heart follows the exact same two flags as the two toggle cards.
        self.assertIn('glyph: "󰋑"', self.section)  # nf-md-heart, not nf-md-check
        self.assertIn("tint: root.dpiUnhealthy || root.warpUnhealthy",
                      self.section)
        self.assertIn("property color tint: root.foreground", self.section)
        self.assertIn("property color accentColor: root.foreground", self.section)
        self.assertIn("color: card.attention ? root.urgent : root.dim", self.section)
        self.assertIn(
            "accentColor: root.dpiUnhealthy ? root.urgent : root.foreground",
            self.section)
        self.assertIn(
            "accentColor: root.warpUnhealthy ? root.urgent : root.foreground",
            self.section)
        self.assertIn("color: control.attention ? root.urgent : root.dim",
                      self.section)
        # Stale probe rows must not paint a deliberately disabled service red.
        self.assertIn("visible: root.installed && root.running", self.section)

    def test_stock_button_behavior_and_square_corners(self):
        # The drawer uses the shell kit, not hand-rolled Controls buttons:
        # theme-owned corner radius, shared hover/pressed fills, focus ring,
        # press scale and stock tooltips.
        self.assertIn("component PilotButton: Button {", self.section)
        self.assertIn("component IconButton: PanelActionButton {", self.section)
        self.assertIn("component HeaderButton: BorderSurface {", self.section)
        self.assertNotIn("Controls.Button", self.section)
        self.assertNotIn("Controls.ToolTip", self.section)
        self.assertNotIn("radius: Style.space(6)", self.section)
        self.assertIn("radius: Style.cornerRadius", self.section)
        self.assertIn("bordered: true", self.section)  # DNS-pill outline
        self.assertIn("horizontalPadding: Style.spacing.controlPaddingX",
                      self.section)
        self.assertNotIn("anchors.margins:", self.section)
        self.assertIn("Style.hoverFillFor", self.section)
        self.assertIn("Style.pressedFillFor", self.section)
        self.assertIn("Border.controlSpec(", self.section)
        self.assertIn('"hover-cursor"', self.section)
        self.assertIn("scale: mouse.pressed ? 0.97 : 1", self.section)
        self.assertIn("easing.bezierCurve: Style.easeOut", self.section)
        # The shield is the DPI Pilot icon, now inside the expanding header.
        self.assertIn('glyph: "󰒘"', self.section)  # nf-md-shield
        self.assertIn("fontSize: Style.font.display", self.section)
        self.assertIn("spacing: Style.space(14)", self.section)
        self.assertIn("iconText: control.glyph", self.section)
        self.assertIn("opened: root.expanded", self.section)

    def test_action_errors_survive_the_next_status_poll(self):
        # A cancelled pkexec dialog must not be cleared by the 2.5s poll.
        self.assertIn("if (outcome.refresh) refresh()", self.section)
        self.assertIn('if (!actionErrorSticky) actionError = ""', self.section)
        self.assertIn("actionErrorSticky = true", self.section)
        self.assertIn("actionErrorSticky = false", self.section)

    def test_status_failures_are_reported_as_no_connectivity(self):
        self.assertIn(
            "DpiModel.stateText(statusReachable, installed, failed, running)",
            self.section)
        self.assertIn("statusReachable = false", self.section)
        self.assertIn("statusReachable = true", self.section)

    def test_pilot_text_never_renders_markup(self):
        # All panel strings come from JSON/CLI output; RichText would execute it.
        block = re.search(r"component PilotText: Text \{(.*?)\n  \}", self.section, re.S)
        self.assertIsNotNone(block)
        self.assertIn("textFormat: Text.PlainText", block.group(1))
        self.assertNotIn("textFormat: Text.RichText", self.section)


class RootInvocationTest(unittest.TestCase):
    def test_pkexec_uid_restores_invoking_home(self):
        uid = os.getuid()
        expected = pwd.getpwuid(uid).pw_dir
        with mock.patch.object(C.os, "geteuid", return_value=0), \
             mock.patch.dict(os.environ, {
                 "HOME": "/root", "PKEXEC_UID": str(uid),
             }, clear=False):
            self.assertEqual(C.invoking_home(), expected)

    def test_sudo_uid_is_used_when_pkexec_uid_is_absent(self):
        uid = os.getuid()
        expected = pwd.getpwuid(uid).pw_dir
        env = {"HOME": "/root", "PKEXEC_UID": "", "SUDO_UID": str(uid)}
        with mock.patch.object(C.os, "geteuid", return_value=0), \
             mock.patch.dict(os.environ, env, clear=False):
            self.assertEqual(C.invoking_home(), expected)

    def test_non_root_keeps_home(self):
        with mock.patch.object(C.os, "geteuid", return_value=1000), \
             mock.patch.dict(os.environ, {
                 "HOME": "/home/session", "PKEXEC_UID": "", "SUDO_UID": "",
             }, clear=False):
            self.assertEqual(C.invoking_home(), "/home/session")


class OwnershipTest(SandboxTest):
    """Root repairs must leave every config parent writable by the user."""

    def _fake_os(self, paths):
        fake = SimpleNamespace(walk=os.walk,
                               chown=lambda path, uid, gid: paths.append(
                                   (pathlib.Path(path), uid, gid)))
        return fake

    def test_chown_tree_covers_children_and_the_root(self):
        root = self.state / "tree"
        child = root / "child"
        child.mkdir(parents=True)
        (child / "file").write_text("x", encoding="utf-8")
        called = []
        ownership.chown_tree(root, 1000, 1000,
                             os_module=self._fake_os(called))
        self.assertEqual({path for path, _, _ in called},
                         {root, child, child / "file"})
        self.assertTrue(all((uid, gid) == (1000, 1000) for _, uid, gid in called))

    def test_chown_with_parents_includes_each_parent(self):
        target = self.config / "state.json"
        target.write_text("{}", encoding="utf-8")
        called = []
        ownership.chown_with_parents((target,), 1000, 1000,
                                     os_module=self._fake_os(called))
        self.assertEqual({path for path, _, _ in called}, {target, self.config})

    def test_repair_chown_is_a_noop_for_regular_users(self):
        report = repair.RepairReport()
        with mock.patch.object(repair, "os", SimpleNamespace(geteuid=lambda: 1000)):
            repair.chown_for_user(report, (C.STATE_FILE,))
        self.assertEqual(report.blocked, [])

    def test_repair_reports_chown_failures(self):
        report = repair.RepairReport()
        fake = self._fake_os([])
        fake.chown = lambda *_args: (_ for _ in ()).throw(OSError("denied"))
        fake.geteuid = lambda: 0
        with mock.patch.object(repair, "os", fake), \
             mock.patch.object(core, "target_user",
                               return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000)):
            repair.chown_for_user(report, (C.STATE_FILE,))
        self.assertTrue(any("права на конфигурацию" in b for b in report.blocked))


if __name__ == "__main__":
    unittest.main()
