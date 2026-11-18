import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
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

    def tearDown(self):
        self.tmp.cleanup()

    def test_status_shape_without_engine(self):
        self.mod.installed_version = lambda: ""
        self.mod.unit_state = lambda: ("inactive", "not-found")
        self.mod.subprocess.run = lambda *a, **k: subprocess.CompletedProcess(
            ["systemctl"], 1, "", "")
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
