#!/usr/bin/env python3
"""Real host -> sandboxed VM -> owned child memory regression tests (Linux)."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST = Path(os.environ.get("KSU_HOSTD", ROOT / "target/debug/ksu-mod-hostd")).resolve()


class HostFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HOST.is_file():
            raise RuntimeError(f"Build workspace binaries first: {HOST}")

    def call(self, *args, success=True):
        result = subprocess.run(
            [str(HOST), *map(str, args), "--json"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0 if success else 1, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertIs(value["ok"], success, value)
        return value

    def script(self, directory, body, grants=("mem.read", "mem.write_heap"), match=None):
        path = Path(directory) / "test.js"
        header = [
            "// ==ModScript==",
            "// @id com.example.ksumod.e2e",
            "// @name E2E fixture",
            "// @version 0.1.0",
            f"// @match {match or 'com.example.ksumod.fixture'}",
            *(f"// @grant {grant}" for grant in grants),
            "// ==/ModScript==",
        ]
        path.write_text("\n".join([*header, body, ""]), encoding="utf-8")
        return path

    def run_script(self, path, *, success=True, approval=None, development=True):
        digest = approval or hashlib.sha256(path.read_bytes()).hexdigest()
        args = ["run", path, "--fixture", "--approve", digest]
        if development:
            args.append("--development-sandbox")
        return self.call(*args, success=success)

    def test_doctor_reports_preview_and_available_runners(self):
        value = self.call("doctor")
        self.assertEqual(value["platform"], "linux")
        self.assertFalse(value["android_supported"])
        self.assertTrue(value["fixture_supported"])

    def test_both_real_runtimes_modify_owned_fixture_and_reap_child(self):
        for extension in ("lua", "js"):
            with self.subTest(runtime=extension):
                path = ROOT / f"examples/demo.{extension}"
                inspect = self.call("inspect-script", path)
                self.assertTrue(inspect["supported"])
                self.assertTrue(inspect["runner_available"])
                self.assertEqual(inspect["source_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                value = self.run_script(path, approval=inspect["source_sha256"])
                self.assertEqual(value["sandbox"], "development")
                self.assertEqual(value["fixture"]["initial_values"], [1337, 42, 1337])
                self.assertEqual(value["fixture"]["final_values"], [7331, 42, 7331])
                self.assertTrue(value["logs"])
                self.assertFalse(Path(f"/proc/{value['fixture']['pid']}").exists(), "fixture leaked")

    def test_full_source_change_invalidates_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, "engine.log('first');")
            approval = self.call("inspect-script", path)["source_sha256"]
            with path.open("a", encoding="utf-8") as source:
                source.write("// source changed\n")
            result = self.run_script(path, success=False, approval=approval)
            self.assertIn("digest", result["error"])

    def test_unimplemented_and_unknown_capabilities_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, "", grants=("mem.read", "net.fetch"))
            self.assertFalse(self.call("inspect-script", path)["supported"])
            self.assertIn("capability", self.run_script(path, success=False)["error"])
            path = self.script(directory, "", grants=("system.shell",))
            self.assertIn("unknown grant", self.call("inspect-script", path, success=False)["error"])

    def test_read_only_grant_denies_actual_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(
                directory,
                "engine.scanI32(1337); engine.writeI32(engine.results(1)[0], 7331);",
                grants=("mem.read",),
            )
            value = self.run_script(path, success=False)
            self.assertIn("authorization denied", value["error"])

    def test_address_outside_fixture_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, "engine.readI32('0x1');")
            self.assertIn("outside", self.run_script(path, success=False)["error"])

    def test_wrong_target_and_missing_fixture_option_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, "", match="com.example.other")
            self.assertFalse(self.call("inspect-script", path)["supported"])
            self.assertIn("match", self.run_script(path, success=False)["error"])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertIn("fixture", self.call("run", path, "--approve", digest, success=False)["error"])

    @unittest.skipIf(os.geteuid() == 0, "Nonroot failure check requires an unprivileged caller")
    def test_strict_is_default_and_never_falls_back(self):
        result = self.run_script(ROOT / "examples/demo.js", development=False, success=False)
        self.assertIn("sandbox", result["error"])
        self.assertIn("root", result["error"])

    def test_infinite_loop_is_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, "while (true) {}")
            start = time.monotonic()
            value = self.run_script(path, success=False)
            self.assertLess(time.monotonic() - start, 7)
            self.assertIn("deadline", value["error"])

    def test_async_never_reports_false_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.script(directory, "Promise.reject(new Error('unhandled'));")
            self.assertIn("async", self.run_script(path, success=False)["error"].lower())

    def test_invalid_utf8_large_sources_and_fifo_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.js"
            path.write_bytes(b"\xff")
            self.assertIn("UTF-8", self.call("inspect-script", path, success=False)["error"])
            path.write_bytes(b" " * (48 * 1024 + 1))
            self.assertIn("48 KiB", self.call("inspect-script", path, success=False)["error"])
            fifo = Path(directory) / "blocked.js"
            os.mkfifo(fifo)
            self.assertIn("regular file", self.call("inspect-script", fifo, success=False)["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
