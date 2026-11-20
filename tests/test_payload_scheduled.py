# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Guard against scheduled lanes silently running no tests or a stale artifact."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("payload_driver", Path(__file__).with_name("run-payload-scheduled.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class ScheduledDriverTests(unittest.TestCase):
    def test_bad_selection_is_an_error(self):
        case = {"package": "praxis-tests-integration", "test": "a::scheduled_case", "adapters": ["pingora"]}
        for manifest, adapter, requested in [
            ([], "pingora", []),
            ([case], "hyper", []),
            ([case], "pingora", ["typo"]),
            ([case, case], "pingora", []),
        ]:
            with self.subTest(manifest=manifest, adapter=adapter, requested=requested):
                with self.assertRaises(ValueError):
                    DRIVER.selected_cases(manifest, adapter, requested)
        self.assertEqual(DRIVER.selected_cases([case], "pingora", [case["test"]]), [case])

    def test_invalid_entries_cannot_disappear_during_adapter_filtering(self):
        valid = {"package": "praxis-tests-integration", "test": "a::ok", "adapters": ["pingora", "hyper"]}
        invalid = [
            {"package": "praxis-tests-integration", "test": "b::typo", "adapters": ["pingorra"]},
            {"package": "praxis-tests-integration", "test": "b::empty", "adapters": []},
            {"package": "praxis-tests-integration", "test": "b::duplicate", "adapters": ["hyper", "hyper"]},
            {"package": "praxis-tests-integration", "test": "b::nonstr", "adapters": ["hyper", 42]},
            {"package": "praxis-tests-integration", "test": "b::string", "adapters": "hyper"},
            {"package": "wrong-package", "test": "b::hidden", "adapters": ["hyper"]},
            {"package": "praxis-tests-integration", "test": "", "adapters": ["hyper"]},
            {"package": "praxis-tests-integration", "test": " b::spaces", "adapters": ["hyper"]},
            {"package": "praxis-tests-integration", "test": "b::missing"},
            {"package": "praxis-tests-resilience", "test": "a::ok", "adapters": ["hyper"]},
        ]
        for entry in invalid:
            for adapter in ("pingora", "hyper"):
                with self.subTest(entry=entry, adapter=adapter), self.assertRaises(ValueError):
                    DRIVER.selected_cases([valid, entry], adapter, [])
        for adapter in ("pingora", "hyper"):
            self.assertEqual(DRIVER.selected_cases([valid], adapter, []), [valid])
        for manifest in ({}, [None], ["not a case"]):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                DRIVER.selected_cases(manifest, "pingora", [])
        with self.assertRaises(ValueError):
            DRIVER.selected_cases([valid], "pingora", ["a::ok", "a::ok"])
        with self.assertRaises(ValueError):
            DRIVER.selected_cases([valid], "pingorra", [])

    def test_artifact_must_be_the_unique_test_suite(self):
        def artifact(name, executable):
            return json.dumps({"reason": "compiler-artifact", "target": {"name": name}, "executable": executable})

        selected = artifact("suite", "/exact/suite-hash")
        output = "Compiling a dependency\n" + artifact("praxis", "/different/praxis") + "\n" + selected
        self.assertEqual(DRIVER.executable_from_build(output), "/exact/suite-hash")
        for bad in ["", artifact("praxis", "/wrong"), selected + "\n" + artifact("suite", "/second")]:
            with self.subTest(output=bad), self.assertRaises(RuntimeError):
                DRIVER.executable_from_build(bad)

    def test_invalid_selector_replaces_previous_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "results.json"
            report.write_text(json.dumps({"status": "passed", "revision": "old"}))
            result = subprocess.run(
                [sys.executable, "-B", str(Path(DRIVER.__file__)), "--adapter", "pingora",
                 "--case", "does::not::exist", "--output", directory],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            recorded = json.loads(report.read_text())
            self.assertEqual(recorded["status"], "failed")
            self.assertIn("unknown selectors", recorded["error"])
            self.assertEqual(recorded["cases"], [])

    def test_build_list_and_runtime_outcomes_are_recorded(self):
        manifest = json.loads((DRIVER.ROOT / "tests/payload-scheduled.json").read_text())
        selector = next(case["test"] for case in manifest if "pingora" in case["adapters"])
        for failure_call in (None, 1, 2, 3, 4):
            for error_type in ((None,) if failure_call is None else (RuntimeError, KeyboardInterrupt)):
                with self.subTest(failure_call=failure_call, error_type=error_type):
                    with tempfile.TemporaryDirectory() as directory:
                        calls = []

                        def fake_run(command, log, env, timeout, *, contained=False):
                            calls.append((command, contained))
                            if len(calls) == failure_call:
                                raise error_type("injected failure")
                            if len(calls) == 2:
                                return json.dumps({"reason": "compiler-artifact", "target": {"name": "suite"},
                                                   "executable": "/exact/suite"})
                            if len(calls) == 3:
                                return f"{selector}: test\n"
                            if len(calls) == 4:
                                return "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
                            return ""

                        argv = ["run-payload-scheduled.py", "--adapter", "pingora", "--case", selector,
                                "--output", directory]
                        with mock.patch.object(sys, "argv", argv), mock.patch.object(DRIVER, "run", fake_run):
                            if error_type is None:
                                DRIVER.main()
                            else:
                                with self.assertRaises(error_type):
                                    DRIVER.main()
                        recorded = json.loads((Path(directory) / "results.json").read_text())
                        status = "passed" if error_type is None else (
                            "interrupted" if error_type is KeyboardInterrupt else "failed")
                        self.assertEqual(recorded["status"], status)
                        if error_type is not None:
                            self.assertIn(error_type.__name__, recorded["error"])
                            self.assertIn("injected failure", recorded["error"])
                        if failure_call is None or failure_call == 4:
                            self.assertEqual(recorded["cases"][0]["result"], status)
                        else:
                            self.assertEqual(recorded["cases"], [])
                        if failure_call is None:
                            self.assertEqual(recorded["expected_cases"], 1)
                            self.assertEqual(calls[2][0][-1], "--list")
                            self.assertIn("--exact", calls[2][0])
                            self.assertTrue(calls[3][1], "actual test must be contained")

    def test_scheduled_child_inherits_runtime_containment(self):
        script = ("import json,resource; print(json.dumps(["
                  "resource.getrlimit(resource.RLIMIT_AS),"
                  "resource.getrlimit(resource.RLIMIT_FSIZE)]))")
        with tempfile.TemporaryDirectory() as directory:
            output = DRIVER.run([sys.executable, "-c", script],
                                Path(directory) / "limits.log", os.environ.copy(), 10,
                                contained=True)
        address, files = json.loads(output)
        for actual, maximum in ((address, 8_589_934_592), (files, 20_971_520)):
            self.assertGreater(actual[0], 0)
            self.assertLessEqual(actual[0], maximum)
            self.assertEqual(actual[0], actual[1])

    def test_deadline_terminates_a_real_test_process(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.TimeoutExpired):
                DRIVER.run([sys.executable, "-c", "import time; time.sleep(60)"],
                           Path(directory) / "deadline.log", os.environ.copy(), 0.1,
                           contained=True)


if __name__ == "__main__":
    unittest.main()
