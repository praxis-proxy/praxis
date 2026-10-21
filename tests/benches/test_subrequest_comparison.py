#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Check driver modes and comparison guards without compiling Rust workloads."""

import contextlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "subrequest_comparison", Path(__file__).with_name("subrequest-comparison.py")
)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class DriverTests(unittest.TestCase):
    """Exercise argument validation, matrix execution, and historical invariants."""

    def test_partial_comparison_and_unpaired_completion_are_rejected(self):
        """Invalid modes must fail before resolving refs or starting a build."""
        for arguments in (["--base", "base"], ["--before", "before"],
                          ["--completion-parent", "parent"], ["--base", ""],
                          ["--base", "", "--before", ""]):
            with self.subTest(arguments=arguments), mock.patch.object(
                sys, "argv", ["driver", "--candidate", "candidate", "--output", "output", *arguments]
            ), mock.patch.object(DRIVER, "output") as command, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as failure:
                    DRIVER.main()
                self.assertEqual(failure.exception.code, 2)
                command.assert_not_called()

    def test_changed_locked_dependency_is_rejected(self):
        """Historical comparisons must not silently measure different dependencies."""
        self.check_historical_guard("2.0.0", "1.0.0", "", "", "same locked package versions")

    def test_changed_compiler_profile_is_rejected(self):
        """Matching dependencies do not permit different compiler settings."""
        self.check_historical_guard("1.0.0", "1.0.0", "[profile.release]\nlto = true\n",
                                    "[profile.release]\nlto = false\n", "identical compiler profiles")

    def check_historical_guard(self, current_version, old_version, current_profile, old_profile, error):
        """Let the real preparation checks inspect different fixture trees."""
        with tempfile.TemporaryDirectory() as scratch:
            repository, historical = Path(scratch) / "current", Path(scratch) / "historical"
            for tree, version, profile in ((repository, current_version, current_profile),
                                           (historical, old_version, old_profile)):
                tree.mkdir()
                (tree / "Cargo.lock").write_text(
                    f'[[package]]\nname = "dependency"\nversion = "{version}"\nsource = "registry+test"\n'
                )
                (tree / "Cargo.toml").write_text(profile)
            with mock.patch.object(DRIVER.subprocess, "run"), self.assertRaisesRegex(RuntimeError, error):
                DRIVER.prepare_tree(repository, historical, "historical")

    def test_candidate_mode_runs_every_cell_without_historical_refs(self):
        """An unrelated PR validates all workloads without resolving old snapshots."""
        self.check_mode(comparison=False)

    def test_comparison_mode_retains_three_complete_matrices(self):
        """Explicit references still produce the full three-revision comparison."""
        self.check_mode(comparison=True)

    def check_mode(self, comparison):
        """Run real orchestration and measurement loops with fake compiled binaries."""
        revisions = {"base": "a" * 40, "before": "b" * 40, "candidate": "c" * 40}
        labels = ("base", "before", "candidate") if comparison else ("candidate",)
        with tempfile.TemporaryDirectory() as scratch:
            repository, destination = Path(scratch), Path(scratch) / "results"
            (repository / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "stable"\n')
            arguments = ["driver", "--candidate", "candidate", "--output", str(destination)]
            if comparison:
                arguments += ["--base", "base", "--before", "before"]

            def command_output(command, cwd):
                """Resolve fixture revisions while retaining the real CLI flow."""
                if command == ["git", "rev-parse", "--show-toplevel"]:
                    return str(repository)
                if command == ["git", "rev-parse", "HEAD"]:
                    return revisions["candidate"]
                if command == ["rustc", "-Vv"]:
                    return "fixture rustc"
                return revisions[command[-1].removesuffix("^{commit}")]

            def measurement(command, **kwargs):
                """Return the requested cell's result in the workload's JSON format."""
                options = dict(zip(command[1::2], command[2::2]))
                return json.dumps(dict(mode=options["--mode"], protocol=options["--protocol"],
                                       headers=int(options["--headers"]), attempts=int(options["--attempts"]),
                                       sample_ns_per_call=[100, 110, 120], total_calls=2,
                                       allocations=4, bytes=128))

            with mock.patch.object(sys, "argv", arguments), mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(DRIVER.platform, "platform", return_value="fixture platform"), \
                    mock.patch.object(DRIVER, "output", side_effect=command_output) as commands, \
                    mock.patch.object(DRIVER, "prepare_tree") as prepare, \
                    mock.patch.object(DRIVER, "build", return_value=Path("fixture-binary")) as build, \
                    mock.patch.object(DRIVER.subprocess, "check_output", side_effect=measurement), \
                    contextlib.redirect_stdout(io.StringIO()):
                DRIVER.main()
            self.assertEqual([call.args[2] for call in prepare.call_args_list],
                             [revisions[label] for label in labels])
            self.assertEqual(build.call_count, len(labels) * 2)
            resolved = [call.args[0][-1] for call in commands.call_args_list
                        if "--verify" in call.args[0]]
            self.assertEqual(resolved, [f"{label}^{{commit}}" for label in labels])
            metadata = json.loads((destination / "metadata.json").read_text())
            self.assertEqual(metadata["mode"], "comparison" if comparison else "candidate-validation")
            self.assertEqual(metadata["revisions"], {label: revisions[label] for label in labels})
            records = [json.loads(line) for line in (destination / "results.jsonl").read_text().splitlines()]
            self.assertEqual(len(records), len(labels) * 16)
            actual = {(row["revision"], row["protocol"], row["headers"], row["attempts"], row["mode"])
                      for row in records}
            expected = set(itertools.product(labels, ("h1", "h2"), (16, 64), (1, 2), ("timing", "allocations")))
            self.assertEqual(actual, expected)
            summary = (destination / "summary.md").read_text()
            self.assertIn("across all three revisions" if comparison else "Candidate workload validation only", summary)


if __name__ == "__main__":
    unittest.main()
