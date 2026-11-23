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

    def test_completion_matrix_balances_process_positions_and_ratios(self):
        """The paired matrix keeps process order and process-median ratios."""
        cases = list(itertools.product(("h1", "h2"), (16, 64), (1, 2)))
        revisions = {"parent": "p" * 40, "candidate": "c" * 40}
        binaries = {(label, "timing"): Path(f"{label}-timing") for label in revisions}
        commands = []

        def measurement(command, **kwargs):
            """Return nonuniform samples whose pooled median gives another ratio."""
            call_index = len(commands)
            commands.append((command, kwargs))
            block, within_block = divmod(call_index, 32)
            case_position, position = divmod(within_block, 4)
            case_index = (case_position + block) % len(cases)
            options = dict(zip(command[1::2], command[2::2]))
            label = Path(command[0]).name.removesuffix("-timing")
            # Each label occurs twice per cell. Position determines its first or second run.
            if label == "parent":
                low, high = 10 + case_index, 30 + case_index
            else:
                low, high = 50 + case_index + 10 * block, 70 + case_index + 10 * block
            if (position in (0, 1)) == (label == ("parent" if block % 2 == 0 else "candidate")):
                samples = [1, 1, 1, low, 1000, 1000, 1000]
            else:
                samples = [high - 10] * 3 + [high] + [high + 10] * 3
            return json.dumps(dict(mode=options["--mode"], protocol=options["--protocol"],
                                   headers=int(options["--headers"]), attempts=int(options["--attempts"]),
                                   sample_ns_per_call=samples))

        with tempfile.TemporaryDirectory() as scratch:
            destination = Path(scratch)
            with mock.patch.object(DRIVER.subprocess, "check_output", side_effect=measurement), \
                    mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()):
                DRIVER.measure_completion(binaries, revisions, destination)
            self.assertEqual(len(commands), 128)
            records = [json.loads(line) for line in (destination / "completion-results.jsonl").read_text().splitlines()]
            self.assertEqual(len(records), 128)
            for index, ((command, kwargs), record) in enumerate(zip(commands, records)):
                block, within_block = divmod(index, 32)
                case_position, position = divmod(within_block, 4)
                protocol, headers, attempts = cases[(case_position + block) % len(cases)]
                order = ("parent", "candidate", "candidate", "parent") if block % 2 == 0 else \
                    ("candidate", "parent", "parent", "candidate")
                label = order[position]
                options = dict(zip(command[1::2], command[2::2]))
                self.assertEqual(Path(command[0]), binaries[label, "timing"])
                self.assertEqual(options, {"--mode": "timing", "--protocol": protocol,
                                           "--headers": str(headers), "--attempts": str(attempts),
                                           "--iterations": "1000", "--samples": "7"})
                self.assertEqual(kwargs["cwd"], destination)
                self.assertEqual(kwargs["timeout"], 300)
                self.assertEqual((record["revision"], record["sha"], record["block"], record["position"]),
                                 (label, revisions[label], block, position))
                self.assertEqual((record["protocol"], record["headers"], record["attempts"]),
                                 (protocol, headers, attempts))
                self.assertEqual(len(record["sample_ns_per_call"]), 7)

            ratio_rows = json.loads((destination / "completion-ratios.json").read_text())
            self.assertEqual(len(ratio_rows), 32)
            summary = (destination / "completion-summary.md").read_text()
            for case_index, (protocol, headers, attempts) in enumerate(cases):
                expected = [(60 + case_index + 10 * block) / (20 + case_index) for block in range(4)]
                for block, ratio in enumerate(expected):
                    row = ratio_rows[block * 8 + (case_index - block) % 8]
                    self.assertEqual((row["protocol"], row["headers"], row["attempts"], row["block"]),
                                     (protocol, headers, attempts, block))
                    self.assertAlmostEqual(row["candidate_parent_ratio"], ratio)
                middle = (expected[1] + expected[2]) / 2
                values = ", ".join(f"{ratio:.4f}" for ratio in expected)
                self.assertIn(f"| {protocol} | {headers} | {attempts} | {values} | "
                              f"{middle:.4f} | {expected[0]:.4f}–{expected[-1]:.4f} |", summary)

    def run_completion_fixture(self, changed, parent=DRIVER.COMPLETION_PARENT):
        """Run the real completion guard with fake revisions and no builds."""
        revisions = {"base": "a" * 40, "before": "b" * 40, "candidate": "h" * 40,
                     "parent": parent}
        with tempfile.TemporaryDirectory() as scratch:
            repository, destination = Path(scratch), Path(scratch) / "results"
            (repository / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "stable"\n')
            arguments = ["driver", "--candidate", "candidate", "--base", "base", "--before", "before",
                         "--completion-parent", "parent", "--output", str(destination)]

            def command_output(command, cwd):
                """Resolve the fixture references without invoking git or rustc."""
                if command == ["git", "rev-parse", "--show-toplevel"]:
                    return str(repository)
                if command == ["git", "rev-parse", "HEAD"]:
                    return revisions["candidate"]
                if command == ["rustc", "-Vv"]:
                    return "fixture rustc"
                return revisions[command[-1].removesuffix("^{commit}")]

            def fake_build(tree, label, mode, destination, environment):
                """Provide a distinct path for each revision and mode."""
                return Path(f"{label}-{mode}")

            with mock.patch.object(sys, "argv", arguments), mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(DRIVER, "output", side_effect=command_output), \
                    mock.patch.object(DRIVER.subprocess, "check_output", return_value=changed) as diff, \
                    mock.patch.object(DRIVER, "prepare_tree") as prepare, \
                    mock.patch.object(DRIVER, "build", side_effect=fake_build) as build, \
                    mock.patch.object(DRIVER, "measure", return_value=[]) as measure, \
                    mock.patch.object(DRIVER, "measure_completion") as completion, \
                    contextlib.redirect_stdout(io.StringIO()):
                try:
                    DRIVER.main()
                except RuntimeError as failure:
                    error = str(failure)
                else:
                    error = None
            metadata = json.loads((destination / "metadata.json").read_text()) if destination.exists() else None
            return dict(error=error, destination_exists=destination.exists(), metadata=metadata,
                        diff=diff, prepare=prepare, build=build, measure=measure, completion=completion)

    def test_completion_guard_rejects_non_harness_changes(self):
        """A permitted file does not hide production or workload changes."""
        allowed = b"tests/benches/test_subrequest_comparison.py\0"
        for forbidden in (b"crates/core/src/circuit.rs",
                          b"tests/benches/benches/subrequest_headers.rs"):
            with self.subTest(forbidden=forbidden):
                result = self.run_completion_fixture(allowed + forbidden + b"\0")
                self.assertIn("only in harness files", result["error"])
                self.assertFalse(result["destination_exists"])
                result["diff"].assert_called_once()
                result["prepare"].assert_not_called()
                result["build"].assert_not_called()

    def test_completion_guard_requires_pinned_parent(self):
        """The optional comparison refuses a different resolved parent."""
        result = self.run_completion_fixture(b"", parent="x" * 40)
        self.assertIn("pinned parent commit", result["error"])
        self.assertFalse(result["destination_exists"])
        result["diff"].assert_not_called()
        result["prepare"].assert_not_called()
        result["build"].assert_not_called()

    def test_completion_mode_accepts_harness_only_changes(self):
        """Valid completion modes retain comparison work and reuse timing binaries."""
        for changed in (b"", b"tests/benches/test_subrequest_comparison.py\0"
                        b"tests/benches/subrequest-comparison.py\0"):
            with self.subTest(changed=changed):
                result = self.run_completion_fixture(changed)
                self.assertIsNone(result["error"])
                self.assertEqual(result["metadata"]["completion_parent"], DRIVER.COMPLETION_PARENT)
                self.assertEqual(result["metadata"]["completion_runtime_equivalent"], DRIVER.COMPLETION_CANDIDATE)
                self.assertEqual(result["metadata"]["harness_sha"], "h" * 40)
                self.assertNotEqual(result["metadata"]["harness_sha"], DRIVER.COMPLETION_CANDIDATE)
                self.assertEqual(result["metadata"]["mode"], "comparison")
                self.assertEqual([call.args[2] for call in result["prepare"].call_args_list],
                                 ["a" * 40, "b" * 40, "h" * 40, DRIVER.COMPLETION_PARENT])
                self.assertEqual([(call.args[1], call.args[2]) for call in result["build"].call_args_list],
                                 [(label, mode) for label in ("base", "before", "candidate")
                                  for mode in ("timing", "allocations")] + [("parent", "timing")])
                result["measure"].assert_called_once()
                completion = result["completion"]
                completion.assert_called_once()
                binaries, revisions = completion.call_args.args[:2]
                self.assertEqual(binaries["candidate", "timing"], Path("candidate-timing"))
                self.assertEqual(binaries["parent", "timing"], Path("parent-timing"))
                self.assertEqual(revisions, {"parent": DRIVER.COMPLETION_PARENT, "candidate": "h" * 40})


if __name__ == "__main__":
    unittest.main()
