#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Build identical subrequest workloads against three revisions on one CI runner.

Only peer construction is adapted for the pre-seam public API. All workloads,
compiler settings, and dependencies are otherwise identical. Backend processes
are outside the client's heap profiler. Timing uses separate, uninstrumented
release binaries; two attempts measure concurrent subrequests, not the hedge
scheduler. Measurements include the common harness validation overhead.
"""

import argparse
import itertools
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import tomllib


COMPLETION_PARENT = "3141d5b9a19fa1688cf0fcd26cd036d35918df6d"
COMPLETION_CANDIDATE = "e6f006bc64783fa63e4b0e284e3e55f583efd1b2"
COMPLETION_HARNESS_PATHS = {
    ".github/workflows/subrequest-benchmarks.yaml",
    "tests/benches/subrequest-comparison.py",
    "tests/benches/subrequest-benchmark.md",
}


LEGACY_PEER = '''// SPDX-License-Identifier: Apache-2.0
//! Baseline adapter for the pre-seam public peer type; setup is not measured.
use std::net::SocketAddr;
pub(crate) type BenchPeer = pingora_core::upstreams::peer::HttpPeer;
pub(crate) fn build_peer(address: SocketAddr, http2: bool) -> BenchPeer {
    let mut peer = BenchPeer::new(address.to_string(), false, String::new());
    let version = if http2 { 2 } else { 1 };
    peer.options.set_http_version(version, version);
    peer
}
'''


def output(command, cwd):
    """Read a command's output without invoking a shell."""
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def add_lock_dependency(lockfile, dependency):
    """Add an already locked package to the benchmark's dependency edges."""
    text = lockfile.read_text()
    start = text.index('name = "praxis-tests-benches"\n')
    end = text.index("\n[[package]]", start)
    package = text[start:end]
    before, dependencies = package.split("dependencies = [\n", 1)
    entries, after = dependencies.split("]", 1)
    lines = set(entries.splitlines())
    lines.add(f' "{dependency}",')
    replacement = before + "dependencies = [\n" + "\n".join(sorted(lines)) + "\n]" + after
    lockfile.write_text(text[:start] + replacement + text[end:])


def prepare_tree(repository, tree, revision):
    """Overlay the candidate workload without changing historical production code."""
    subprocess.run(["git", "worktree", "add", "--detach", str(tree), revision], cwd=repository, check=True)
    def package_versions(directory):
        lock = tomllib.loads((directory / "Cargo.lock").read_text())
        return {(package["name"], package["version"], package.get("source")) for package in lock["package"]}
    if package_versions(tree) != package_versions(repository):
        raise RuntimeError("comparison references must use the same locked package versions")
    source_profile = tomllib.loads((repository / "Cargo.toml").read_text()).get("profile", {})
    historical_profile = tomllib.loads((tree / "Cargo.toml").read_text()).get("profile", {})
    if source_profile != historical_profile:
        raise RuntimeError("comparison references must use identical compiler profiles")
    benches = tree / "tests/benches"
    for source in (repository / "tests/benches/benches").glob("subrequest_*.rs"):
        shutil.copy2(source, benches / "benches" / source.name)
    shutil.copy2(repository / "tests/benches/Cargo.toml", benches / "Cargo.toml")
    # Retain each revision's original workspace edges and locked versions.
    # The workload only reuses packages already present in all three locks.
    for dependency in ("bytes", "h2"):
        add_lock_dependency(tree / "Cargo.lock", dependency)
    if not (tree / "crates/core/src/egress/peer.rs").exists():
        (benches / "benches/subrequest_peer.rs").write_text(LEGACY_PEER)
        manifest = benches / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace(
            'praxis-core = { workspace = true, features = ["pingora"] }',
            'praxis-core = { workspace = true }', 1
        ).replace(
            "[dev-dependencies]\n", "[dev-dependencies]\npingora-core = { workspace = true }\n", 1
        ))
        add_lock_dependency(tree / "Cargo.lock", "quixotic-plecostomus-core")


def build(tree, label, mode, destination, environment):
    """Save a revision-specific binary before building the next revision."""
    command = ["cargo", "bench", "--no-run", "--locked", "-p", "praxis-tests-benches",
               "--bench", "subrequest_headers", "--message-format=json-render-diagnostics"]
    if mode == "allocations":
        command += ["--features", "dhat-heap"]
    executable = None
    with (destination / f"build-{label}-{mode}.jsonl").open("w") as log:
        process = subprocess.Popen(command, cwd=tree, env=environment, stdout=subprocess.PIPE, text=True)
        for line in process.stdout:
            log.write(line)
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("reason") == "compiler-message":
                print(message["message"].get("rendered", ""), end="", flush=True)
            if message.get("target", {}).get("name") == "subrequest_headers" and message.get("executable"):
                executable = message["executable"]
        if process.wait() != 0 or executable is None:
            raise RuntimeError(f"benchmark build failed: {label}/{mode}")
    binary = destination / f"{label}-{mode}"
    shutil.copy2(executable, binary)
    return binary


def measure(binaries, revisions, destination):
    """Rotate revision order across cases and retain every raw measurement."""
    cases = list(itertools.product(("h1", "h2"), (16, 64), (1, 2)))
    records = []
    with (destination / "results.jsonl").open("w") as results:
        for mode in ("timing", "allocations"):
            for index, (protocol, headers, attempts) in enumerate(cases):
                labels = list(revisions)
                offset = index % len(labels)
                for label in labels[offset:] + labels[:offset]:
                    command = [str(binaries[label, mode]), "--mode", mode, "--protocol", protocol,
                               "--headers", str(headers), "--attempts", str(attempts),
                               "--iterations", "1000" if mode == "timing" else "200", "--samples", "7"]
                    name = f"{label}-{mode}-{protocol}-{headers}-{attempts}"
                    with (destination / f"{name}.stderr").open("w") as errors:
                        raw = subprocess.check_output(command, cwd=destination, stderr=errors, text=True, timeout=300)
                    record = json.loads(raw)
                    record.update(revision=label, sha=revisions[label])
                    records.append(record)
                    results.write(json.dumps(record) + "\n")
                    results.flush()
                    print(json.dumps(record), flush=True)
    return records


def measure_completion(binaries, revisions, destination):
    """Compare the guard commit with its parent in four balanced ABBA/BAAB process blocks."""
    cases = list(itertools.product(("h1", "h2"), (16, 64), (1, 2)))
    rows = []
    with (destination / "completion-results.jsonl").open("w") as results:
        for block in range(4):
            offset = block % len(cases)
            for protocol, headers, attempts in cases[offset:] + cases[:offset]:
                medians = {"parent": [], "candidate": []}
                order = ("parent", "candidate", "candidate", "parent")
                if block % 2:
                    order = ("candidate", "parent", "parent", "candidate")
                for position, label in enumerate(order):
                    command = [str(binaries[label, "timing"]), "--mode", "timing",
                               "--protocol", protocol, "--headers", str(headers),
                               "--attempts", str(attempts), "--iterations", "1000", "--samples", "7"]
                    name = f"completion-{block}-{protocol}-{headers}-{attempts}-{position}-{label}"
                    with (destination / f"{name}.stderr").open("w") as errors:
                        raw = subprocess.check_output(command, cwd=destination, stderr=errors,
                                                      text=True, timeout=300)
                    record = json.loads(raw)
                    record.update(revision=label, sha=revisions[label], block=block, position=position)
                    print(json.dumps(record), flush=True)
                    results.write(json.dumps(record) + "\n")
                    results.flush()
                    medians[label].append(statistics.median(record["sample_ns_per_call"]))
                ratio = statistics.median(medians["candidate"]) / statistics.median(medians["parent"])
                rows.append(dict(protocol=protocol, headers=headers, attempts=attempts,
                                 block=block, candidate_parent_ratio=ratio))
    (destination / "completion-ratios.json").write_text(json.dumps(rows, indent=2) + "\n")
    summary = ["# Completion guard paired timing", "",
               "Pinned parent versus verified guard-equivalent harness head, four alternating ABBA/BAAB blocks per cell.",
               "Each process has its own warmup and seven contiguous timing samples.",
               "Each block ratio divides the median of two candidate process medians by",
               "the median of two parent process medians. Samples are not independent replicates.",
               "Ratios above 1 mean slower candidate amortized wall time; this is not a speed gate.", "",
               "| Protocol | Headers | Attempts | Four block ratios | Median ratio | Range |",
               "|---|---:|---:|---|---:|---|"]
    for protocol, headers, attempts in cases:
        ratios = [row["candidate_parent_ratio"] for row in rows
                  if (row["protocol"], row["headers"], row["attempts"]) == (protocol, headers, attempts)]
        values = ", ".join(f"{ratio:.4f}" for ratio in ratios)
        summary.append(f"| {protocol} | {headers} | {attempts} | {values} | "
                       f"{statistics.median(ratios):.4f} | {min(ratios):.4f}–{max(ratios):.4f} |")
    text = "\n".join(summary) + "\n"
    (destination / "completion-summary.md").write_text(text)
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary_file:
            summary_file.write(text)


def summarize(records, destination):
    """Present descriptive timing and allocation data without a noisy speed gate."""
    rows = ["# Subrequest performance comparison", "",
            "Same runner, compiler, dependencies, and workload across all three revisions.",
            "Timing is amortized wall time per completed subrequest, not tail latency.",
            "DHAT runs measure client allocations separately; their timing is not compared.",
            "Two attempts are concurrent executor calls, not the full hedge scheduler.", "",
            "| Revision | Protocol | Headers | Attempts | Mode | Measurement |",
            "|---|---|---:|---:|---|---|"]
    for record in records:
        if record["mode"] == "timing":
            samples = record["sample_ns_per_call"]
            value = f"median {statistics.median(samples):.1f} ns/call (range {min(samples):.1f}–{max(samples):.1f})"
        else:
            count = record["total_calls"]
            value = f'{record["allocations"] / count:.2f} allocations, {record["bytes"] / count:.1f} bytes/call'
        rows.append(f'| {record["revision"]} | {record["protocol"]} | {record["headers"]} | '
                    f'{record["attempts"]} | {record["mode"]} | {value} |')
    text = "\n".join(rows) + "\n"
    (destination / "summary.md").write_text(text)
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
            summary.write(text)


def main():
    """Build once per revision/mode, then execute the fixed case matrix."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("base", "before", "candidate", "output"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--completion-parent", help="Enable the pinned parent/guard timing investigation")
    args = parser.parse_args()
    repository = Path(output(["git", "rev-parse", "--show-toplevel"], Path.cwd()))
    revisions = {label: output(["git", "rev-parse", "--verify", "--end-of-options", f"{getattr(args, label)}^{{commit}}"], repository)
                 for label in ("base", "before", "candidate")}
    harness_sha = output(["git", "rev-parse", "HEAD"], repository)
    if harness_sha != revisions["candidate"]:
        raise RuntimeError("checkout must be the exact candidate commit")
    if args.completion_parent:
        parent = output(["git", "rev-parse", "--verify", "--end-of-options",
                         f"{args.completion_parent}^{{commit}}"], repository)
        if parent != COMPLETION_PARENT:
            raise RuntimeError("completion investigation requires the pinned parent commit")
        changed = subprocess.check_output(
            ["git", "diff", "--no-renames", "--name-only", "-z", COMPLETION_CANDIDATE, harness_sha, "--"],
            cwd=repository,
        ).decode().split("\0")
        if set(filter(None, changed)) - COMPLETION_HARNESS_PATHS:
            raise RuntimeError("completion candidate may differ from the guard commit only in harness files")
    destination = Path(args.output).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    metadata = {"harness_sha": harness_sha, "completion_parent": parent if args.completion_parent else None,
                "completion_runtime_equivalent": COMPLETION_CANDIDATE if args.completion_parent else None,
                "revisions": revisions, "platform": platform.platform(),
                "rustc": output(["rustc", "-Vv"], repository),
                "cpu": Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else platform.processor()}
    (destination / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    toolchain = tomllib.loads((repository / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    environment = dict(os.environ, CARGO_TARGET_DIR=str(repository / "target"), RUSTUP_TOOLCHAIN=toolchain)
    binaries = {}
    with tempfile.TemporaryDirectory(prefix="praxis-subrequest-") as scratch:
        for label, revision in revisions.items():
            tree = Path(scratch) / label
            prepare_tree(repository, tree, revision)
            for mode in ("timing", "allocations"):
                binaries[label, mode] = build(tree, label, mode, destination, environment)
        summarize(measure(binaries, revisions, destination), destination)
        if args.completion_parent:
            parent_tree = Path(scratch) / "parent"
            prepare_tree(repository, parent_tree, parent)
            binaries["parent", "timing"] = build(parent_tree, "parent", "timing", destination, environment)
            measure_completion(binaries, dict(parent=parent, candidate=revisions["candidate"]), destination)


if __name__ == "__main__":
    main()
