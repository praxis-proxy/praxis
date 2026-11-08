#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
"""Run every scheduled payload selector once, with a matching optimized proxy."""

import argparse
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("praxis-tests-integration", "praxis-tests-resilience")
ADAPTERS = frozenset(("pingora", "hyper"))


def validate_manifest(manifest):
    """Validate every entry before any adapter-specific filtering."""
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("scheduled manifest must be a nonempty list")
    seen = set()
    for case in manifest:
        if not isinstance(case, dict):
            raise ValueError("scheduled case must be an object")
        package, test, adapters = case.get("package"), case.get("test"), case.get("adapters")
        if package not in PACKAGES:
            raise ValueError(f"unsupported scheduled package: {package!r}")
        if not isinstance(test, str) or not test or test != test.strip():
            raise ValueError(f"invalid scheduled selector: {test!r}")
        if test in seen:
            raise ValueError(f"duplicate or ambiguous scheduled selector: {test}")
        seen.add(test)
        if (not isinstance(adapters, list) or not adapters
                or any(not isinstance(item, str) or item not in ADAPTERS for item in adapters)
                or len(adapters) != len(set(adapters))):
            raise ValueError(f"invalid adapters for {test}: {adapters!r}")


def selected_cases(manifest, adapter, requested):
    """Refuse typos, duplicate selectors, and an empty execution lane."""
    validate_manifest(manifest)
    if adapter not in ADAPTERS:
        raise ValueError(f"unknown adapter: {adapter!r}")
    if len(requested) != len(set(requested)):
        raise ValueError("duplicate requested selector")
    cases = [case for case in manifest if adapter in case["adapters"]]
    available = {case["test"] for case in cases}
    missing = set(requested) - available
    if missing:
        raise ValueError(f"unknown selectors for {adapter}: {sorted(missing)}")
    if requested:
        cases = [case for case in cases if case["test"] in requested]
    if not cases:
        raise ValueError("scheduled lane must select supported test packages")
    return cases


def contain_test_process():
    """Contain a scheduled fixture; these are runner limits, not proxy policy."""
    address_space = 8_589_934_592  # 8 GiB, including mapped address space.
    output_file = 20_971_520  # 20 MiB per output file, enforced during writes.
    for kind, desired in ((resource.RLIMIT_AS, address_space), (resource.RLIMIT_FSIZE, output_file)):
        _, hard = resource.getrlimit(kind)
        bound = desired if hard == resource.RLIM_INFINITY else min(desired, hard)
        resource.setrlimit(kind, (bound, bound))


def kill_group(child):
    """Remove fixture descendants even if the group leader already exited."""
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run(command, log, env, timeout, *, contained=False):
    """Keep output on disk, enforce a deadline, and expose failures verbatim."""
    print("+", " ".join(map(str, command)), flush=True)
    with log.open("w") as output:
        child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True,
                                 preexec_fn=contain_test_process if contained else None)
        try:
            code = child.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            # Kill the entire fixture group, including proxies and backends.
            # Killing only the test executable bypasses its RAII teardown.
            kill_group(child)
            child.wait()
            raise
        finally:
            if contained:
                kill_group(child)
    if code:
        with log.open("rb") as output:
            output.seek(max(0, log.stat().st_size - 65_536))
            print(output.read().decode(errors="replace"), file=sys.stderr)
        raise RuntimeError(f"command exited {code}; see {log}")
    if log.stat().st_size > 20_971_520:
        raise RuntimeError(f"command output exceeded the 20 MiB observation budget: {log}")
    return log.read_text()


def executable_from_build(output):
    """Take the exact Cargo artifact rather than guessing a hashed filename."""
    executables = set()
    for line in output.splitlines():
        if not line.startswith("{"):
            continue
        item = json.loads(line)
        if (item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "suite"
                and item.get("executable")):
            executables.add(item["executable"])
    if len(executables) != 1:
        raise RuntimeError(f"expected one suite executable, found {sorted(executables)}")
    return executables.pop()


def describe_error(error):
    """Include the exception type and any message in the results artifact."""
    detail = str(error)
    return f"{type(error).__name__}: {detail}" if detail else type(error).__name__


def run_cases(args, output, report, results):
    """Validate, build and run the selected cases, recording completed work."""
    if not sys.platform.startswith("linux"):
        raise RuntimeError("the resource lane requires Linux procfs")
    cases = selected_cases(json.loads((ROOT / "tests/payload-scheduled.json").read_text()),
                           args.adapter, args.case)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    results.update(revision=revision, status="building", expected_cases=len(cases))
    results["dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True))
    report.write_text(json.dumps(results, indent=2) + "\n")
    target = ROOT / "target" if args.adapter == "pingora" else ROOT / "target/hyper"
    env = os.environ.copy()
    env.setdefault("CARGO_BUILD_JOBS", "4")
    proxy_features = f"{args.adapter},config-reload,admin-api,policy-builtins,cloud-events-filter"
    common = ["--locked", "--profile", args.profile, "--target-dir", str(target), "--no-default-features"]
    run(["cargo", "build", *common, "-p", "praxis-proxy", "--features", proxy_features],
        output / "build-proxy.log", env, 3600)
    env["PRAXIS_BIN"] = str(target / args.profile / "praxis")
    suites = {}
    for package in dict.fromkeys(case["package"] for case in cases):
        features = f"{args.adapter},policy-builtins"
        if package == "praxis-tests-integration":
            features += ",cloud-events-filter"
        build = run(["cargo", "test", *common, "-p", package, "--features", features,
                     "--test", "suite", "--no-run", "--message-format=json"],
                    output / f"build-{package}.log", env, 3600)
        suites[package] = executable_from_build(build)
    results.update(status="running", proxy_features=proxy_features, praxis_bin=env["PRAXIS_BIN"])
    report.write_text(json.dumps(results, indent=2) + "\n")
    for index, case in enumerate(cases):
        command = [suites[case["package"]], case["test"], "--exact", "--ignored"]
        listed = run([*command, "--list"], output / f"{index:02d}-list.log", env, 30)
        matches = [line[:-6] for line in listed.splitlines() if line.endswith(": test")]
        if matches != [case["test"]]:
            raise RuntimeError(f"selector must match exactly one ignored test: {case}, got {matches}")
        started = time.monotonic()
        record = {**case, "result": "running"}
        results["cases"].append(record)
        try:
            text = run([*command, "--test-threads=1", "--nocapture"],
                       output / f"{index:02d}-test.log", env, 1800, contained=True)
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in text:
                raise RuntimeError(f"missing single-test completion proof: {case}")
            record["result"] = "passed"
        except KeyboardInterrupt as error:
            record.update(result="interrupted", error=describe_error(error))
            raise
        except Exception as error:
            record.update(result="failed", error=describe_error(error))
            raise
        finally:
            record["seconds"] = time.monotonic() - started
            report.write_text(json.dumps(results, indent=2) + "\n")
    results["status"] = "passed"
    report.write_text(json.dumps(results, indent=2) + "\n")
    print(f"Passed {len(results['cases'])} scheduled selectors; evidence: {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", choices=("pingora", "hyper"), default="pingora")
    parser.add_argument("--profile", choices=("profiling", "release"), default="profiling")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()
    output = (args.output or ROOT / "target" / f"payload-results-{args.adapter}").resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = output / "results.json"
    results = {"adapter": args.adapter, "profile": args.profile, "status": "initializing", "cases": []}
    try:
        # Replace any previous report before validation or a build can fail.
        report.write_text(json.dumps(results, indent=2) + "\n")
        run_cases(args, output, report, results)
    except KeyboardInterrupt as error:
        results.update(status="interrupted", error=describe_error(error))
        raise
    except Exception as error:
        results.update(status="failed", error=describe_error(error))
        raise
    finally:
        report.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
