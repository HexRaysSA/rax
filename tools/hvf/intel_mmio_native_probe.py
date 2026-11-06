#!/usr/bin/env python3
"""Build and execute the actual RAX Intel HVF MMIO and MSR guest controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

import intel_mmio_prepared as prepared

EXPECTED_CASES = 952


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--compile-only", action="store_true",
                       help="cross-build and sign; do not claim native guest execution")
    modes.add_argument("--execute-prepared", type=Path,
                       help="verify and execute the prepared report from this workflow run")
    parser.add_argument("--export-guest", action="store_true",
                        help="with --compile-only, retain the signed consumer in the report")
    parser.add_argument("--opt-level", choices=("0", "1"), default="1")
    parser.add_argument("--profile", choices=("mmio", "coherence", "combined"), default="mmio")
    args = parser.parse_args()
    expected_cases = {"mmio": EXPECTED_CASES, "coherence": 16, "combined": EXPECTED_CASES + 16}[args.profile]
    if args.export_guest and not args.compile_only:
        parser.error("--export-guest requires --compile-only")
    root = args.repo.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    consumer = Path(__file__).with_name("intel_mmio_native_guest.rs")
    result = {"scope": __doc__, "compile_only": args.compile_only,
              "export_guest": args.export_guest, "expected_cases": expected_cases,
              "profile": args.profile, "commands": [],
              "success": False, "guest_execution_qualified": False, "error": None,
              "consumer_sha256": prepared.digest(prepared.consumer_inputs(root)),
              "consumer_sources": prepared.consumer_inputs(root),
              "script_sha256": sha(Path(__file__)),
              "support_sha256": sha(Path(prepared.__file__)),
              "github": {name: os.environ.get(name) for name in (
                  "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}}
    inputs = prepared.engine_inputs(root)
    (output / "engine-source.json").write_text(json.dumps(inputs, indent=2) + "\n")
    result["engine_source_digest"] = hashlib.sha256(
        json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("RAX_") or name in {
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER"}:
            environment.pop(name)
    scratch = None

    def guest_command(executable):
        output_path = str(output / "observations.jsonl")
        if args.profile == "coherence":
            return [str(executable), "--coherence", output_path]
        suffix = ["--with-coherence"] if args.profile == "combined" else []
        return [str(executable), output_path, *suffix]

    def run(label, command, timeout=60):
        return prepared.execute(label, command, root=root, environment=environment,
                                output=output, result=result, timeout=timeout)

    try:
        executable = None
        if args.execute_prepared:
            executable, description = prepared.admit(
                args.execute_prepared, inputs, result["consumer_sha256"],
                result["script_sha256"], expected_cases)
            result["prepared"] = description
            result["executable_sha256"] = description["executable_sha256"]
            # Artifact transport does not retain executable permission.
            executable.chmod(executable.stat().st_mode | 0o100)
            run("verify-signature", ["codesign", "--verify", "--strict", str(executable)])
        run("os", ["sw_vers"])
        run("kernel", ["uname", "-a"])
        run("sdk", ["xcrun", "--sdk", "macosx", "--show-sdk-version"])
        if not args.execute_prepared:
            run("rustc", ["rustc", "+stable", "-vV"])
        run("commit", ["git", "rev-parse", "HEAD"])
        if not args.compile_only:
            run("availability", ["python3", str(root / "tools/hvf/native_intel_availability.py"),
                                 "--output", str(output / "availability")], timeout=300)
            available = json.loads((output / "availability/result.json").read_text())
            assert available["hvf_vm_available"]
            assert available["probe"]["native_intel_process"]
            result["native_host"] = available["probe"]
        if not args.execute_prepared:
            with tempfile.TemporaryDirectory(prefix="rax-hvf-intel-mmio-",
                                             dir=os.environ.get("RUNNER_TEMP") or "/tmp") as tmp:
                scratch = Path(tmp)
                target = scratch / "build"
                environment.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2",
                                   CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
                                   CARGO_PROFILE_DEV_OPT_LEVEL=args.opt_level,
                                   CARGO_PROFILE_DEV_OVERFLOW_CHECKS="true",
                                   CARGO_PROFILE_DEV_DEBUG_ASSERTIONS="true")
                result["build_environment"] = {name: environment[name] for name in (
                    "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG",
                    "CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_DEV_OVERFLOW_CHECKS",
                    "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS")}
                triple = "x86_64-apple-darwin"
                messages = run("library", ["cargo", "+stable", "build", "--locked",
                                           "--no-default-features", "--features",
                                           "x86_64-suite,smir-jit,hvf,debug", "--target", triple,
                                           "--lib", "--message-format=json"], timeout=1800)
                artifacts = {}
                for line in messages.read_text().splitlines():
                    row = json.loads(line)
                    if row.get("reason") == "compiler-artifact" and row["target"]["name"] in {
                            "rax", "vm_memory"}:
                        for filename in row["filenames"]:
                            if filename.endswith(".rlib"):
                                artifacts[row["target"]["name"]] = Path(filename)
                assert set(artifacts) == {"rax", "vm_memory"}, artifacts
                result["libraries"] = {name: {"sha256": sha(path), "bytes": path.stat().st_size}
                                       for name, path in artifacts.items()}
                executable = scratch / "native-mmio"
                run("consumer-build", ["rustc", "+stable", "--edition=2024", "--target", triple,
                                       str(consumer), "--extern", "rax=" + str(artifacts["rax"]),
                                       "--extern", "vm_memory=" + str(artifacts["vm_memory"]),
                                       "-L", "dependency=" + str(target / triple / "debug/deps"),
                                       "-L", "dependency=" + str(target / "debug/deps"),
                                       "-o", str(executable)], timeout=180)
                entitlements = scratch / "entitlements.plist"
                entitlements.write_bytes(plistlib.dumps({"com.apple.security.hypervisor": True}))
                run("sign", ["codesign", "--force", "--sign", "-", "--entitlements",
                             str(entitlements), "--timestamp=none", str(executable)])
                run("verify-signature", ["codesign", "--verify", "--strict", str(executable)])
                result["executable_sha256"] = sha(executable)
                assert prepared.digest(prepared.consumer_inputs(root)) == result["consumer_sha256"]
                assert sha(Path(__file__)) == result["script_sha256"]
                if args.export_guest:
                    shutil.copy2(executable, output / prepared.EXECUTABLE)
                elif not args.compile_only:
                    run("guest", guest_command(executable), timeout=900)
                    observations = prepared.observations(output / "observations.jsonl", expected_cases)
                    result["cases"] = len(observations)
                    result["guest_execution_qualified"] = True
        else:
            if sha(executable) != result["executable_sha256"]:
                raise ValueError("prepared executable changed before execution")
            run("guest", guest_command(executable), timeout=900)
            result["cases"] = len(prepared.observations(output / "observations.jsonl", expected_cases))
            result["guest_execution_qualified"] = True
        assert prepared.engine_inputs(root) == inputs
        assert prepared.digest(prepared.consumer_inputs(root)) == result["consumer_sha256"]
        assert sha(Path(__file__)) == result["script_sha256"]
        assert sha(Path(prepared.__file__)) == result["support_sha256"]
        if args.export_guest:
            prepared.export_description(output, result, expected_cases)
        result["engine_inputs_unchanged"] = len(inputs)
        result["success"] = True
    except (OSError, ValueError, KeyError, TypeError, AssertionError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["success"] = False
        result["error"] = repr(error)
    finally:
        result["owned_build_removed"] = scratch is None or not scratch.exists()
        prepared.save(output / "result.json", result)
    print(json.dumps({name: result[name] for name in (
        "success", "guest_execution_qualified", "owned_build_removed", "error")}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
