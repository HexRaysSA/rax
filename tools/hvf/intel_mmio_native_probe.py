#!/usr/bin/env python3
"""Build and execute the actual RAX Intel HVF scalar MMIO guest consumer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    parser.add_argument("--compile-only", action="store_true",
                        help="cross-build and sign; do not claim native guest execution")
    args = parser.parse_args()
    root = args.repo.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    consumer = Path(__file__).with_name("intel_mmio_native_guest.rs")
    result = {"scope": __doc__, "compile_only": args.compile_only, "commands": [],
              "success": False, "guest_execution_qualified": False, "error": None,
              "consumer_sha256": sha(consumer), "script_sha256": sha(Path(__file__)),
              "github": {name: os.environ.get(name) for name in (
                  "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}}
    inputs = {str(p.relative_to(root)): sha(p) for p in (root / "src").rglob("*.rs")}
    for path in (root / "vendor/vm-memory").rglob("*"):
        if path.is_file() and path.suffix in {".rs", ".toml"}:
            inputs[str(path.relative_to(root))] = sha(path)
    for name in ["Cargo.toml", "Cargo.lock", ".cargo/config.toml"]:
        if (root / name).exists():
            inputs[name] = sha(root / name)
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

    def run(label, command, timeout=60):
        start = time.monotonic()
        stdout = output / (label + ".stdout")
        stderr = output / (label + ".stderr")
        entry = {"label": label, "argv": [str(x) for x in command]}
        result["commands"].append(entry)
        with stdout.open("x") as out, stderr.open("x") as err:
            try:
                completed = subprocess.run(command, cwd=root, env=environment,
                                           stdout=out, stderr=err, timeout=timeout)
            except subprocess.TimeoutExpired:
                entry.update(timed_out=True, seconds=time.monotonic() - start)
                raise
        entry.update(exit_code=completed.returncode, seconds=time.monotonic() - start)
        if completed.returncode:
            raise RuntimeError(f"{label} failed with status {completed.returncode}")
        return stdout

    try:
        run("os", ["sw_vers"])
        run("kernel", ["uname", "-a"])
        run("sdk", ["xcrun", "--sdk", "macosx", "--show-sdk-version"])
        run("rustc", ["rustc", "+stable", "-vV"])
        run("commit", ["git", "rev-parse", "HEAD"])
        if not args.compile_only:
            run("availability", ["python3", str(root / "tools/hvf/native_intel_availability.py"),
                                 "--output", str(output / "availability")], timeout=300)
            available = json.loads((output / "availability/result.json").read_text())
            assert available["hvf_vm_available"]
            assert available["probe"]["native_intel_process"]
            result["native_host"] = available["probe"]
        with tempfile.TemporaryDirectory(prefix="rax-hvf-intel-mmio-",
                                         dir=os.environ.get("RUNNER_TEMP") or "/tmp") as tmp:
            scratch = Path(tmp)
            target = scratch / "build"
            environment.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2",
                               CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
                               CARGO_PROFILE_DEV_OPT_LEVEL="1",
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
            assert sha(consumer) == result["consumer_sha256"]
            assert sha(Path(__file__)) == result["script_sha256"]
            if not args.compile_only:
                run("guest", [str(executable), str(output / "observations.jsonl")], timeout=600)
                observations = [json.loads(line) for line in
                                (output / "observations.jsonl").read_text().splitlines()]
                assert len(observations) == 114
                assert [row["case"] for row in observations] == list(range(114))
                assert all(row["passed"] for row in observations)
                result["cases"] = len(observations)
                result["guest_execution_qualified"] = True
            assert all(sha(root / name) == digest for name, digest in inputs.items())
            result["engine_inputs_unchanged"] = len(inputs)
            result["success"] = True
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["success"] = False
        result["error"] = repr(error)
    finally:
        result["owned_build_removed"] = scratch is None or not scratch.exists()
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({name: result[name] for name in (
        "success", "guest_execution_qualified", "owned_build_removed", "error")}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
