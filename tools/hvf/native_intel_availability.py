#!/usr/bin/env python3
"""Record Intel macOS HVF availability; this does not qualify guest execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_suffix(".c")
    result = {"scope": __doc__, "commands": [], "probe": None, "error": None,
              "guest_execution_qualified": False,
              "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "python_machine": platform.machine(),
              "github": {name: os.environ.get(name) for name in (
                  "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}}
    scratch = None

    def run(label, argv, required=True):
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        result["commands"].append({"label": label, "argv": argv,
                                   "exit_code": completed.returncode,
                                   "stdout": completed.stdout, "stderr": completed.stderr})
        if required and completed.returncode:
            raise RuntimeError(f"{label} failed with status {completed.returncode}")
        return completed

    try:
        if sys.platform != "darwin":
            raise RuntimeError("macOS is required")
        run("os", ["sw_vers"])
        run("kernel", ["uname", "-a"])
        run("cpu", ["sysctl", "-n", "machdep.cpu.brand_string"], required=False)
        run("sdk", ["xcrun", "--sdk", "macosx", "--show-sdk-version"])
        run("compiler", ["xcrun", "--sdk", "macosx", "clang", "--version"])
        with tempfile.TemporaryDirectory(prefix="rax-hvf-intel-availability-",
                                         dir=os.environ.get("RUNNER_TEMP") or "/tmp") as tmp:
            scratch = Path(tmp)
            executable = scratch / "probe"
            entitlements = scratch / "entitlements.plist"
            entitlements.write_bytes(plistlib.dumps({"com.apple.security.hypervisor": True}))
            run("build", ["xcrun", "--sdk", "macosx", "clang", "-arch", "x86_64",
                          "-std=c11", "-O1", "-Wall", "-Wextra", str(source),
                          "-framework", "Hypervisor", "-o", str(executable)])
            run("sign", ["codesign", "--force", "--sign", "-", "--entitlements",
                         str(entitlements), "--timestamp=none", str(executable)])
            run("verify-signature", ["codesign", "--verify", "--strict", str(executable)])
            result["executable_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
            completed = run("observe", [str(executable)], required=False)
            result["probe"] = json.loads(completed.stdout)
            result["probe_exit_code"] = completed.returncode
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    finally:
        result["owned_build_removed"] = scratch is not None and not scratch.exists()
        result["hvf_vm_available"] = bool(result["error"] is None and
                                           result["probe_exit_code"] == 0 and
                                           result["probe"]["native_intel_process"] and
                                           result["probe"]["vm_created"] and
                                           result["probe"]["vm_destroyed"])
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({name: result[name] for name in (
        "hvf_vm_available", "guest_execution_qualified", "owned_build_removed", "error")}))
    return 0 if result["hvf_vm_available"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
