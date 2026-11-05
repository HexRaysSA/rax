#!/usr/bin/env python3
"""Observe native Intel SDK DEBUGCTL access and TF/BTF stepping; no RAX library is linked."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile

from intel_ram_entry_native import STATE_FIELDS, sha, unsigned

CASES = ("read-msr", "write-zero", "write-btf", "tf", "btf-default-entry", "btf-load-entry")
OPTIONAL_FIELDS = ("debugctl", "exit_controls", "pending_debug", "exit_qualification",
                   "exit_interrupt_info", "instruction_error")


def validate_observation(rows, case):
    """Validate complete observations, including rejected controls and failed entries."""
    if case not in CASES or not isinstance(rows, list) or len(rows) != 2:
        raise ValueError("expected availability and one known DEBUGCTL case")
    availability, entry = rows
    if not isinstance(availability, dict) or not isinstance(entry, dict):
        raise ValueError("observation must be an object")
    if availability.get("native_intel_process") is not True or availability.get("vm_created") is not True:
        raise ValueError("native Intel HVF availability was not established")
    if entry.get("probe") != "debugctl" or entry.get("case") != case:
        raise ValueError("unexpected probe or case")
    if type(entry.get("version")) is not int or entry["version"] != 1:
        raise ValueError("unexpected DEBUGCTL record version")
    for phase in ("before", "after"):
        state = entry.get(phase)
        if not isinstance(state, dict) or set(state) != {"core", "dr6", "rdx", *OPTIONAL_FIELDS}:
            raise ValueError("incomplete debug-state observation")
        core = state["core"]
        if not isinstance(core, dict) or set(core) != set(STATE_FIELDS):
            raise ValueError("incomplete core-state observation")
        if not all(unsigned(value) for value in core.values()):
            raise ValueError("invalid core-state scalar")
        if not unsigned(state["dr6"]) or not unsigned(state["rdx"]):
            raise ValueError("invalid register scalar")
        for key in OPTIONAL_FIELDS:
            field = state[key]
            if not isinstance(field, dict) or set(field) != {"status", "value"}:
                raise ValueError("incomplete SDK field read")
            if not unsigned(field["status"], 32):
                raise ValueError("invalid SDK field-read status")
            if field["status"] == 0:
                if not unsigned(field["value"]):
                    raise ValueError("missing successful SDK field value")
            elif field["value"] is not None:
                raise ValueError("failed SDK field read must have a null value")
    initial, bitmap = entry.get("initial_exception_bitmap"), entry.get("exception_bitmap")
    if not unsigned(initial, 32) or not unsigned(bitmap, 32) or bitmap != initial | 0x2002:
        raise ValueError("SDK intercepts were not preserved with DB/GP interception")
    expected_debugctl = 2 if case.startswith("btf-") else 0
    if not unsigned(entry.get("requested_debugctl")) or entry["requested_debugctl"] != expected_debugctl:
        raise ValueError("unexpected requested DEBUGCTL")
    config = entry.get("configuration_status")
    if not unsigned(config, 32):
        raise ValueError("invalid configuration status")
    attempted, entries = entry.get("guest_entry_attempted"), entry.get("entries")
    if type(attempted) is not bool or not unsigned(entries) or entries > 10:
        raise ValueError("invalid guest-entry accounting")
    if attempted != (entries > 0) or attempted != (config == 0):
        raise ValueError("entry attempt contradicts SDK configuration status")
    status, reason = entry.get("run_status"), entry.get("exit_reason")
    if attempted:
        if not unsigned(status, 32) or (status == 0 and not unsigned(reason, 32)):
            raise ValueError("incomplete SDK run result")
        if status != 0 and reason is not None:
            raise ValueError("failed run must have no inferred exit reason")
    elif status is not None or reason is not None:
        raise ValueError("unattempted entry must have no run result")
    for key in ("vcpu_destroy_status", "guest_unmap_status", "vm_destroy_status", "host_unmap_status"):
        if type(entry.get(key)) is not int or entry[key] != 0:
            raise ValueError("owned resources were not released")
    return entry


def describe_exit(entry):
    """Describe raw first exits without promoting an observation to conformance."""
    if not entry["guest_entry_attempted"]:
        return "SDK configuration rejected"
    if entry["run_status"] != 0:
        return "SDK run rejected"
    reason = entry["exit_reason"]
    if reason == 0:
        info = entry["after"]["exit_interrupt_info"]
        if info["status"] == 0 and info["value"] & (1 << 31):
            return f"intercepted exception vector {info['value'] & 255}"
    return {12: "HLT", 31: "RDMSR delegated", 32: "WRMSR delegated", 1: "host interrupt",
            52: "deadline"}.get(reason, f"VM-exit {reason:#x}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    parser.add_argument("--compile-only", action="store_true", help="sign and verify without executing")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_suffix(".c")
    sources = (source, Path(__file__), source.with_name("intel_ram_entry_native.c"),
               source.with_name("intel_ram_entry_native.py"),
               source.with_name("native_intel_availability.c"))
    result = {
        "scope": __doc__, "success": False, "error": None, "commands": [], "observations": [],
        "compile_only": args.compile_only, "observation_matrix_complete": False,
        "rax_guest_execution_qualified": False, "exit_observations": {},
        "source_sha256": {path.name: sha(path) for path in sources},
    }
    scratch = None
    result["expected_observations"] = len(CASES)

    def run(label, argv):
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        result["commands"].append({"label": label, "argv": [str(x) for x in argv],
                                   "exit_code": completed.returncode,
                                   "stdout": completed.stdout, "stderr": completed.stderr})
        if completed.returncode:
            raise RuntimeError(f"{label} failed with status {completed.returncode}")
        return completed

    try:
        run("os", ["sw_vers"])
        run("sdk", ["xcrun", "--sdk", "macosx", "--show-sdk-version"])
        run("compiler", ["xcrun", "--sdk", "macosx", "clang", "--version"])
        with tempfile.TemporaryDirectory(prefix="rax-hvf-intel-debugctl-",
                                         dir=os.environ.get("RUNNER_TEMP") or "/tmp") as tmp:
            scratch = Path(tmp)
            executable = scratch / "probe"
            entitlements = scratch / "entitlements.plist"
            entitlements.write_bytes(plistlib.dumps({"com.apple.security.hypervisor": True}))
            run("build", ["xcrun", "--sdk", "macosx", "clang", "-arch", "x86_64",
                          "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", str(source),
                          "-framework", "Hypervisor", "-o", str(executable)])
            run("sign", ["codesign", "--force", "--sign", "-", "--entitlements",
                         str(entitlements), "--timestamp=none", str(executable)])
            run("verify-signature", ["codesign", "--verify", "--strict", str(executable)])
            result["executable_sha256"] = sha(executable)
            if not args.compile_only:
                for case in CASES:
                    completed = run(case, [str(executable), case])
                    rows = [json.loads(line) for line in completed.stdout.splitlines()]
                    result["observations"].append(rows)
                    entry = validate_observation(rows, case)
                    result["exit_observations"][case] = describe_exit(entry)
                result["observation_matrix_complete"] = True
            if any(sha(path) != result["source_sha256"][path.name] for path in sources):
                raise RuntimeError("probe source changed during observation")
            result["success"] = True
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = repr(error)
    finally:
        result["owned_build_removed"] = scratch is None or not scratch.exists()
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in (
        "success", "compile_only", "observation_matrix_complete", "exit_observations",
        "rax_guest_execution_qualified", "owned_build_removed", "error")}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
