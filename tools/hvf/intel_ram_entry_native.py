#!/usr/bin/env python3
"""Observe SDK-only RAM-entry controls and optional constructor subsets; no RAX library is linked."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile

VARIANTS = (
    "baseline", "full-shadows", "required-masks", "required-masks-and-shadows",
    "register-controls", "register-controls-and-shadows", "required-state-and-shadows",
    "vmx-masks-and-shadows",
)
STATE_FIELDS = (
    "cr0", "cr3", "cr4", "efer", "cr0_mask", "cr4_mask", "cr0_shadow", "cr4_shadow",
    "entry_controls", "cs_access", "activity", "interruptibility", "rip", "r10", "rax", "rdi", "rflags",
    "pin_controls", "primary_controls", "secondary_controls",
)
MARKER = 0xA1B2C3D4E5F60718


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unsigned(value, bits=64):
    return type(value) is int and 0 <= value < (1 << bits)


def validate_observation(rows, variant, constructor_flags=0):
    """Admit complete observations without turning a failed entry into a guest pass."""
    if not isinstance(rows, list) or len(rows) != 2:
        raise ValueError("expected availability and RAM-entry records")
    availability, entry = rows
    if not isinstance(availability, dict) or not isinstance(entry, dict):
        raise ValueError("observation must be an object")
    if availability.get("native_intel_process") is not True or availability.get("vm_created") is not True:
        raise ValueError("native Intel HVF availability was not established")
    if entry.get("probe") != "ram-entry" or entry.get("variant") != variant:
        raise ValueError("unexpected RAM-entry variant")
    if type(entry.get("version")) is not int or entry["version"] != 2:
        raise ValueError("unexpected RAM-entry record version")
    if not unsigned(entry.get("constructor_flags"), 3) or entry["constructor_flags"] != constructor_flags:
        raise ValueError("unexpected constructor controls")
    if entry.get("guest_entry_attempted") is not True:
        raise ValueError("missing guest-entry attempt")
    for phase in ("before", "after"):
        state = entry.get(phase)
        if not isinstance(state, dict) or set(state) != set(STATE_FIELDS):
            raise ValueError("incomplete state observation")
        if not all(unsigned(value) for value in state.values()):
            raise ValueError("invalid state scalar")
    if not unsigned(entry.get("run_status"), 32):
        raise ValueError("invalid run status")
    reason = entry.get("exit_reason")
    if entry["run_status"] == 0:
        if not unsigned(reason, 32):
            raise ValueError("missing VM-exit reason after successful SDK call")
    elif reason is not None:
        raise ValueError("VM-exit reason must be absent after failed SDK call")
    if not unsigned(entry.get("entries")) or not 1 <= entry["entries"] <= 10:
        raise ValueError("invalid bounded entry count")
    reached = entry.get("guest_reached_hlt")
    if type(reached) is not bool:
        raise ValueError("missing guest-result boolean")
    if reached and (entry["run_status"] != 0 or reason != 12 or
                    entry["after"]["rip"] != 0x1000A or entry["after"]["r10"] != MARKER or
                    entry["after"]["rax"] != 0x1122334455667788 or
                    entry["after"]["rdi"] != 0x40000080 or entry["after"]["rflags"] != 2):
        raise ValueError("claimed HLT disagrees with observed guest state")
    for status_key, value_key, bits in (("vmx_status_read_status", "vmx_flags", 32),
                                        ("instruction_error_read_status", "instruction_error", 64)):
        status, value = entry.get(status_key), entry.get(value_key)
        if not unsigned(status, 32) or (status == 0 and not unsigned(value, bits)):
            raise ValueError("incomplete VMX diagnostic read")
        if status != 0 and value is not None:
            raise ValueError("failed VMX diagnostic read must have a null value")
    for key in ("vcpu_destroy_status", "guest_unmap_status", "vm_destroy_status", "host_unmap_status"):
        if type(entry.get(key)) is not int or entry[key] != 0:
            raise ValueError("owned resources were not released")
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    parser.add_argument("--compile-only", action="store_true", help="sign and verify without executing")
    parser.add_argument("--constructor-matrix", action="store_true",
                        help="also compare constructor subsets and all-core transfer variants")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_suffix(".c")
    sources = (source, Path(__file__), source.with_name("native_intel_availability.c"))
    result = {
        "scope": __doc__, "success": False, "error": None, "commands": [], "observations": [],
        "compile_only": args.compile_only, "observation_matrix_complete": False,
        "rax_guest_execution_qualified": False, "positive_sdk_variants": [],
        "source_sha256": {path.name: sha(path) for path in sources},
    }
    scratch = None
    cases = [(variant, 0) for variant in VARIANTS]
    if args.constructor_matrix:
        cases += [("baseline", flags) for flags in range(1, 8)]
        cases += [(variant, 7) for variant in VARIANTS[1:]]
    result["expected_observations"] = len(cases)

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
        with tempfile.TemporaryDirectory(prefix="rax-hvf-intel-ram-entry-",
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
                for variant, flags in cases:
                    label = f"{variant}/constructor-{flags}"
                    completed = run(label, [str(executable), variant, str(flags)])
                    rows = [json.loads(line) for line in completed.stdout.splitlines()]
                    # Preserve raw and parsed records before rejecting malformed output.
                    result["observations"].append(rows)
                    entry = validate_observation(rows, variant, flags)
                    if entry["guest_reached_hlt"]:
                        result["positive_sdk_variants"].append(label)
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
        "success", "compile_only", "observation_matrix_complete", "positive_sdk_variants",
        "rax_guest_execution_qualified", "owned_build_removed", "error")}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
