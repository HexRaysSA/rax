#!/usr/bin/env python3
"""Observe TSC-deadline mode controls and masked expiry in independent KVM guests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_suffix(".c")
    result = {"scope": __doc__, "success": False, "commands": [],
              "host": list(platform.uname()), "source_sha256": sha(source),
              "script_sha256": sha(Path(__file__)), "guest_attempted": False,
              "guest_execution_qualified": False, "physical_intel_hvf_validation": False}
    scratch = None

    def run(label, argv):
        entry = {"label": label, "argv": [str(value) for value in argv]}
        result["commands"].append(entry)
        started = time.monotonic()
        with (output / (label + ".stdout")).open("x") as out, \
                (output / (label + ".stderr")).open("x") as err:
            completed = subprocess.run(argv, stdout=out, stderr=err, timeout=70)
        entry.update(exit_code=completed.returncode, seconds=time.monotonic() - started)
        if completed.returncode:
            raise RuntimeError(f"{label} failed with status {completed.returncode}")

    try:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise RuntimeError("native Linux x86-64 is required")
        cpu = {}
        for line in Path("/proc/cpuinfo").read_text().split("\n\n", 1)[0].splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() in {"vendor_id", "model name", "cpu family", "model",
                                              "stepping", "flags"}:
                cpu[key.strip()] = value.strip()
        result["cpu"] = cpu
        if cpu.get("vendor_id") != "GenuineIntel":
            raise RuntimeError("this control requires an Intel host")
        ignore = Path("/sys/module/kvm/parameters/ignore_msrs").read_text().strip()
        result["kvm_ignore_msrs"] = ignore
        if ignore not in {"N", "0"}:
            raise RuntimeError("KVM ignore_msrs must already be disabled")
        run("compiler", ["cc", "--version"])
        with tempfile.TemporaryDirectory(prefix="rax-tsc-deadline-",
                                         dir=os.environ.get("TMPDIR") or "/tmp") as tmp:
            scratch = Path(tmp)
            executable = scratch / "probe"
            run("build", ["cc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra",
                          "-Werror", str(source), "-o", str(executable)])
            result["executable_sha256"] = sha(executable)
            result["guest_attempted"] = True
            run("guest", [str(executable)])
            observed = [json.loads(line) for line in
                        (output / "guest.stdout").read_text().splitlines()]
            assert len(observed) == 11
            assert [row["case"] for row in observed] == list(range(11))
            assert all(row["control_passed"] is True for row in observed[:8])
            assert all(row["control_passed"] is None for row in observed[8:])
            for row in observed[:8]:
                expected = 0 if row["case"] in {0, 1, 3, 4, 5} else 0xffffffffffffffff
                assert all(row[key] == expected for key in (
                    "initial_deadline", "after_wait_deadline", "after_unmask_deadline"))
            assert observed[6]["current_count"] == 0
            assert all(row["sampled_tsc"] > 1 for row in observed)
            assert all(row["guest_cpuid_1_ecx"] & (1 << 24) for row in observed)
            result.update(cases=11, asserted_control_cases=8, expiry_observation_cases=3,
                          observations=observed, guest_execution_qualified=True)
        assert sha(source) == result["source_sha256"]
        assert sha(Path(__file__)) == result["script_sha256"]
        result["success"] = True
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = repr(error)
    finally:
        result["owned_build_removed"] = scratch is None or not scratch.exists()
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result.get(key) for key in (
        "success", "guest_attempted", "guest_execution_qualified", "cases", "error",
        "owned_build_removed")}))
    return 0 if result["success"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
