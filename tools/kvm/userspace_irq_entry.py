#!/usr/bin/env python3
"""Observe native xAPIC/x2APIC and deadline-MSR routing without a kernel IRQ chip."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

DEADLINE = 0x1122334455667788


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(record, count, x2apic):
    if not isinstance(record, dict) or record.get("kernel_irqchip_created") is not False:
        raise ValueError("kernel IRQ chip must be absent")
    if record.get("mwait_exit_disabled") is not True or record.get("x2apic") is not x2apic:
        raise ValueError("incorrect per-VM control profile")
    if type(record.get("cpu_count")) is not int or record["cpu_count"] != count:
        raise ValueError("incorrect CPU count")
    cpus = record.get("cpus")
    if not isinstance(cpus, list) or len(cpus) != count:
        raise ValueError("incomplete CPU observations")
    for index, cpu in enumerate(cpus):
        if not isinstance(cpu, dict) or type(cpu.get("id")) is not int or cpu["id"] != index:
            raise ValueError("CPU observations must be ordered and unique")
        expected = {"deadline": DEADLINE + index, "deadline_write_exits": 1,
                    "deadline_read_exits": 1, "apic_write_exits": 0 if x2apic else 1,
                    "x2apic_write_exits": int(x2apic), "x2apic_read_exits": int(x2apic),
                    "native_entries": 5 if x2apic else 4,
                    "rip": 0x10000 + (54 if x2apic else 49),
                    "r10": (DEADLINE + index) & 0xFFFFFFFF, "r11": DEADLINE >> 32}
        for key, value in expected.items():
            if type(cpu.get(key)) is not int or cpu[key] != value:
                raise ValueError(f"incorrect CPU {index} {key}")
        if cpu.get("passed") is not True:
            raise ValueError("guest did not pass its native checks")
        if type(cpu.get("lapic_query_errno")) is not int or cpu["lapic_query_errno"] <= 0:
            raise ValueError("kernel LAPIC absence not established")
        if x2apic and (type(cpu.get("r13")) is not int or cpu["r13"] != 0x40041):
            raise ValueError("x2APIC guest LVT readback differs")
        for key in ("x2apic_write_reason", "x2apic_read_reason"):
            if key not in cpu:
                raise ValueError("incomplete x2APIC observation schema")
            if x2apic:
                if type(cpu.get(key)) is not int or cpu[key] not in (1, 2):
                    raise ValueError("missing unknown/invalid x2APIC MSR exit")
            elif cpu.get(key) is not None:
                raise ValueError("unattempted x2APIC MSR reason must be null")
    for key in ("timer_expiry_qualified", "checkpoint_restore_qualified"):
        if record.get(key) is not False:
            raise ValueError("access routing cannot qualify timer expiry or checkpoint restore")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 20:
        parser.error("repetitions must be between 1 and 20")
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_suffix(".c")
    result = {"scope": __doc__, "success": False, "error": None, "commands": [], "cases": [],
              "source_sha256": sha(source), "script_sha256": sha(Path(__file__)),
              "timer_expiry_qualified": False, "checkpoint_restore_qualified": False}
    scratch = None

    def run(argv, timeout=30):
        child = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        row = {"argv": [str(x) for x in argv], "exit_code": child.returncode,
               "stdout": child.stdout, "stderr": child.stderr}
        result["commands"].append(row)
        return child

    try:
        for argv in (("uname", "-a"), ("cc", "--version")):
            if run(argv).returncode:
                raise RuntimeError("host identity command failed")
        headers = (Path("/usr/include/linux/kvm.h"), Path("/usr/include/x86_64-linux-gnu/asm/kvm.h"))
        result["headers_sha256"] = {str(path): sha(path) for path in headers}
        with tempfile.TemporaryDirectory(prefix="rax-userspace-irq-entry-", dir="/tmp") as tmp:
            scratch = Path(tmp)
            executable = scratch / "probe"
            if run(["cc", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                    str(source), "-o", str(executable)]).returncode:
                raise RuntimeError("C observer build failed")
            result["executable_sha256"] = sha(executable)
            baseline = run([str(executable), "1", "--kernel-timer-path"], 10)
            result["baseline"] = {"exit_code": baseline.returncode, "stdout": baseline.stdout,
                                  "stderr": baseline.stderr}
            # A newer kernel may route the baseline write correctly. Retain its
            # actual outcome; it does not replace the explicit owned-mode cases.
            for x2apic in (False, True):
                for count in (1, 2, 4):
                    for repetition in range(args.repetitions):
                        argv = [str(executable), str(count)] + (["--x2apic"] if x2apic else [])
                        child = run(argv, 10)
                        case = {"cpu_count": count, "x2apic": x2apic, "repetition": repetition,
                                "exit_code": child.returncode, "stdout": child.stdout, "stderr": child.stderr}
                        result["cases"].append(case)
                        if child.returncode:
                            raise RuntimeError("native routing observation failed")
                        record = json.loads(child.stdout)
                        validate(record, count, x2apic)
                        case["observation"] = record
            if sha(source) != result["source_sha256"] or sha(Path(__file__)) != result["script_sha256"]:
                raise RuntimeError("observer source changed during execution")
            result["success"] = True
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = repr(error)
    finally:
        result["owned_build_removed"] = scratch is None or not scratch.exists()
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("success", "owned_build_removed", "error")}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
