#!/usr/bin/env python3
"""Independent same-PE A64 MRS -> A32 VMRS controls; no RAX imports.

Requires LLVM MC/LLD/objcopy and QEMU system AArch64. All linked/compiled files
live in an automatically removed temporary directory. JSON retains exact commands,
raw output, tool versions and source hashes. Time and memory are O(1) per profile.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--llvm-bin", type=pathlib.Path, default=pathlib.Path("/Users/int/local/bin"))
    parser.add_argument("--qemu", default=shutil.which("qemu-system-aarch64"))
    args = parser.parse_args()
    here = pathlib.Path(__file__).resolve().parent
    records = []

    def run(argv, cwd):
        try:
            process = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=15)
            record = dict(argv=argv, cwd=str(cwd), exit_code=process.returncode, stdout=process.stdout, stderr=process.stderr)
        except subprocess.TimeoutExpired as error:
            record = dict(argv=argv, cwd=str(cwd), exit_code=None, timeout_seconds=15,
                          stdout=(error.stdout or b"").decode(), stderr=(error.stderr or b"").decode())
        records.append(record)
        if record["exit_code"] != 0:
            raise RuntimeError(record)
        return record["stdout"]

    result = {
        "scope": "QEMU CPU-profile comparisons, not physical-hardware or per-field-isolation evidence",
        "source_sha256": {name: hashlib.sha256((here / name).read_bytes()).hexdigest()
                          for name in ["qemu-loader.s", "qemu-a32.s", "qemu-tid3.s", "qemu-controls.py"]},
        "records": records, "cases": [], "passed": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="rax-mvfr-", dir=os.environ.get("TMPDIR")) as temporary:
            work = pathlib.Path(temporary)
            result["qemu_version"] = run([args.qemu, "--version"], work)
            result["llvm_version"] = run([str(args.llvm_bin / "llvm-mc"), "--version"], work)
            for profile in ["cortex-a53", "max"]:
                for thumb in [False, True]:
                    text = (here / "qemu-a32.s").read_text().replace(
                        "EXECUTION_MODE", ".thumb" if thumb else ".arm").replace(
                        "SEMIHOST_EXIT", "    hlt #0x3c" if thumb else "    hlt #0xf000")
                    (work / "a32.s").write_text(text)
                    (work / "loader.s").write_text((here / "qemu-loader.s").read_text().replace(
                        "SAVED_PSTATE", "0x1f3" if thumb else "0x1d3"))
                    for target, source, address in [("armv8.2a-none-eabi", "a32", "0x40081000"),
                                                    ("aarch64-none-elf", "loader", "0x40080000")]:
                        run([str(args.llvm_bin / "llvm-mc"), "-triple=" + target, "-filetype=obj",
                             source + ".s", "-o", source + ".o"], work)
                        run([str(args.llvm_bin / "ld.lld"), "-Ttext=" + address,
                             "-e", "_start", source + ".o", "-o", source + ".elf"], work)
                        run([str(args.llvm_bin / "llvm-objcopy"), "-O", "binary",
                             source + ".elf", source + ".bin"], work)
                    output = run([args.qemu, "-M", "virt,virtualization=on", "-cpu", profile,
                                  "-m", "64M", "-display", "none", "-monitor", "none", "-serial", "stdio",
                                  "-semihosting-config", "enable=on,target=native", "-kernel", "loader.bin"], work)
                    values = [int(line, 16) for line in output.splitlines() if re.fullmatch(r"[0-9a-f]{8}", line)]
                    case = dict(profile=profile, thumb=thumb, values=values)
                    result["cases"].append(case)
                    assert len(values) == 7 and values[0] == 8, case
                    assert values[1:4] == values[4:7], case
                    # Check the known half-arithmetic distinction separately from
                    # full IDs, which vary by independently implemented CPU model.
                    half = profile == "max"
                    assert (values[2] >> 24) & 15 == (3 if half else 2), case
                    assert (values[2] >> 20) & 15 == (2 if half else 1), case
            for profile in ["cortex-a53", "max"]:
                for tid3 in [False, True]:
                    (work / "tid3.s").write_text((here / "qemu-tid3.s").read_text().replace(
                        "TRAP_BITS", "0x8004" if tid3 else "0x8000").replace(
                        "REPORT_OFFSET", "32" if tid3 else "0"))
                    run([str(args.llvm_bin / "llvm-mc"), "-triple=aarch64-none-elf", "-filetype=obj",
                         "tid3.s", "-o", "tid3.o"], work)
                    run([str(args.llvm_bin / "ld.lld"), "-Ttext=0x40080000", "-e", "_start",
                         "tid3.o", "-o", "tid3.elf"], work)
                    run([str(args.llvm_bin / "llvm-objcopy"), "-O", "binary", "tid3.elf", "tid3.bin"], work)
                    output = run([args.qemu, "-M", "virt,virtualization=on", "-cpu", profile,
                                  "-m", "64M", "-display", "none", "-monitor", "none", "-serial", "stdio",
                                  "-semihosting-config", "enable=on,target=native", "-kernel", "tid3.bin"], work)
                    values = [int(line, 16) for line in output.splitlines() if re.fullmatch(r"[0-9a-f]{8}", line)]
                    case = dict(profile=profile, tid3=tid3, values=values)
                    result["cases"].append(case)
                    if tid3:
                        assert values == [0x62300007, 0x62320027, 0x62340047], case
                    else:
                        assert values == next(c["values"][1:4] for c in result["cases"]
                                              if c["profile"] == profile and "thumb" in c), case
            result["passed"] = True
    finally:
        args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
