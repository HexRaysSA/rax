#!/usr/bin/env python3
"""Execute real RAX file-resume workloads and independent QEMU UART traces.

No case self-skips. --expect-parent records the known predecessor defects;
it is a negative control and never a corrected-behavior validation result.
Outputs contain guest inputs, tool identities, every command and raw streams.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rax", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--llvm-bin-dir", type=Path)
    parser.add_argument("--qemu", default="qemu-system-riscv64")
    parser.add_argument("--expect-parent", action="store_true")
    args = parser.parse_args()
    args.rax = args.rax.resolve(strict=True)
    args.out.mkdir(parents=True, exist_ok=False)
    inputs = Path(__file__).resolve().parent

    def llvm(name):
        found = str(args.llvm_bin_dir / name) if args.llvm_bin_dir else shutil.which(name)
        if not found or not Path(found).is_file():
            raise RuntimeError(f"required LLVM executable missing: {name}")
        return found

    qemu = shutil.which(args.qemu)
    if not qemu:
        raise RuntimeError(f"required independent oracle missing: {args.qemu}")
    commands = []
    env = dict(os.environ, RAX_NO_JIT="1", RUST_LOG="error")

    def run(label, command):
        started = time.monotonic()
        try:
            result = subprocess.run(command, env=env, input=b"", capture_output=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            (args.out / f"{label}.stdout").write_bytes(error.stdout or b"")
            (args.out / f"{label}.stderr").write_bytes(error.stderr or b"")
            commands.append(dict(label=label, command=command, timeout=True))
            (args.out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            raise
        (args.out / f"{label}.stdout").write_bytes(result.stdout)
        (args.out / f"{label}.stderr").write_bytes(result.stderr)
        commands.append(dict(label=label, command=command, code=result.returncode,
                             seconds=time.monotonic() - started))
        (args.out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(f"{label} exited {result.returncode}; see retained streams")
        return result.stdout

    producer = dict(rax=str(args.rax), rax_sha256=digest(args.rax),
                    qemu=str(Path(qemu).resolve()), qemu_sha256=digest(Path(qemu)),
                    qemu_version=run("qemu-version", [qemu, "--version"]).decode(),
                    llvm_version=run("llvm-version", [llvm("llvm-mc"), "--version"]).decode(),
                    negative_control=args.expect_parent)
    (args.out / "producer.json").write_text(json.dumps(producer, indent=2) + "\n")
    results = []
    for case in ["uart", "reservation"]:
        output = args.out / case
        output.mkdir()
        source = inputs / f"riscv_context_{case}.s"
        script = inputs / "riscv_context.ld"
        obj, elf = output / "guest.o", output / "guest.elf"
        run(f"{case}-assemble", [llvm("llvm-mc"), "--triple=riscv64", "--mattr=+v,+a",
                                "--filetype=obj", str(source), "-o", str(obj)])
        run(f"{case}-link", [llvm("ld.lld"), "-m", "elf64lriscv", "-T", str(script), str(obj), "-o", str(elf)])
        symbols = run(f"{case}-symbols", [llvm("llvm-nm"), "-n", str(elf)]).decode()
        addresses = {line.split()[2]: int(line.split()[0], 16) for line in symbols.splitlines()
                     if len(line.split()) == 3 and line.split()[2] in ["_start", "checkpoint_frontier"]}
        count = (addresses["checkpoint_frontier"] - addresses["_start"]) // 4 + 1
        assert count == {"uart": 11, "reservation": 1000}[case], addresses
        run(f"{case}-disassembly", [llvm("llvm-objdump"), "-d", str(elf)])
        reference = run(f"{case}-qemu", [qemu, "-machine", "virt", "-bios", "none",
                       "-m", "128M", "-smp", "1", "-cpu", "rv64,v=true,vlen=128,elen=64",
                       "-display", "none", "-monitor", "none", "-serial", "stdio", "-kernel", str(elf)])
        assert reference == {"uart": b"ABCD", "reservation": b"0"}[case], reference
        original = run(f"{case}-uninterrupted", [str(args.rax), "--arch", "riscv64", "--backend", "emulator",
                       "--memory", "128M", "--kernel", str(elf), "--snapshot-at", str(count), "--snapshot-dir", str(output)])
        snapshots = list(output.glob("snapshot_*.rxc"))
        assert len(snapshots) == 1, snapshots
        resumed = run(f"{case}-resumed", [str(args.rax), "--checkpoint", str(snapshots[0])])
        results.append(dict(case=case, snapshot_retirement=count,
                            snapshot_pc=hex(addresses["checkpoint_frontier"] + 4),
                            source_sha256=digest(source), elf_sha256=digest(elf),
                            checkpoint_sha256=digest(snapshots[0]),
                            qemu=reference.decode(), uninterrupted=original.decode(), resumed=resumed.decode()))
        (args.out / "observations.json").write_text(json.dumps(results, indent=2) + "\n")
        expected = ((b"D", b"") if case == "uart" else (b"0", b"1")) if args.expect_parent else (
            (b"ABCD", b"BCD") if case == "uart" else (b"0", b"0"))
        assert (original, resumed) == expected, (case, original, resumed, expected)
    assert digest(args.rax) == producer["rax_sha256"], "RAX executable changed during the run"
    (args.out / "result.json").write_text(json.dumps(dict(code=0, cases=2, qemu_executions=2,
        rax_executions=4, negative_control=args.expect_parent, observations=results), indent=2) + "\n")
    print(json.dumps(dict(cases=2, qemu_executions=2, rax_executions=4,
                          negative_control=args.expect_parent)))


if __name__ == "__main__":
    main()
