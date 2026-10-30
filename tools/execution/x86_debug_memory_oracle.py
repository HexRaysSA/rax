#!/usr/bin/env python3
"""Observe two real x86 guest address spaces through QEMU's GDB stub."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


# GDB treats ordinary memory as process-wide and may send Hg with thread zero.
# Select an explicit CPU immediately before each raw memory request so the
# oracle measures that CPU's translation, independently of client heuristics.
GDB_SCRIPT = r"""
import gdb
import json
import re

high = 0xffff800000400000
inferior = gdb.selected_inferior()
assert len(inferior.threads()) == 2


def rsp(payload):
    text = gdb.execute('maintenance packet ' + payload, to_string=True)
    values = re.findall(r'received: "([^"\\]*)"', text)
    assert len(values) == 1, (payload, text)
    return values[0]


def read(thread, address, size):
    assert rsp('Hgp1.%x' % thread) == 'OK'
    return bytes.fromhex(rsp('m%x,%x' % (address, size)))


rows = []
for thread, root, expected in [(1, 0x1000, b'CPU0DATA'), (2, 0x7000, b'CPU1DATA')]:
    gdb.execute('thread %d' % thread)
    cr0 = int(gdb.parse_and_eval('$cr0'))
    enabled = (1 << 31) | (1 << 16)
    assert cr0 & enabled == enabled, ('PG/WP', thread, hex(cr0))
    actual_root = int(gdb.parse_and_eval('$cr3'))
    assert actual_root == root, ('CR3', thread, hex(actual_root), hex(root))
    actual = read(thread, high, 8)
    assert actual == expected, ('memory', thread, actual.hex(), expected.hex())
    rows.append(dict(thread=thread, cr0=cr0, cr3=root, before=actual.hex()))

# Both CPUs are stopped. Clear A bits set by the actual guest loads so
# debugger-only reads and writes can be checked against all four entries.
entries = {0x7800: 0xd003, 0xd000: 0xe003, 0xe010: 0xf003, 0xf000: 0xb001}
assert rsp('Qqemu.PhyMemMode:1') == 'OK'
for address, value in entries.items():
    assert rsp('M%x,8:%s' % (address, value.to_bytes(8, 'little').hex())) == 'OK'
assert rsp('Qqemu.PhyMemMode:0') == 'OK'
assert read(2, high, 8) == b'CPU1DATA'
for address, value in entries.items():
    assert read(2, address, 8) == value.to_bytes(8, 'little'), ('read A/D', hex(address))
pte_before = read(2, 0xf000, 8)
assert int.from_bytes(pte_before, 'little') & 2 == 0
assert rsp('Hgp1.2') == 'OK'
assert rsp('M%x,4:41424344' % high) == 'OK'
after_write = read(2, high, 8)
assert after_write == b'ABCDDATA', ('write', after_write.hex())
for address, value in entries.items():
    assert read(2, address, 8) == value.to_bytes(8, 'little'), ('write A/D', hex(address))
rows[1]['after'] = after_write.hex()
assert read(1, high, 8) == b'CPU0DATA'
assert rsp('Qqemu.PhyMemMode:1') == 'OK'
assert read(2, 0xb000, 8) == b'ABCDDATA'
guest_reads = read(1, 0x700, 16)
assert guest_reads == b'CPU0DATACPU1DATA', ('guest loads', guest_reads.hex())
assert rsp('Qqemu.PhyMemMode:0') == 'OK'
report = dict(
    records=rows,
    read_only_write_bypasses_wp=True,
    debugger_keeps_pte_status=True,
    cleared_paging_entries_checked=len(entries),
    physical_mode=True,
    guest_reads=guest_reads.hex(),
)
print('RAX_MEMORY_ORACLE=' + json.dumps(report, sort_keys=True))
"""


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--gdb", default="gdb")
    args = parser.parse_args()
    output = args.work_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Use an empty evidence directory")
    args.scratch_dir.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name("x86_debug_memory_guest.s")
    commands = []
    artifacts = {}
    manifest = {
        "schema": 1,
        "status": "failed",
        "tool_sha256": sha256(Path(__file__)),
        "guest_sha256": sha256(source),
        "commands": commands,
        "removed_build_artifacts": artifacts,
        "scope": (
            "Actual two-CPU QEMU TCG guest loads and explicit-CPU RSP memory "
            "observations through installed GDB; not physical Intel, RAX SDK "
            "execution or complete native qualification"
        ),
    }

    def run(name, command, cwd):
        command = [str(value) for value in command]
        start = time.monotonic()
        record = {"name": name, "argv": command}
        commands.append(record)
        stdout, stderr = b"", b""
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=45)
            stdout, stderr = result.stdout, result.stderr
            record["exit_code"] = result.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b"", error.stderr or b""
            record["timed_out"] = True
            raise
        finally:
            record["elapsed_seconds"] = time.monotonic() - start
            (output / (name + ".stdout")).write_bytes(stdout)
            (output / (name + ".stderr")).write_bytes(stderr)
        if result.returncode:
            raise RuntimeError((name, result.returncode, stderr[-2000:]))
        return result

    try:
        manifest["binaries"] = {}
        for executable in (args.qemu, args.gdb):
            path = Path(shutil.which(executable) or executable).resolve()
            manifest["binaries"][executable] = {
                "path": str(path), "sha256": sha256(path)
            }
        run("qemu-version", [args.qemu, "--version"], output)
        run("gdb-version", [args.gdb, "--version"], output)
        run("llvm-version", [args.llvm_bin / "llvm-mc", "--version"], output)
        with tempfile.TemporaryDirectory(
            prefix="debug-memory-", dir=args.scratch_dir
        ) as temporary:
            scratch = Path(temporary)
            (scratch / "guest.s").write_bytes(source.read_bytes())
            (output / "guest.s").write_bytes(source.read_bytes())
            (scratch / "link.ld").write_text(
                "ENTRY(_start)\nSECTIONS {. = 0x100000; "
                ".multiboot : {*(.multiboot)} .text : {*(.text*)} "
                ".rodata : {*(.rodata*)} .bss : {*(.bss*) *(COMMON)}}\n"
            )
            run("assemble", [
                args.llvm_bin / "llvm-mc", "-triple=i386-none-elf",
                "-filetype=obj", "guest.s", "-o", "guest.o",
            ], scratch)
            run("link", [
                args.llvm_bin / "ld.lld", "-m", "elf_i386", "-T", "link.ld",
                "guest.o", "-o", "guest.elf",
            ], scratch)
            artifacts.update({name: sha256(scratch / name)
                              for name in ("guest.o", "guest.elf")})
            socket = scratch / "gdb.sock"
            ready = scratch / "ready.bin"
            command = [
                args.qemu, "-machine", "pc,accel=tcg", "-cpu", "Haswell-noTSX",
                "-smp", "2,cores=2,threads=1,sockets=1", "-m", "64M",
                "-display", "none", "-serial", "none", "-monitor", "none",
                "-no-reboot", "-no-shutdown", "-debugcon", "file:" + str(ready),
                "-global", "isa-debugcon.iobase=0xe9", "-chardev",
                "socket,path=" + str(socket) + ",server=on,wait=off,id=gdb0",
                "-gdb", "chardev:gdb0", "-kernel", "guest.elf",
            ]
            start = time.monotonic()
            with (output / "qemu.stdout").open("wb") as stdout, (
                output / "qemu.stderr"
            ).open("wb") as stderr:
                child = subprocess.Popen(command, cwd=scratch, stdout=stdout, stderr=stderr)
                try:
                    while not ready.exists() or ready.read_bytes().count(b"R") < 2:
                        if child.poll() is not None or time.monotonic() - start > 15:
                            raise RuntimeError("Both CPUs did not reach long-mode ready state")
                        time.sleep(0.01)
                    (output / "gdb-script.py").write_text(GDB_SCRIPT)
                    result = run("gdb", [
                        args.gdb, "--batch", "-nx", "-ex", "set debug remote 1",
                        "-ex", "set remotetimeout 10", "-ex", "target remote " + str(socket),
                        "-ex", "python exec(" + repr(GDB_SCRIPT) + ")", "-ex", "detach",
                    ], output)
                    prefix = "RAX_MEMORY_ORACLE="
                    markers = [line[len(prefix):] for line in result.stdout.decode().splitlines()
                               if line.startswith(prefix)]
                    errors = (
                        b"Python Exception", b"Error occurred", b"AssertionError",
                        b"Traceback", b"target description", b"target-supplied description",
                    )
                    if len(markers) != 1 or any(error in result.stderr for error in errors):
                        raise RuntimeError("GDB assertions or target description failed")
                    manifest["report"] = json.loads(markers[0])
                finally:
                    if ready.exists():
                        (output / "ready.bin").write_bytes(ready.read_bytes())
                    if child.poll() is None:
                        child.terminate()
                    try:
                        code = child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        code = child.wait(timeout=5)
                    commands.append({
                        "name": "qemu", "argv": command, "exit_code": code,
                        "elapsed_seconds": time.monotonic() - start,
                        "termination": "Stopped only this invocation's owned QEMU child",
                    })
        manifest["status"] = "passed"
    except Exception as error:
        manifest["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest["report"], indent=2))


if __name__ == "__main__":
    main()
