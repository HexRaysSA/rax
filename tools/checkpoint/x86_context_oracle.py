#!/usr/bin/env python3
"""Actual QEMU/RAX file continuation with the source boot ISO unavailable."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_iso(boot):
    assert len(boot) == 2048
    iso = bytearray(1024 * 2048)
    pvd = 16 * 2048
    iso[pvd:pvd + 7] = b"\x01CD001\x01"
    iso[pvd + 40:pvd + 72] = b"RAX_CONTEXT_BOOT".ljust(32, b" ")
    iso[pvd + 80:pvd + 88] = struct.pack("<I", 1024) + struct.pack(">I", 1024)
    for offset, value in [(120, 1), (124, 1), (128, 2048)]:
        iso[pvd + offset:pvd + offset + 4] = struct.pack("<H", value) + struct.pack(">H", value)
    iso[pvd + 881] = 1
    brvd = 17 * 2048
    iso[brvd:brvd + 7] = b"\x00CD001\x01"
    iso[brvd + 7:brvd + 30] = b"EL TORITO SPECIFICATION"
    iso[brvd + 0x47:brvd + 0x4b] = struct.pack("<I", 19)
    end = 18 * 2048
    iso[end:end + 7] = b"\xffCD001\x01"
    cat = 19 * 2048
    validation = bytearray(32)
    validation[0] = 1
    validation[30:32] = b"\x55\xaa"
    validation[28:30] = struct.pack("<H", (-sum(struct.unpack("<16H", validation))) & 0xffff)
    assert sum(struct.unpack("<16H", validation)) & 0xffff == 0
    iso[cat:cat + 32] = validation
    entry = bytearray(32)
    entry[0] = 0x88
    entry[6:8] = struct.pack("<H", 4)
    entry[8:12] = struct.pack("<I", 20)
    iso[cat + 32:cat + 64] = entry
    iso[20 * 2048:21 * 2048] = boot
    iso[25 * 2048:26 * 2048] = b"S" * 2048
    return iso


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rax", required=True, type=Path)
    parser.add_argument("--llvm-bin-dir", required=True, type=Path)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expect-parent", action="store_true")
    args = parser.parse_args()
    args.rax = args.rax.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    qemu = shutil.which(args.qemu)
    if not qemu:
        raise RuntimeError("qemu-system-x86_64 is required; no self-skip")
    commands = []

    def run(name, command, timeout=120):
        command = list(map(str, command))
        start = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (args.out / (name + ".stdout")).write_bytes(error.stdout or b"")
            (args.out / (name + ".stderr")).write_bytes(error.stderr or b"")
            commands.append(dict(name=name, command=command, timeout=timeout))
            (args.out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            raise
        (args.out / (name + ".stdout")).write_bytes(result.stdout)
        (args.out / (name + ".stderr")).write_bytes(result.stderr)
        commands.append(dict(name=name, command=command, code=result.returncode,
                             seconds=time.monotonic() - start))
        (args.out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(f"{name} exited {result.returncode}; see retained streams")
        return result.stdout

    def llvm(name):
        return args.llvm_bin_dir / name

    producer = dict(rax=str(args.rax), rax_sha256=digest(args.rax),
                    qemu=str(Path(qemu).resolve()), qemu_sha256=digest(Path(qemu)),
                    qemu_version=run("qemu-version", [qemu, "--version"]).decode(),
                    llvm_version=run("llvm-version", [llvm("llvm-mc"), "--version"]).decode(),
                    negative_control=args.expect_parent)
    (args.out / "producer.json").write_text(json.dumps(producer, indent=2) + "\n")
    source = Path(__file__).with_name("x86_context_bios.s")
    obj, elf, boot = [args.out / name for name in ["guest.o", "guest.elf", "boot.bin"]]
    run("assemble", [llvm("llvm-mc"), "--triple=i386", "--filetype=obj", source, "-o", obj])
    run("link", [llvm("ld.lld"), "-m", "elf_i386", "--image-base=0", "-Ttext=0x7c00", "-e", "_start", obj, "-o", elf])
    run("binary", [llvm("llvm-objcopy"), "-O", "binary", elf, boot])
    run("symbols", [llvm("llvm-nm"), "-n", elf])
    run("disassembly", [llvm("llvm-objdump"), "--triple=i386", "--mattr=+16bit-mode", "-d", elf])
    image = args.out / "source.iso"
    image.write_bytes(make_iso(boot.read_bytes()))
    reference = run("qemu", [qemu, "-machine", "pc", "-m", "128M", "-display", "none", "-monitor", "none",
                              "-serial", "stdio", "-cdrom", image, "-boot", "d", "-no-reboot"], 30)
    if reference != b"S":
        raise RuntimeError(f"QEMU guest failed: {reference!r}")
    original = run("uninterrupted", [args.rax, "--arch", "x86-64", "--backend", "emulator", "--memory", "128M",
                                    "--kernel", image, "--snapshot-at", "1000", "--snapshot-dir", args.out])
    snapshots = list(args.out.glob("snapshot_*.rxc"))
    if original != b"S" or len(snapshots) != 1:
        raise RuntimeError(f"RAX guest/snapshot failed: {original!r}, {snapshots}")
    retained = args.out / "retained-source.iso"
    image.rename(retained)
    assert not image.exists()
    resumed = run("resumed", [args.rax, "--checkpoint", snapshots[0]])
    expected = b"F" if args.expect_parent else b"S"
    if resumed != expected:
        raise RuntimeError(f"restored guest emitted {resumed!r}, expected {expected!r}")
    if digest(args.rax) != producer["rax_sha256"]:
        raise RuntimeError("RAX executable changed during the qualification")
    result = dict(code=0, cases=1, qemu_executions=1, rax_executions=2,
                  negative_control=args.expect_parent, qemu=reference.decode(),
                  uninterrupted=original.decode(), resumed=resumed.decode(),
                  missing_source_iso=str(image), retained_source_iso=str(retained),
                  snapshot_retirement=1000, unread_sector_lba=25,
                  sha256={path.name: digest(path) for path in [source, elf, retained, snapshots[0]]})
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
