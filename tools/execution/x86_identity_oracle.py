#!/usr/bin/env python3
"""Retain 1/2/4-CPU QEMU identity/BSP observations separately from Intel rules."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--scratch-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    args = parser.parse_args()
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError('Use an empty output directory')
    source = Path(__file__).with_name('x86_identity_guest.s')
    commands = []
    records = []

    def run(name, command, cwd, accepted=(0,)):
        start = time.monotonic()
        result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=30)
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(name=name, argv=[str(x) for x in command], exit_code=result.returncode, elapsed_seconds=time.monotonic() - start))
        if result.returncode not in accepted:
            raise RuntimeError((name, result.returncode, result.stderr[-2000:]))

    run('qemu-version', [args.qemu, '--version'], out)
    run('llvm-version', [str(args.llvm_bin / 'llvm-mc'), '--version'], out)
    artifacts = []
    for count in [1, 2, 4]:
        with tempfile.TemporaryDirectory(prefix='x86-identity-', dir=args.scratch_dir) as temp:
            temp = Path(temp)
            guest = source.read_text().replace('@CPU_COUNT@', str(count))
            (out / f'guest-{count}.s').write_text(guest)
            (temp / 'guest.s').write_text(guest)
            (temp / 'link.ld').write_text('ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .bss : {*(.bss*) *(COMMON)}}\n')
            run(f'assemble-{count}', [str(args.llvm_bin / 'llvm-mc'), '-triple=i386-none-elf', '-filetype=obj', 'guest.s', '-o', 'guest.o'], temp)
            run(f'link-{count}', [str(args.llvm_bin / 'ld.lld'), '-m', 'elf_i386', '-T', 'link.ld', 'guest.o', '-o', 'guest.elf'], temp)
            for name in ['guest.o', 'guest.elf']:
                artifacts.append(dict(cpu_count=count, name=name, sha256=sha(temp / name)))
            run(f'qemu-{count}', [args.qemu, '-machine', 'pc,accel=tcg', '-cpu', 'Haswell-noTSX', '-smp', f'{count},cores={count},threads=1,sockets=1', '-m', '64M', '-display', 'none', '-serial', 'none', '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-debugcon', f'file:{out / f"records-{count}.bin"}', '-global', 'isa-debugcon.iobase=0xe9', '-kernel', 'guest.elf'], temp, accepted=(33,))
        raw = (out / f'records-{count}.bin').read_bytes()
        assert raw[:8] == b'RAXID001' and raw[-8:] == b'ID_DONE!'
        assert struct.unpack_from('<I', raw, 8)[0] == count
        assert len(raw) == 20 + count * 40
        for index in range(count):
            row = struct.unpack_from('<10I', raw, 12 + index * 40)
            initial = row[2] | (row[3] << 32)
            written = row[4] | (row[5] << 32)
            restored = row[6] | (row[7] << 32)
            assert row[0] == index and row[1] == index and row[9] == index
            assert initial == 0xfee00800 | (256 if index == 0 else 0)
            assert restored == initial
            if row[8] != 0 or written not in (initial, initial ^ 256):
                raise AssertionError(('unknown reference BSP behavior', count, index, row))
            records.append(dict(cpu_count=count, cpu_id=index, initial_apic_id=row[0], topology_id=row[1], mmio_id=row[9], initial_base=initial, written_base=written, restored_base=restored, fault_vector=row[8], primary_bsp_write_matches=written == initial ^ 256 and row[8] == 0))
    report = dict(cpu_observations=len(records), initial_identity_mismatches=0, restored_state_mismatches=0, bsp_write_primary_disagreements=sum(not row['primary_bsp_write_matches'] for row in records), unknown_reference_failures=0, records=records)
    manifest = dict(version=1, tool_sha256=sha(Path(__file__)), guest_source_sha256=sha(source), commands=commands, removed_build_artifacts=artifacts, report=report, scope='Actual QEMU TCG 1/2/4-CPU initial CPUID/MMIO identities and APIC_BASE observations. Writable BSP is assessed against Intel primary sources; disagreements are retained. Not physical Intel validation or complete topology/startup qualification.')
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
