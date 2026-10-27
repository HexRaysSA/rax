#!/usr/bin/env python3
"""Execute scalar RMW guests and optionally compare the actual product planner.

The guest records all GPRs, a 24-byte memory span, and before/after flags.
Only ISA-undefined flags are excluded. Device atomicity and physical Intel
VMX behavior require their separate validation gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def register_encoding(size: int, index: int, locked: bool, opcode: list[int],
                      high: bool = False) -> bytes:
    prefix = [0xf0] if locked else []
    if size == 2:
        prefix.append(0x66)
    rex = (8 if size == 8 else 0) | (4 if index >= 8 else 0)
    if rex or (size == 1 and 4 <= index < 8 and not high):
        prefix.append(0x40 | rex)
    return bytes(prefix + opcode + [((index & 7) << 3) | 7])


def instructions():
    # (instruction bytes, bit-source register, selected bit value, undefined flags)
    for size in [1, 2, 4, 8]:
        for locked in [False, True]:
            for index in range(16):
                for opcode in [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x86]:
                    code = register_encoding(size, index, locked, [opcode + (size != 1)])
                    yield code, None, None, 0x10 if opcode in [0x08, 0x20, 0x30] else 0
                for opcode in [0xb0, 0xc0]:
                    yield register_encoding(size, index, locked, [0x0f, opcode + (size != 1)]), None, None, 0
            for group in [0, 1]:
                prefix = ([0xf0] if locked else []) + ([0x66] if size == 2 else []) + ([0x48] if size == 8 else [])
                yield bytes(prefix + [0xfe if size == 1 else 0xff, (group << 3) | 7]), None, None, 0
            for group in [2, 3]:
                prefix = ([0xf0] if locked else []) + ([0x66] if size == 2 else []) + ([0x48] if size == 8 else [])
                yield bytes(prefix + [0xf6 if size == 1 else 0xf7, (group << 3) | 7]), None, None, 0
            for group in range(7):
                prefix = ([0xf0] if locked else []) + ([0x66] if size == 2 else []) + ([0x48] if size == 8 else [])
                yield bytes(prefix + [0x80 if size == 1 else 0x83, (group << 3) | 7, 0xff]), None, None, 0x10 if group in [1, 4, 6] else 0
    for locked in [False, True]:
        for high in range(4, 8):
            for opcode in [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x86]:
                yield register_encoding(1, high, locked, [opcode], True), None, None, 0x10 if opcode in [0x08, 0x20, 0x30] else 0
            for opcode in [0xb0, 0xc0]:
                yield register_encoding(1, high, locked, [0x0f, opcode], True), None, None, 0
    for size in [2, 4, 8]:
        for locked in [False, True]:
            for index in range(16):
                for bit in [-1, size * 8, size * 8 - 1]:
                    for opcode in [0xab, 0xb3, 0xbb]:
                        yield register_encoding(size, index, locked, [0x0f, opcode]), index, bit, 0x894
            for group in [5, 6, 7]:
                prefix = ([0xf0] if locked else []) + ([0x66] if size == 2 else []) + ([0x48] if size == 8 else [])
                yield bytes(prefix + [0x0f, 0xba, (group << 3) | 7, 0xff]), None, None, 0x894


def corpus() -> bytes:
    cases = bytearray()
    for code, bit_register, bit_value, undefined in instructions():
        for data in [0x123456789abcdef0, 0xedcba9876543210f]:
            for flags in [2, 0x8d7]:
                registers = [0x123456789abcdef0 ^ (i * 0x0101010101010101) for i in range(16)]
                registers[4], registers[7] = 0x400000, 0x200000
                delta = 0
                if bit_register is not None:
                    # RDI is also the address base; retain that alias rather
                    # than changing the encoded data address in the harness.
                    if bit_register != 7:
                        registers[bit_register] = bit_value & ((1 << 64) - 1)
                    size = 8 if 0x48 <= next((b for b in code if 0x40 <= b <= 0x4f), 0) <= 0x4f else 2 if 0x66 in code else 4
                    bits = size * 8
                    value = registers[bit_register] & ((1 << bits) - 1)
                    signed = value - (1 << bits) if value & (1 << (bits - 1)) else value
                    delta = (signed // bits) * size
                cases += struct.pack('<16QQQI16siI', *registers, data, flags, len(code), code,
                                     delta, 0xffffffff ^ undefined)
    assert len(cases) % 172 == 0 and cases
    return bytes(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='New evidence directory')
    parser.add_argument('--llvm-bin', required=True, type=Path)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--product-rlib', type=Path)
    parser.add_argument('--capture', action='store_true', help='Create the absent immutable version1 fixture')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cases = corpus()
    count = len(cases) // 172
    assert count <= 65536, 'Corpus and guest buffers must fit the declared 64 MiB guest'
    (out / 'cases.bin').write_bytes(cases)
    source = Path(__file__).with_name('mmio_guest.s')
    guest = source.read_text().replace('@CASE_COUNT@', str(count))
    guest = guest.replace('RAXMM001', 'RAXRM001').replace('MM_DONE!', 'RM_DONE!')
    guest = guest.replace('movq %rax,0x200000', '''movslq 164(%rsi),%rdx
    addq $0x200000,%rdx
    movq %rax,-8(%rdx)
    movq %rax,(%rdx)
    movq %rax,8(%rdx)''')
    guest = guest.replace('''    movq 0x200000,%rax
    movq %rax,(%rdi)
    movq flags_before(%rip),%rax
    movq %rax,8(%rdi)
    movq flags_after(%rip),%rax
    movq %rax,16(%rdi)
    addq $24,%rdi''', '''    movq current_case(%rip),%rdx
    movslq 164(%rdx),%rdx
    addq $0x200000,%rdx
    movq -8(%rdx),%rax
    movq %rax,(%rdi)
    movq (%rdx),%rax
    movq %rax,8(%rdi)
    movq 8(%rdx),%rax
    movq %rax,16(%rdi)
    movq flags_before(%rip),%rax
    movq %rax,24(%rdi)
    movq flags_after(%rip),%rax
    movq %rax,32(%rdi)
    addq $40,%rdi''')
    guest = guest.replace('addq $168,current_case', 'addq $172,current_case').replace('*152', '*168')
    assert 'movq %rax,32(%rdi)' in guest and 'addq $172,current_case' in guest
    (out / 'guest.s').write_text(guest)
    # Keep the corpus/output buffers clear of the 2 MiB operand, 3 MiB probe
    # code and 4 MiB stack used by the independently executing guest.
    (out / 'link.ld').write_text('ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} . = 0x800000; .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n')
    manifest = {'version': 1, 'cases': count, 'case_bytes': 172, 'record_bytes': 168,
                'unique_inputs': len(set(cases[i:i + 172] for i in range(0, len(cases), 172))),
                'tool_sha256': sha(Path(__file__)), 'parent_guest_sha256': sha(source),
                'scope': 'Actual CPL0 long-mode QEMU RAM instructions;all16GPRs,24memorybytes,defined/unaffectedflags. Product observes the operand as an MMIOhole. Device atomicity and physicalIntelVMX are separate.',
                'commands': []}

    def run(name, command, expected=0, timeout=60):
        started = time.monotonic()
        try:
            result = subprocess.run(command, cwd=out, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            manifest['commands'].append({'name': name, 'args': command, 'code': 'timeout'})
            (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            raise
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        manifest['commands'].append({'name': name, 'args': command, 'code': result.returncode,
                                     'seconds': time.monotonic() - started})
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        if result.returncode != expected:
            raise RuntimeError(f'{name}: expected{expected},got{result.returncode}; retained diagnostics')

    llvm = args.llvm_bin.resolve()
    run('qemu-version', [args.qemu, '--version'])
    run('llvm-version', [str(llvm / 'llvm-mc'), '--version'])
    run('assemble', [str(llvm / 'llvm-mc'), '-triple=i386-none-elf', '-filetype=obj', 'guest.s', '-o', 'guest.o'])
    run('link', [str(llvm / 'ld.lld'), '-m', 'elf_i386', '-T', 'link.ld', 'guest.o', '-o', 'guest.elf'])
    run('qemu', [args.qemu, '-machine', 'pc', '-cpu', 'Haswell-noTSX', '-accel', 'tcg,thread=single',
                 '-m', '64M', '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none',
                 '-debugcon', 'file:' + str(out / 'records.bin'), '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                 '-no-reboot', '-kernel', str(out / 'guest.elf')], 33)
    raw = (out / 'records.bin').read_bytes()
    assert len(raw) == 20 + count * 168 and raw[:8] == b'RAXRM001'
    assert struct.unpack_from('<I', raw, 8)[0] == count and raw[-8:] == b'RM_DONE!'
    if args.product_rlib:
        library = args.product_rlib.resolve()
        dependencies = library.parent / 'deps' if (library.parent / 'deps').is_dir() else library.parent
        consumer = Path(__file__).with_name('mmio_rmw_compare.rs')
        run('compare-build', ['rustc', '+stable', '--edition', '2024', str(consumer), '--extern',
                             'rax=' + str(library), '-L', 'dependency=' + str(dependencies),
                             '-o', str(out / 'compare')])
        manifest['product_library_sha256'] = sha(library)
        manifest['consumer_sha256'] = sha(consumer)
        run('compare', [str(out / 'compare'), str(out / 'cases.bin'), str(out / 'records.bin')])
    manifest['artifact_sha256'] = {name: sha(out / name) for name in ['cases.bin', 'records.bin', 'guest.s', 'guest.elf']}
    manifest['result'] = 'product_match' if args.product_rlib else 'reference_complete'
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    fixture = repo / 'tests/fixtures/hvf/mmio-rmw-v1'
    if args.capture:
        fixture.mkdir(parents=True, exist_ok=False)
        for name in ['cases.bin', 'records.bin', 'manifest.json']:
            (fixture / name).write_bytes((out / name).read_bytes())
    if fixture.exists():
        for name in ['cases.bin', 'records.bin']:
            assert (fixture / name).read_bytes() == (out / name).read_bytes(), f'Frozen {name} differs'
    print(json.dumps({'cases': count, 'result': manifest['result']}))


if __name__ == '__main__':
    main()
