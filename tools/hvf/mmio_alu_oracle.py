#!/usr/bin/env python3
"""Independent QEMU x86 ALU records and optional actual product comparison.

Time/space O(cases); at most 65,536 cases in a declared 64 MiB guest. Generated
objects/executables remain in an automatically removed temporary directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import os
import struct
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def instructions():
    result = {}
    def add(code, logical=False):
        result[bytes(code)] = 0xffffffff ^ (0x10 if logical else 0)
    for size in [1, 2, 4, 8]:
        for index in range(16):
            for opcode in [0x03, 0x13, 0x2b, 0x1b, 0x23, 0x0b, 0x33, 0x3b, 0x85, 0x39]:
                prefix = [0x66] if size == 2 else []
                rex = (8 if size == 8 else 0) | (4 if index >= 8 else 0)
                if rex or (size == 1 and 4 <= index < 8):
                    prefix.append(0x40 | rex)
                add(prefix + [opcode - (size == 1), ((index & 7) << 3) | 7], opcode in [0x23, 0x0b, 0x33, 0x85])
        for index in range(4, 8):
            if size == 1:
                for opcode in [0x02, 0x12, 0x2a, 0x1a, 0x22, 0x0a, 0x32, 0x3a, 0x84, 0x38]:
                    add([opcode, (index << 3) | 7], opcode in [0x22, 0x0a, 0x32, 0x84])
        prefix = [0x66] if size == 2 else [0x48] if size == 8 else []
        width = min(size, 4)
        for value in [0, 1, (1 << (width * 8 - 1)), (1 << (width * 8)) - 1]:
            immediate = list(value.to_bytes(width, 'little'))
            add(prefix + [0x80 if size == 1 else 0x81, 0x3f] + immediate)
            add(prefix + [0xf6 if size == 1 else 0xf7, 0x07] + immediate, True)
        if size != 1:
            for value in [0x7f, 0x80, 0xff]:
                add(prefix + [0x83, 0x3f, value])
    return result


def corpus():
    output = bytearray()
    for code, mask in instructions().items():
        for data in [0, 0xffffffffffffffff, 0x8080808080808080, 0x123456789abcdef0]:
            for flags in [2, 0x8d7]:
                registers = [0x123456789abcdef0 ^ (index * 0x0101010101010101) for index in range(16)]
                registers[4], registers[7] = 0x400000, 0x200000
                output += struct.pack('<16QQQI16sI', *registers, data, flags, len(code), code, mask)
    return bytes(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--llvm-bin', required=True, type=Path)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--product-rlib', type=Path)
    parser.add_argument('--capture', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[2]
    cases = corpus()
    count = len(cases) // 168
    assert cases and len(cases) % 168 == 0 and count <= 65536
    (out / 'cases.bin').write_bytes(cases)
    source = Path(__file__).with_name('mmio_guest.s')
    guest = source.read_text().replace('@CASE_COUNT@', str(count)).replace('RAXMM001', 'RAXAL001').replace('MM_DONE!', 'AL_DONE!')
    (out / 'guest.s').write_text(guest)
    link = 'ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} . = 0x800000; .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n'
    (out / 'link.ld').write_text(link)
    manifest = dict(version=1, cases=count, case_bytes=168, record_bytes=152, framing_bytes=20,
                    unique_instructions=len(instructions()), tool_sha256=sha(__file__),
                    guest_template_sha256=sha(source), generated_guest_sha256=sha(out / 'guest.s'),
                    scope='Actual QEMU CPL0 long-mode RAM ALU instructions; product uses the operand as an MMIO hole. All 16 GPRs, unchanged memory, defined/unaffected flags and RF retirement. Physical Intel VMX/device delivery remains unverified.',
                    commands=[])
    def run(name, argv, expected=0, stdin=None, timeout=60):
        started = time.monotonic()
        try:
            process = subprocess.run(argv, cwd=scratch, input=stdin, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (out / (name + '.stdout')).write_bytes(error.stdout or b'')
            (out / (name + '.stderr')).write_bytes(error.stderr or b'')
            manifest['commands'].append(dict(name=name, argv=argv, cwd=str(scratch), exit_code=None, timeout_seconds=timeout))
            raise
        (out / (name + '.stdout')).write_bytes(process.stdout)
        (out / (name + '.stderr')).write_bytes(process.stderr)
        manifest['commands'].append(dict(name=name, argv=argv, cwd=str(scratch), exit_code=process.returncode, elapsed_seconds=time.monotonic()-started))
        assert process.returncode == expected, (name, process.returncode, expected)
    try:
        with tempfile.TemporaryDirectory(prefix='rax-hvf-alu-', dir=os.environ.get('TMPDIR')) as directory:
            scratch = Path(directory)
            for name in ['cases.bin', 'guest.s', 'link.ld']:
                (scratch / name).write_bytes((out / name).read_bytes())
            llvm = args.llvm_bin.resolve()
            run('qemu-version', [args.qemu, '--version'])
            run('llvm-version', [str(llvm / 'llvm-mc'), '--version'])
            disassembly = ''.join(' '.join(f'0x{byte:02x}' for byte in code) + '\n' for code in instructions())
            run('llvm-encodings', [str(llvm / 'llvm-mc'), '-triple=x86_64', '--disassemble'], stdin=disassembly.encode())
            run('assemble', [str(llvm / 'llvm-mc'), '-triple=i386-none-elf', '-filetype=obj', 'guest.s', '-o', 'guest.o'])
            run('link', [str(llvm / 'ld.lld'), '-m', 'elf_i386', '-T', 'link.ld', 'guest.o', '-o', 'guest.elf'])
            manifest['guest_elf_sha256'] = sha(scratch / 'guest.elf')
            run('qemu', [args.qemu, '-machine', 'pc', '-cpu', 'Haswell-noTSX', '-accel', 'tcg,thread=single', '-m', '64M', '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none', '-debugcon', 'file:' + str(out / 'records.bin'), '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-no-reboot', '-kernel', str(scratch / 'guest.elf')], 33)
            records = (out / 'records.bin').read_bytes()
            assert len(records) == 20 + count * 152 and records[:8] == b'RAXAL001' and records[-8:] == b'AL_DONE!'
            assert struct.unpack_from('<I', records, 8)[0] == count
            if args.product_rlib:
                library = args.product_rlib.resolve()
                deps = library.parent / 'deps' if (library.parent / 'deps').is_dir() else library.parent
                consumer = Path(__file__).with_name('mmio_alu_compare.rs')
                run('compare-build', ['rustc', '+stable', '--edition', '2024', str(consumer), '--extern', 'rax=' + str(library), '-L', 'dependency=' + str(deps), '-o', str(scratch / 'compare')])
                run('compare', [str(scratch / 'compare'), str(out / 'cases.bin'), str(out / 'records.bin')])
                manifest['product_library_sha256'] = sha(library)
                manifest['consumer_sha256'] = sha(consumer)
            manifest['artifact_sha256'] = {name: sha(out / name) for name in ['cases.bin', 'records.bin', 'guest.s', 'link.ld']}
            manifest['result'] = 'product_match' if args.product_rlib else 'reference_complete'
            fixture = repo / 'tests/fixtures/hvf/mmio-alu-read-v1'
            if args.capture:
                fixture.mkdir(parents=True, exist_ok=False)
                for name in ['cases.bin', 'records.bin']:
                    (fixture / name).write_bytes((out / name).read_bytes())
                (fixture / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            if fixture.exists():
                for name in ['cases.bin', 'records.bin']:
                    assert (fixture / name).read_bytes() == (out / name).read_bytes(), ('frozen fixture differs', name)
    finally:
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(cases=count, result=manifest['result'])))


if __name__ == '__main__':
    main()
