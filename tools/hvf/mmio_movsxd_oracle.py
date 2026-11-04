#!/usr/bin/env python3
"""Capture native Linux KVM MOVSXD effects independently of the RAX planner.

Time/storage are O(cases); guest RAM is fixed at 64 MiB. Objects, guest ELF and
the native runner are temporary. The retained records do not prove macOS HVF
exit delivery or device ordering.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def corpus():
    cases = bytearray()
    for bits in [16, 32, 64]:
        for index in range(16):
            code = bytearray([0x66] if bits == 16 else [])
            rex = 0x40 | (8 if bits == 64 else 0) | (4 if index >= 8 else 0)
            if rex != 0x40:
                code.append(rex)
            code.extend([0x63, ((index & 7) << 3) | 7])
            for low in [0, 1, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff]:
                for flags in [2, 0x8d7]:
                    registers = [
                        0x123456789abcdef0 ^ (register * 0x0101010101010101)
                        for register in range(16)
                    ]
                    registers[4], registers[7] = 0x400000, 0x200000
                    data = 0xdeadbeef00000000 | low
                    cases.extend(struct.pack(
                        '<16QQQI16sI', *registers, data, flags, len(code), code, 0
                    ))
    assert len(cases) == 768 * 168
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--llvm-bin', required=True, type=Path)
    parser.add_argument('--capture', action='store_true')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    llvm = args.llvm_bin.resolve()
    template = repo / 'tools/hvf/mmio_guest.s'
    native = repo / 'tools/hvf/mmio_movsxd_native.c'
    cases = corpus()
    (output / 'cases.bin').write_bytes(cases)
    guest = template.read_text().replace('@CASE_COUNT@', '768')
    link = (
        'ENTRY(_start)\nSECTIONS { . = 0x100000; '
        '.multiboot : { *(.multiboot) } .text : { *(.text*) } '
        '. = 0x800000; .rodata : { *(.rodata*) } .data : { *(.data*) } '
        '.bss : { *(.bss*) *(COMMON) } }\n'
    )
    manifest = {
        'version': 1, 'cases': 768, 'unique_instructions': 48,
        'case_bytes': 168, 'record_bytes': 152, 'framing_bytes': 20,
        'guest_ram_bytes': 64 * 1024 * 1024,
        'kernel': platform.release(), 'machine': platform.machine(),
        'tool_sha256': sha(__file__), 'guest_template_sha256': sha(template),
        'native_runner_sha256': sha(native), 'commands': [],
        'scope': 'Actual Linux KVM RAM instructions; no RAX code in the reference runner. Physical Intel macOS HVF and device ordering remain unverified.',
    }
    try:
        with tempfile.TemporaryDirectory(prefix='rax-movsxd-') as directory:
            scratch = Path(directory)
            (scratch / 'cases.bin').write_bytes(cases)
            (scratch / 'guest.s').write_text(guest)
            (scratch / 'link.ld').write_text(link)

            def run(label, command, binary=False, timeout=30):
                started = time.monotonic()
                result = subprocess.run(
                    command, cwd=scratch, capture_output=True, timeout=timeout
                )
                (output / (label + ('.bin' if binary else '.stdout'))).write_bytes(result.stdout)
                (output / (label + '.stderr')).write_bytes(result.stderr)
                manifest['commands'].append({
                    'label': label, 'argv': command, 'exit_code': result.returncode,
                    'seconds': time.monotonic() - started,
                })
                assert result.returncode == 0, (label, result.stderr.decode(errors='replace'))
                return result.stdout

            run('compiler-version', ['gcc', '--version'])
            run('assembler-version', [str(llvm / 'llvm-mc'), '--version'])
            run('assemble', [str(llvm / 'llvm-mc'), '-triple=i386-none-elf', '-filetype=obj', 'guest.s', '-o', 'guest.o'])
            run('link', [str(llvm / 'ld.lld'), '-m', 'elf_i386', '-T', 'link.ld', 'guest.o', '-o', 'guest.elf'])
            run('runner-build', ['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O2', str(native), '-o', 'native'])
            manifest['guest_elf_sha256'] = sha(scratch / 'guest.elf')
            records = run('records', [str(scratch / 'native'), str(scratch / 'guest.elf')], binary=True)
            assert len(records) == 20 + 768 * 152
            assert records[:8] == b'RAXMM001' and records[-8:] == b'MM_DONE!'
            assert struct.unpack_from('<I', records, 8)[0] == 768
            for index in range(768):
                flags = struct.unpack_from('<Q', cases, index * 168 + 136)[0]
                before, after = struct.unpack_from('<QQ', records, 12 + index * 152 + 136)
                assert before == after == flags, (index, flags, before, after)
            manifest['artifact_sha256'] = {
                'cases.bin': sha(output / 'cases.bin'),
                'records.bin': sha(output / 'records.bin'),
            }
        manifest['temporary_artifacts_removed'] = True
        manifest['result'] = 'native_reference_complete'
        fixture = repo / 'tests/fixtures/hvf/mmio-movsxd-v1'
        if args.capture:
            fixture.mkdir(parents=True, exist_ok=False)
            for name in ['cases.bin', 'records.bin']:
                (fixture / name).write_bytes((output / name).read_bytes())
            (fixture / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        else:
            for name in ['cases.bin', 'records.bin']:
                assert (fixture / name).read_bytes() == (output / name).read_bytes(), name
        print(json.dumps({'cases': 768, 'result': manifest['result']}))
    finally:
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
