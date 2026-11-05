#!/usr/bin/env python3
"""Independent Intel KVM BT records; no RAX code is linked into the guest.

Time/storage O(cases). The checked-in boundary corpus occupies about 1 MiB;
--exhaustive-immediates checks every imm8 separately. Compiled artifacts are
scoped to a temporary directory and removed on success or failure.
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

from mmio_shift_oracle import guest_source as rmw_guest_source


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def guest_source(template, count):
    guest = rmw_guest_source(template, count)
    old = '''movq %rax,-8(%rdx)
    movq %rax,(%rdx)
    movq %rax,8(%rdx)'''
    assert guest.count(old) == 1
    return guest.replace(old, '''movq %rax,(%rdx)
    movabsq $0xa55aa55aa55aa55a,%rcx
    xorq %rax,%rcx
    movq %rcx,-8(%rdx)
    notq %rax
    movq %rax,8(%rdx)''')


def corpus(exhaustive=False):
    cases = bytearray()
    for size in [2, 4, 8]:
        bits = size * 8
        prefix = ([0x66] if size == 2 else [])
        offsets = [-32768, -129, -65, -64, -33, -32, -17, -16, -1,
                   0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 32767]
        forms = []
        for source in [0, 1, 8, 15]:
            rex = (8 if size == 8 else 0) | (4 if source >= 8 else 0)
            code = prefix + ([0x40 | rex] if rex else []) + [0x0f, 0xa3, ((source & 7) << 3) | 7]
            for offset in offsets:
                forms.append((bytes(code), source, offset, (offset // bits) * size))
        immediates = range(256) if exhaustive else [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255]
        for immediate in immediates:
            code = prefix + ([0x48] if size == 8 else []) + [0x0f, 0xba, 0x27, immediate]
            forms.append((bytes(code), None, 0, 0))
        for code, source, offset, delta in forms:
            for memory in [0, 0xffffffffffffffff, 0x8080808080808080, 0x123456789abcdef0]:
                for flags in [2, 0x8d7]:
                    registers = [0x123456789abcdef0 ^ (i * 0x0101010101010101) for i in range(16)]
                    registers[4], registers[7] = 0x400000, 0x200000
                    if source is not None:
                        # Dirty upper bits test operand-width sign extraction.
                        mask = (1 << bits) - 1
                        registers[source] = (registers[source] & ~mask) | (offset & mask)
                    # CF defined, ZF/unrelated bits unaffected; OF/SF/AF/PF undefined.
                    mask = 0xffffffff ^ (0x800 | 0x80 | 0x10 | 0x4)
                    cases.extend(struct.pack('<16QQQI16siI', *registers, memory, flags,
                                             len(code), code, delta, mask))
    assert cases and len(cases) % 172 == 0
    return bytes(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--llvm-bin', required=True, type=Path)
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--exhaustive-immediates', action='store_true')
    parser.add_argument('--capture', action='store_true')
    args = parser.parse_args()
    assert not (args.capture and args.exhaustive_immediates)
    repo = args.repo.resolve() if args.repo else Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cases = corpus(args.exhaustive_immediates)
    count = len(cases) // 172
    (out / 'cases.bin').write_bytes(cases)
    inputs = ['tools/hvf/mmio_bt_oracle.py', 'tools/hvf/mmio_shift_oracle.py',
              'tools/hvf/mmio_guest.s', 'tools/hvf/mmio_movsxd_native.c']
    record = dict(version=1, cases=count, case_bytes=172, record_bytes=168,
                  exhaustive_immediates=args.exhaustive_immediates,
                  kernel=platform.release(), machine=platform.machine(),
                  cpuinfo=Path('/proc/cpuinfo').read_text().split('\n\n')[0],
                  source_sha256={name: sha(repo / name) for name in inputs}, commands=[],
                  scope='Physical Intel Linux KVM BT RAM instructions, independent of RAX. All16GPRs,24unchanged memory bytes,CF and unaffected flags. No Intel macOS HVF or device-cycle proof.')
    try:
        with tempfile.TemporaryDirectory(prefix='rax-mmio-bt-') as directory:
            scratch = Path(directory)

            def run(label, argv):
                started = time.monotonic()
                result = subprocess.run(argv, cwd=scratch, capture_output=True, timeout=60)
                (out / (label + '.stdout')).write_bytes(result.stdout)
                (out / (label + '.stderr')).write_bytes(result.stderr)
                record['commands'].append(dict(label=label, argv=argv, exit_code=result.returncode,
                                                seconds=time.monotonic() - started))
                assert result.returncode == 0, (label, result.stderr.decode(errors='replace'))
                return result.stdout

            llvm = args.llvm_bin.resolve()
            run('compiler-version', ['gcc', '--version'])
            run('assembler-version', [str(llvm / 'llvm-mc'), '--version'])
            run('runner-build', ['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O2',
                                 str(repo / inputs[-1]), '-o', str(scratch / 'native')])
            (scratch / 'link.ld').write_text(
                'ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} '
                '.text : {*(.text*)} . = 0x800000; .rodata : {*(.rodata*)} '
                '.data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n')
            records = bytearray(b'RAXRM001' + struct.pack('<I', count))
            for index, offset in enumerate(range(0, len(cases), 4096 * 172)):
                batch = cases[offset:offset + 4096 * 172]
                (scratch / 'cases.bin').write_bytes(batch)
                (scratch / 'guest.s').write_text(guest_source((repo / inputs[2]).read_text(), len(batch) // 172))
                run(f'assemble-{index}', [str(llvm / 'llvm-mc'), '-triple=i386-none-elf',
                                        '-filetype=obj', 'guest.s', '-o', 'guest.o'])
                run(f'link-{index}', [str(llvm / 'ld.lld'), '-m', 'elf_i386', '-T', 'link.ld',
                                    'guest.o', '-o', 'guest.elf'])
                native = run(f'native-{index}', [str(scratch / 'native'), str(scratch / 'guest.elf')])
                assert len(native) == 20 + len(batch) // 172 * 168
                assert native[:8] == b'RAXRM001' and native[-8:] == b'RM_DONE!'
                assert struct.unpack_from('<I', native, 8)[0] == len(batch) // 172
                records.extend(native[12:-8])
            records.extend(b'RM_DONE!')
            (out / 'records.bin').write_bytes(records)
            for i, case in enumerate(struct.iter_unpack('<16QQQI16siI', cases)):
                observed = records[12 + i * 168:12 + (i + 1) * 168]
                assert observed[:128] == cases[i * 172:i * 172 + 128], ('GPR mutation', i)
                expected = struct.pack('<3Q', case[16] ^ 0xa55aa55aa55aa55a,
                                       case[16], case[16] ^ 0xffffffffffffffff)
                assert observed[128:152] == expected, ('memory mutation', i)
                assert struct.unpack_from('<Q', observed, 152)[0] == case[17], ('entry flags', i)
        record['owned_build_artifacts_removed'] = not Path(directory).exists()
        record['artifact_sha256'] = {name: sha(out / name) for name in ['cases.bin', 'records.bin']}
        record['result'] = 'native_reference_complete'
        if args.capture:
            fixture = repo / 'tests/fixtures/hvf/mmio-bit-test-v1'
            fixture.mkdir(parents=True, exist_ok=False)
            for name in ['cases.bin', 'records.bin']:
                (fixture / name).write_bytes((out / name).read_bytes())
            (fixture / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(dict(cases=count, result=record['result'])))
    finally:
        (out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
