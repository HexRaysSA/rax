#!/usr/bin/env python3
"""Collect scalar shift/rotate effects using the independent Linux KVM runner.

The versioned corpus uses count boundaries. --exhaustive-counts also checks
every imm8/CL count without adding that larger corpus to the repository.
Guest objects, ELF files and the runner are removed on success or failure.
Time and retained storage are O(cases); each guest uses 64 MiB of RAM.
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


def corpus(exhaustive=False):
    cases = bytearray()
    # Group2 /6 is the alternate SHL encoding; retain it independently.
    for group in range(8):
        for size in [1, 2, 4, 8]:
            bits = size * 8
            counts = range(256) if exhaustive else [
                0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255
            ]
            patterns = [0, 1, 1 << (bits - 1), (1 << bits) - 1,
                        0xa55aa55aa55aa55a, 0x5aa55aa55aa55aa5]
            for form in ['one', 'immediate', 'cl']:
                for count in ([1] if form == 'one' else counts):
                    prefix = ([0x66] if size == 2 else []) + ([0x48] if size == 8 else [])
                    opcode = {'one': 0xd0, 'immediate': 0xc0, 'cl': 0xd2}[form]
                    code = bytes(prefix + [opcode + (size != 1), (group << 3) | 7]
                                 + ([count] if form == 'immediate' else []))
                    masked = count & (63 if size == 8 else 31)
                    effective = masked
                    if group in (2, 3) and size in (1, 2):
                        effective %= bits + 1
                    undefined = 0
                    if group in (4, 5, 6, 7) and masked:
                        undefined |= 0x10  # AF is undefined after a nonzero shift.
                        if group != 7 and masked >= bits:
                            undefined |= 1  # SHL/SHR CF is undefined here.
                    if masked != 1 and effective:
                        undefined |= 0x800  # OF is defined only for masked count1.
                    for pattern in patterns:
                        for flags in [2, 0x8d7]:
                            registers = [0x123456789abcdef0 ^ (i * 0x0101010101010101)
                                         for i in range(16)]
                            registers[4], registers[7] = 0x400000, 0x200000
                            if form == 'cl':
                                registers[1] = (registers[1] & ~255) | count
                            cases.extend(struct.pack('<16QQQI16siI', *registers, pattern,
                                                     flags, len(code), code, 0,
                                                     0xffffffff ^ undefined))
    assert cases and len(cases) % 172 == 0
    return bytes(cases)


def guest_source(template, count):
    guest = template.replace('@CASE_COUNT@', str(count))
    guest = guest.replace('RAXMM001', 'RAXRM001').replace('MM_DONE!', 'RM_DONE!')
    old = 'movq %rax,0x200000'
    assert guest.count(old) == 1
    guest = guest.replace(old, '''movslq 164(%rsi),%rdx
    addq $0x200000,%rdx
    movq %rax,-8(%rdx)
    movq %rax,(%rdx)
    movq %rax,8(%rdx)''')
    old = '''    movq 0x200000,%rax
    movq %rax,(%rdi)
    movq flags_before(%rip),%rax
    movq %rax,8(%rdi)
    movq flags_after(%rip),%rax
    movq %rax,16(%rdi)
    addq $24,%rdi'''
    assert guest.count(old) == 1
    guest = guest.replace(old, '''    movq current_case(%rip),%rdx
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
    assert 'addq $172,current_case' in guest and 'movq %rax,32(%rdi)' in guest
    return guest


def main(*, corpus_fn=corpus, fixture_name='mmio-shifts-v1',
         scope='Physical Linux x86-64 KVM RAM instructions; no RAX code linked. All16GPRs,24memory bytes,defined/unaffected flags. Does not qualify Intel macOS HVF exits or device ordering.',
         extra_sources=None, validate_records=None, description=None):
    parser = argparse.ArgumentParser(description=description or __doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--llvm-bin', required=True, type=Path)
    parser.add_argument('--repo', type=Path, help='Read existing guest/runner sources from this checkout')
    parser.add_argument('--exhaustive-counts', action='store_true')
    parser.add_argument('--capture', action='store_true')
    args = parser.parse_args()
    assert not (args.capture and args.exhaustive_counts)
    repo = args.repo.resolve() if args.repo else Path(__file__).resolve().parents[2]
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    template = repo / 'tools/hvf/mmio_guest.s'
    runner = repo / 'tools/hvf/mmio_movsxd_native.c'
    llvm = args.llvm_bin.resolve()
    cases = corpus_fn(args.exhaustive_counts)
    count = len(cases) // 172
    (output / 'cases.bin').write_bytes(cases)
    record = dict(version=1, cases=count, case_bytes=172, record_bytes=168,
                  exhaustive_counts=args.exhaustive_counts,
                  kernel=platform.release(), machine=platform.machine(),
                  cpuinfo=Path('/proc/cpuinfo').read_text().split('\n\n')[0],
                  sources={'tools/hvf/mmio_shift_oracle.py': sha(__file__),
                           'tools/hvf/mmio_guest.s': sha(template),
                           'tools/hvf/mmio_movsxd_native.c': sha(runner)},
                  commands=[],
                  scope=scope)
    record['sources'].update(extra_sources or {})
    try:
        with tempfile.TemporaryDirectory(prefix='rax-mmio-shift-') as directory:
            scratch = Path(directory)

            def run(label, command):
                started = time.monotonic()
                result = subprocess.run(command, cwd=scratch, capture_output=True, timeout=60)
                (output / (label + '.stdout')).write_bytes(result.stdout)
                (output / (label + '.stderr')).write_bytes(result.stderr)
                record['commands'].append(dict(label=label, argv=command,
                                                exit_code=result.returncode,
                                                seconds=time.monotonic() - started))
                assert result.returncode == 0, (label, result.stderr.decode(errors='replace'))
                return result.stdout

            run('compiler-version', ['gcc', '--version'])
            run('assembler-version', [str(llvm / 'llvm-mc'), '--version'])
            run('runner-build', ['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O2',
                                 str(runner), '-o', str(scratch / 'native')])
            (scratch / 'link.ld').write_text(
                'ENTRY(_start)\nSECTIONS { . = 0x100000; .multiboot : { *(.multiboot) } '
                '.text : { *(.text*) } . = 0x800000; .rodata : { *(.rodata*) } '
                '.data : { *(.data*) } .bss : { *(.bss*) *(COMMON) } }\n')
            # Each batch stays below the runner's1MiB retained-output bound.
            observations = bytearray(b'RAXRM001' + struct.pack('<I', count))
            for index, offset in enumerate(range(0, len(cases), 4096 * 172)):
                batch = cases[offset:offset + 4096 * 172]
                batch_count = len(batch) // 172
                (scratch / 'cases.bin').write_bytes(batch)
                (scratch / 'guest.s').write_text(guest_source(template.read_text(), batch_count))
                run(f'assemble-{index}', [str(llvm / 'llvm-mc'), '-triple=i386-none-elf',
                                        '-filetype=obj', 'guest.s', '-o', 'guest.o'])
                run(f'link-{index}', [str(llvm / 'ld.lld'), '-m', 'elf_i386', '-T', 'link.ld',
                                    'guest.o', '-o', 'guest.elf'])
                raw = run(f'native-{index}', [str(scratch / 'native'), str(scratch / 'guest.elf')])
                assert len(raw) == 20 + batch_count * 168
                assert raw[:8] == b'RAXRM001' and raw[-8:] == b'RM_DONE!'
                assert struct.unpack_from('<I', raw, 8)[0] == batch_count
                observations.extend(raw[12:-8])
            observations.extend(b'RM_DONE!')
            (output / 'records.bin').write_bytes(observations)
            assert len(observations) == 20 + count * 168
            for index in range(count):
                assert struct.unpack_from('<Q', cases, index * 172 + 136)[0] == \
                    struct.unpack_from('<Q', observations, 12 + index * 168 + 152)[0]
            if validate_records is not None:
                validate_records(cases, bytes(observations))
        record['owned_build_artifacts_removed'] = not Path(directory).exists()
        record['artifact_sha256'] = {name: sha(output / name) for name in ['cases.bin', 'records.bin']}
        record['result'] = 'native_reference_complete'
        if args.capture:
            fixture = repo / 'tests/fixtures/hvf' / fixture_name
            fixture.mkdir(parents=True, exist_ok=False)
            for name in ['cases.bin', 'records.bin']:
                (fixture / name).write_bytes((output / name).read_bytes())
            (fixture / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(dict(cases=count, result=record['result'])))
    finally:
        (output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
