"""Run all A32/T32 immediate shift counts in a single independent QEMU guest."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


OPERATIONS = [
    (op, u)
    for op in range(8)
    for u in range(2)
    if (op, u) not in [(4, 0), (6, 0)]
]


def lane_reference(source, old, op, unsigned, bits, count):
    mask = (1 << bits) - 1
    result = 0
    saturated = False
    for lane in range(64 // bits):
        value = (source >> (lane * bits)) & mask
        previous = (old >> (lane * bits)) & mask
        signed = value - (1 << bits) if value & (1 << (bits - 1)) else value
        if op <= 3:
            value = value if unsigned else signed
            if op >= 2:
                value += 1 << (count - 1)
            value >>= count
            if op & 1:
                value += previous
        elif op == 4:
            inserted = mask >> count
            value = (previous & ~inserted) | ((value >> count) & inserted)
        elif op == 5:
            value <<= count
            if unsigned:
                value |= previous & ((1 << count) - 1)
        else:
            value = (signed if op == 6 or not unsigned else value) << count
            if op == 7 and not unsigned:
                minimum, maximum = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
            else:
                minimum, maximum = 0, mask
            clamped = min(max(value, minimum), maximum)
            saturated |= value != clamped
            value = clamped
        result |= (value & mask) << (lane * bits)
    return result, saturated


def cases():
    rows = []
    for op, unsigned in OPERATIONS:
        for bits in [8, 16, 32, 64]:
            for count in range(1, bits + 1) if op <= 4 else range(bits):
                for thumb in [False, True]:
                    for q in [0, 1]:
                        rows.append((op, unsigned, bits, count, thumb, q, False))
    for op in [4, 6]:
        for bits in [8, 64]:
            for thumb in [False, True]:
                rows.append((op, 0, bits, bits if op == 4 else 0, thumb, 0, True))
    return rows


def load32(register, value):
    return f" movw {register}, #{value & 65535}\n movt {register}, #{value >> 16}\n"


def program(rows):
    source = """.syntax unified
.arch armv7-a
.fpu neon
.arm
.section .text
.global _start
_start:
 b start
 b undef
 b .
 b .
 b .
 b .
 b .
 b .
start:
 ldr r0, =_start
 mcr p15, 0, r0, c12, c0, 0
 mrc p15, 0, r0, c1, c0, 2
 orr r0, r0, #0x00f00000
 mcr p15, 0, r0, c1, c0, 2
 isb
 mov r0, #0x40000000
 vmsr fpexc, r0
 mov r4, #0x09000000
 b case_start_0
 .ltorg
undef:
 mov r8, #'U'
 mrs r0, spsr
 bic r0, r0, #0x20
 msr spsr_cxsf, r0
 movs pc, r9
record:
 mov r6, lr
 str r8, [r4]
 vmov r0, r1, d0
 bl puthex
 mov r0, r1
 bl puthex
 vmov r0, r1, d1
 bl puthex
 mov r0, r1
 bl puthex
 vmrs r0, fpscr
 bl puthex
 mov r0, #10
 str r0, [r4]
 bx r6
puthex:
 mov r2, #8
1:
 mov r3, r0, lsr #28
 cmp r3, #10
 addlo r3, r3, #'0'
 addhs r3, r3, #('a'-10)
 str r3, [r4]
 lsl r0, r0, #4
 subs r2, r2, #1
 bne 1b
 bx lr
"""
    descriptions = []
    for index, (op, unsigned, bits, count, thumb, q, reserved) in enumerate(rows):
        source += f"case_start_{index}:\n"
        initial = [
            0x9ABCDEF012345678, 0x8000000000000001,
            0x0706050503020100, 0xFEDCBA9876543210,
        ]
        if index % 5 == 0:
            initial[2:] = [0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF]
        m = 0 if index % 3 == 0 else 2
        fpscr = 0x11 | ((1 << 27) if index % 7 == 0 else 0)
        for register, value in enumerate(initial):
            source += load32('r0', value & 0xFFFFFFFF) + load32('r1', value >> 32)
            source += f" vmov d{register}, r0, r1\n"
        source += load32('r0', fpscr) + " vmsr fpscr, r0\n mov r8, #'L'\n"
        immediate = 2 * bits - count if op <= 4 else bits + count
        raw = 0xF2800010 | (unsigned << 24) | ((immediate & 63) << 16)
        raw |= ((immediate >> 6) << 7) | (op << 8) | (q << 6) | m
        source += f" adr r9, after_{index}\n"
        if thumb:
            raw = (raw & 0xFFFFFF) | 0xEF000000 | (unsigned << 28)
            source += f""" ldr r0, 1f
 bx r0
1: .word instruction_{index}
 .thumb
 .thumb_func
instruction_{index}:
 .inst.w {raw:#x}
 bx r9
 .arm
 .balign 4
"""
        else:
            source += f" .inst {raw:#x}\n"
        source += f"after_{index}:\n bl record\n"
        expected = initial[:]
        if not reserved:
            for register in range(q + 1):
                expected[register], saturated = lane_reference(
                    initial[m + register], initial[register], op, unsigned, bits, count
                )
                if saturated:
                    fpscr |= 1 << 27
        descriptions.append({
            'raw': raw, 'op': op, 'unsigned': unsigned, 'bits': bits, 'count': count,
            'thumb': thumb, 'q': q, 'm': m, 'reserved': reserved,
            'expected': ['U' if reserved else 'L', expected[0], expected[1], fpscr],
        })
    source += " mov r0, #0x18\n ldr r1, =0x20026\n svc 0x123456\n b .\n .ltorg\n"
    return source, descriptions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--assembler', default=shutil.which('llvm-mc'))
    parser.add_argument('--linker', default=shutil.which('ld.lld'))
    parser.add_argument('--qemu', default=shutil.which('qemu-system-arm'))
    args = parser.parse_args()
    if not all([args.assembler, args.linker, args.qemu]):
        parser.error('llvm-mc, ld.lld and qemu-system-arm are required')
    if args.limit is not None and args.limit < 1:
        parser.error('--limit must be positive')
    rows = cases()
    if args.limit is not None:
        rows = rows[:args.limit]
    source, descriptions = program(rows)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'guest.S').write_text(source)
    (args.out / 'cases.json').write_text(json.dumps(descriptions, indent=2) + '\n')
    steps = []
    with tempfile.TemporaryDirectory(prefix='rax-shift-qemu-') as temporary:
        scratch = Path(temporary)
        assembly, obj, elf, script = [
            scratch / name for name in ['guest.S', 'guest.o', 'guest.elf', 'guest.ld']
        ]
        assembly.write_text(source)
        script.write_text('ENTRY(_start)\nSECTIONS { . = 0x40010000; .text : { *(.text*) } }\n')
        commands = [
            [
                args.assembler, '-triple=armv7a-none-eabi', '-filetype=obj',
                str(assembly), '-o', str(obj),
            ],
            [args.linker, '-T', str(script), str(obj), '-o', str(elf)],
            [
                args.qemu, '-machine', 'virt', '-cpu', 'cortex-a15', '-m', '128M',
                '-nographic', '-monitor', 'none', '-serial', 'stdio',
                '-semihosting', '-kernel', str(elf),
            ],
        ]
        for index, command in enumerate(commands):
            started = time.monotonic()
            result = subprocess.run(command, capture_output=True, timeout=60)
            (args.out / f'phase-{index}.stdout').write_bytes(result.stdout)
            (args.out / f'phase-{index}.stderr').write_bytes(result.stderr)
            steps.append({
                'argv': command, 'exit_code': result.returncode,
                'seconds': time.monotonic() - started,
            })
            if result.returncode:
                raise RuntimeError(result.stderr.decode())
        elf_hash = hashlib.sha256(elf.read_bytes()).hexdigest()
        output = result.stdout.decode().splitlines()
        assert len(output) == len(descriptions), (len(output), len(descriptions))
        for index, (line, case) in enumerate(zip(output, descriptions, strict=True)):
            assert len(line) == 41, (index, line)
            words = [int(line[1 + i * 8:9 + i * 8], 16) for i in range(5)]
            actual = [
                line[0], words[0] | (words[1] << 32),
                words[2] | (words[3] << 32), words[4],
            ]
            assert actual == case['expected'], (index, case, actual)
    record = {
        'cases': len(descriptions), 'reserved_cases': sum(x['reserved'] for x in descriptions),
        'all_match': True, 'steps': steps, 'owned_compilation_directory_removed': True,
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'guest_source_sha256': hashlib.sha256(source.encode()).hexdigest(), 'elf_sha256': elf_hash,
        'observations_sha256': hashlib.sha256(result.stdout).hexdigest(),
        'scope': 'QEMU Cortex-A15; no physical AArch32 validation.',
    }
    (args.out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
