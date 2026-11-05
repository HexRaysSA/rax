"""Independent complete-literal and reserved A32/T32 modified-immediate controls."""

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def encoded(raw, thumb):
    if thumb:
        return (raw & 0x00ffffff) | 0xef000000 | (((raw >> 24) & 1) << 28)
    return raw


def literal(cmode, op, value, q, d=0):
    return (0xf2800010 | ((value >> 7) << 24) | (((value >> 4) & 7) << 16)
            | ((d >> 4) << 22) | ((d & 15) << 12) | (cmode << 8)
            | (q << 6) | (op << 5) | (value & 15))


def expansion(cmode, op, value):
    # Element placement from AdvSIMDExpandImm, without RAX helpers.
    if cmode < 8:
        return (value << (8 * (cmode // 2))) * 0x0000000100000001
    if cmode < 12:
        return (value << (8 * ((cmode - 8) // 2))) * 0x0001000100010001
    if cmode == 12:
        return (value * 256 + 255) * 0x0000000100000001
    if cmode == 13:
        return (value * 65536 + 65535) * 0x0000000100000001
    if cmode == 14:
        if op == 0:
            return value * 0x0101010101010101
        return sum(255 << (8 * byte) for byte in range(8) if value & (1 << byte))
    bit6 = (value >> 6) & 1
    scalar = ((value & 128) << 24) | ((1 - bit6) << 30) | ((bit6 * 31) << 25) | ((value & 63) << 19)
    return scalar * 0x0000000100000001


def cases():
    result = []
    for cmode in range(16):
        for op in range(2):
            for value in range(256):
                for q in range(2):
                    for thumb in [False, True]:
                        reserved = cmode == 15 and op == 1
                        result.append(dict(raw=encoded(literal(cmode, op, value, q), thumb),
                                           thumb=thumb, q=q, cmode=cmode, op=op,
                                           value=value, reserved=reserved, kind='canonical'))
    for immediate in range(8, 64):
        for high_literal in range(2):
            for op in range(2):
                for q in range(2):
                    for thumb in [False, True]:
                        raw = literal(11, op, (high_literal << 7) | 2, q) | (immediate << 16)
                        result.append(dict(raw=encoded(raw, thumb), thumb=thumb, q=q,
                                           reserved=True, kind='high_prefix', immediate=immediate))
    for cmode in range(16):
        for op in range(2):
            if cmode == 15 and op == 1:
                continue
            for value in [0, 255]:
                for d in [1, 31]:
                    for thumb in [False, True]:
                        result.append(dict(raw=encoded(literal(cmode, op, value, 1, d), thumb),
                                           thumb=thumb, q=1, reserved=True, kind='odd_q'))
    assert len(result) == 33912
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    support = Path(__file__).resolve().parent.parent / 'a32-immediate-shifts/qemu-controls.py'
    spec = importlib.util.spec_from_file_location('shift_qemu_transport', support)
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    controls = cases()
    source, initialized = reference.program([
        (10, 0, 8, 0, case['thumb'], case['q'], True) for case in controls
    ])
    instructions = iter(f" .inst{'.w' if case['thumb'] else ''} {case['raw']:#x}" for case in controls)
    source = re.sub(r'^ \.inst(?:\.w)? 0x[0-9a-f]+$', lambda _: next(instructions), source, flags=re.MULTILINE)
    assert next(instructions, None) is None
    for case, initial in zip(controls, initialized, strict=True):
        expected = initial['expected'][:]
        if not case['reserved']:
            expected[0] = 'L'
            cmode, op = case['cmode'], case['op']
            immediate = expansion(cmode, op, case['value'])
            for register in range(case['q'] + 1):
                old = expected[register + 1]
                if cmode >= 14:
                    value = immediate
                elif cmode >= 12 or cmode & 1 == 0:
                    value = immediate if op == 0 else ~immediate
                else:
                    value = old | immediate if op == 0 else old & ~immediate
                expected[register + 1] = value & ((1 << 64) - 1)
        case['expected'] = expected
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'cases.json').write_text(json.dumps(controls, indent=2) + '\n')
    steps = []
    with tempfile.TemporaryDirectory(prefix='rax-modimm-qemu-') as temporary:
        scratch = Path(temporary)
        assembly, obj, elf, script = [scratch / name for name in ['guest.S', 'guest.o', 'guest.elf', 'guest.ld']]
        assembly.write_text(source)
        script.write_text('ENTRY(_start)\nSECTIONS { . = 0x40010000; .text : { *(.text*) } }\n')
        commands = [
            [shutil.which('llvm-mc'), '-triple=armv7a-none-eabi', '-filetype=obj', str(assembly), '-o', str(obj)],
            [shutil.which('ld.lld'), '-T', str(script), str(obj), '-o', str(elf)],
            [shutil.which('qemu-system-arm'), '-machine', 'virt', '-cpu', 'cortex-a15', '-m', '128M',
             '-nographic', '-monitor', 'none', '-serial', 'stdio', '-semihosting', '-kernel', str(elf)],
        ]
        for index, command in enumerate(commands):
            started = time.monotonic()
            result = subprocess.run(command, capture_output=True, timeout=45)
            (args.out / f'phase-{index}.stdout').write_bytes(result.stdout)
            (args.out / f'phase-{index}.stderr').write_bytes(result.stderr)
            steps.append(dict(argv=command, exit_code=result.returncode, seconds=time.monotonic() - started))
            assert result.returncode == 0, result.stderr.decode()
        lines = result.stdout.decode().splitlines()
        assert len(lines) == len(controls)
        for index, (line, case) in enumerate(zip(lines, controls, strict=True)):
            assert len(line) == 41, (index, line)
            words = [int(line[1 + word * 8:9 + word * 8], 16) for word in range(5)]
            actual = [line[0], words[0] | words[1] << 32, words[2] | words[3] << 32, words[4]]
            assert actual == case['expected'], (index, case, actual)
        executable_digest = hashlib.sha256(elf.read_bytes()).hexdigest()
    record = {
        'cases': len(controls), 'legal': 31744, 'reserved': 2168, 'all_match': True,
        'steps': steps, 'source_bytes': len(source.encode()),
        'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'support_sha256': hashlib.sha256(support.read_bytes()).hexdigest(),
        'executable_sha256': executable_digest,
        'observations_sha256': hashlib.sha256(result.stdout).hexdigest(),
        'owned_compilation_directory_removed': not scratch.exists(),
        'scope': 'Independent QEMU Cortex-A15; exact completion class, D0/D1 and FPSCR. No physical AArch32 claim.',
    }
    (args.out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
