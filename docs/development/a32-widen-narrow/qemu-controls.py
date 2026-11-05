"""Independent complete-count VSHLL/VMOVL and reserved fixed-field controls."""

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    support = here.parent / 'a32-immediate-shifts/qemu-controls.py'
    spec = importlib.util.spec_from_file_location('shift_qemu', support)
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)

    controls = []
    for bits in [8, 16, 32]:
        for unsigned in [0, 1]:
            for count in range(bits):
                for thumb in [False, True]:
                    raw = 0xF2800A12 | (unsigned << 24) | ((bits + count) << 16)
                    controls.append(dict(kind='legal', bits=bits, unsigned=unsigned,
                                         count=count, thumb=thumb, raw=raw, maximum=False))
        for thumb in [False, True]:
            raw = 0xF3B20302 | ([8, 16, 32].index(bits) << 18)
            controls.append(dict(kind='legal', bits=bits, unsigned=1,
                                 count=bits, thumb=thumb, raw=raw, maximum=True))
    reserved = []
    for op in [8, 9, 10]:
        for unsigned in [0, 1]:
            for immediate in [8, 16, 32]:
                for bit6 in [0, 1]:
                    raw = 0xF2800012 | (unsigned << 24) | (immediate << 16)
                    reserved.append(raw | (op << 8) | (1 << 7) | (bit6 << 6))
    for unsigned in [0, 1]:
        for immediate in [8, 16, 32]:
            reserved.append(0xF2800A52 | (unsigned << 24) | (immediate << 16))
    reserved.append(0xF3BE0302)
    for raw in reserved:
        for thumb in [False, True]:
            controls.append(dict(kind='reserved', thumb=thumb, raw=raw))
    rows = [(10, 0, 8, 0, case['thumb'], 0, True) for case in controls]
    source, initial_records = reference.program(rows)
    descriptions = []
    instructions = []
    for index, (case, initial) in enumerate(zip(controls, initial_records, strict=True)):
        raw, thumb = case['raw'], case['thumb']
        if thumb:
            raw = (raw & 0xFFFFFF) | 0xEF000000 | (((raw >> 24) & 1) << 28)
        instructions.append(f" .inst{'.w' if thumb else ''} {raw:#x}")
        expected = initial['expected'][:]
        if case['kind'] == 'legal':
            bits, unsigned, count = case['bits'], case['unsigned'], case['count']
            value = 0xFFFFFFFFFFFFFFFF if index % 5 == 0 else 0x0706050503020100
            mask = (1 << bits) - 1
            wide_mask = (1 << (2 * bits)) - 1
            packed = 0
            for lane in range(64 // bits):
                element = (value >> (lane * bits)) & mask
                if not unsigned and element & (1 << (bits - 1)):
                    element -= 1 << bits
                packed |= ((element << count) & wide_mask) << (lane * 2 * bits)
            expected = ['L', packed & ((1 << 64) - 1), packed >> 64, expected[3]]
        descriptions.append(dict(case, raw=raw, expected=expected))
    iterator = iter(instructions)
    source = re.sub(r'^ \.inst(?:\.w)? 0x[0-9a-f]+$', lambda _: next(iterator), source, flags=re.MULTILINE)
    assert next(iterator, None) is None
    known = json.loads((here / 'arm-assembly.json').read_text())
    known += json.loads((here / 'thumb-assembly.json').read_text())
    assert all(any(case['raw'] == row['raw'] for case in descriptions) for row in known)

    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'guest.S').write_text(source)
    (args.out / 'cases.json').write_text(json.dumps(descriptions, indent=2) + '\n')
    steps = []
    with tempfile.TemporaryDirectory(prefix='rax-widen-qemu-') as temporary:
        scratch = Path(temporary)
        assembly, obj, elf, script = [
            scratch / name for name in ['guest.S', 'guest.o', 'guest.elf', 'guest.ld']
        ]
        assembly.write_text(source)
        script.write_text('ENTRY(_start)\nSECTIONS { . = 0x40010000; .text : { *(.text*) } }\n')
        commands = [
            [
                shutil.which('llvm-mc'), '-triple=armv7a-none-eabi', '-filetype=obj',
                str(assembly), '-o', str(obj),
            ],
            [shutil.which('ld.lld'), '-T', str(script), str(obj), '-o', str(elf)],
            [
                shutil.which('qemu-system-arm'), '-machine', 'virt', '-cpu', 'cortex-a15',
                '-m', '128M', '-nographic', '-monitor', 'none', '-serial', 'stdio',
                '-semihosting', '-kernel', str(elf),
            ],
        ]
        for index, command in enumerate(commands):
            started = time.monotonic()
            result = subprocess.run(command, capture_output=True, timeout=45)
            (args.out / f'phase-{index}.stdout').write_bytes(result.stdout)
            (args.out / f'phase-{index}.stderr').write_bytes(result.stderr)
            steps.append({
                'argv': command, 'exit_code': result.returncode,
                'seconds': time.monotonic() - started,
            })
            assert result.returncode == 0, result.stderr.decode()
        lines = result.stdout.decode().splitlines()
        assert len(lines) == len(descriptions) == 316
        for index, (line, case) in enumerate(zip(lines, descriptions, strict=True)):
            assert len(line) == 41
            words = [int(line[1 + word * 8:9 + word * 8], 16) for word in range(5)]
            actual = [
                line[0], words[0] | words[1] << 32,
                words[2] | words[3] << 32, words[4],
            ]
            assert actual == case['expected'], (index, case, actual)
        executable_sha256 = hashlib.sha256(elf.read_bytes()).hexdigest()
    record = {
        'cases': len(descriptions), 'legal_cases': 230, 'reserved_cases': 86,
        'all_match': True, 'steps': steps,
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'support_sha256': hashlib.sha256(support.read_bytes()).hexdigest(),
        'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'executable_sha256': executable_sha256,
        'observations_sha256': hashlib.sha256(result.stdout).hexdigest(),
        'owned_objects_and_executable_removed': True,
        'scope': 'Actual QEMU Cortex-A15 execution; no physical AArch32 claim.',
    }
    (args.out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
