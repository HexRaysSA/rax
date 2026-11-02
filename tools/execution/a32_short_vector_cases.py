#!/usr/bin/env python3
"""DDI0406C.d D11 bank rules and exact finite inputs; LLVM supplies encodings only."""
from pathlib import Path
import argparse
import json
import math
import re
import shutil
import struct
import subprocess
parser = argparse.ArgumentParser(description='Verify or regenerate primary-derived optional VFP short-vector cases.')
parser.add_argument('--llvm-mc', default=shutil.which('llvm-mc'), required=shutil.which('llvm-mc') is None)
parser.add_argument('--write', action='store_true')
args = parser.parse_args()
r = Path(__file__).resolve().parents[2] / 'docs/development/a32-short-vectors'
ops = [('vadd', 'binary'), ('vsub', 'binary'), ('vmul', 'binary'), ('vdiv', 'binary'), ('vmla', 'binary'), ('vmls', 'binary'), ('vnmla', 'binary'), ('vnmls', 'binary'), ('vnmul', 'binary'), ('vabs', 'unary'), ('vneg', 'unary'), ('vsqrt', 'unary'), ('vmov', 'unary'), ('vmov', 'immediate')]
rows = []

def bits(x, double):
    return int.from_bytes(struct.pack('<d' if double else '<f', x), 'little')

def value(x, double):
    return struct.unpack('<d' if double else '<f', x.to_bytes(8 if double else 4, 'little'))[0]
for double in [False, True]:
    bank = 4 if double else 8
    prefix = 'd' if double else 's'
    precision = 64 if double else 32
    for op, shape in ops:
        for label, d, n, m in [('vector', 29, 21, 13), ('scalar_dest', 1, 21, 13), ('scalar_source', 29, 1 if double else 5, 1), ('upper_scalar', 17 if double else 3, 21, 17 if double else 3)]:
            for length, stride in [(1, 1), (2, 1), (2, 2), (3, 1), (4, 1), (3, 2), (4, 2), (5, 1), (6, 1), (7, 1), (8, 1)]:
                if double and d & 12 != 0 and (length > 4 or (stride == 2 and length > 2)):
                    continue
                asm = f'{op}.f{precision} {prefix}{d},' + (f'{prefix}{n},{prefix}{m}' if shape == 'binary' else f'{prefix}{m}' if shape == 'unary' else '#2.0')
                scalar = lambda reg: reg & (12 if double else 24) == 0
                iterations = 1 if scalar(d) else length
                control = length - 1 << 16 | (3 if stride == 2 else 0) << 20
                initial = [bits(((-1 if i % 2 else 1) if op in ['vabs', 'vneg'] else 1) * 4.0 ** ((i % 4 + i // 4 // 2) % 4 + 1), double) for i in range(32)]
                regs = initial.copy()
                advance = lambda reg, i: reg & ~(bank - 1) | reg + i * stride & bank - 1
                for i in range(iterations):
                    dest = advance(d, i)
                    left = advance(n, i)
                    right = m if scalar(m) else advance(m, i)
                    a = value(regs[left], double)
                    b = value(regs[right], double)
                    acc = value(regs[dest], double)
                    if shape == 'immediate':
                        out = 2.0
                    elif op == 'vadd':
                        out = a + b
                    elif op == 'vsub':
                        out = a - b
                    elif op == 'vmul':
                        out = a * b
                    elif op == 'vdiv':
                        out = a / b
                    elif op == 'vmla':
                        out = acc + a * b
                    elif op == 'vmls':
                        out = acc - a * b
                    elif op == 'vnmla':
                        out = -acc - a * b
                    elif op == 'vnmls':
                        out = -acc + a * b
                    elif op == 'vnmul':
                        out = -(a * b)
                    elif op == 'vabs':
                        out = abs(b)
                    elif op == 'vneg':
                        out = -b
                    elif op == 'vsqrt':
                        out = math.sqrt(b)
                    elif op == 'vmov':
                        out = b
                    else:
                        raise AssertionError(op)
                    regs[dest] = bits(out, double)

                def dregs(rs):
                    return rs if double else [rs[i] | rs[i + 1] << 32 for i in range(0, 32, 2)] + [16045690981097406464 + i for i in range(16, 32)]
                rows.append(dict(name=f'{op}-{shape}-f{precision}-{label}-len{length}-stride{stride}', asm=asm, operation=op, shape=shape, bits=precision, d=d, n=n, m=m, length=length, stride=stride, control=control, initial=dregs(initial), expected=dregs(regs), expected_fpscr=control))
# Encode each distinct assembly form in both instruction sets.
extras = ['vadd.f32 s9,s8,s10', 'vadd.f64 d5,d4,d6', 'vmov.f32 s8,s9', 'vmov.f64 d4,d5', 'vabs.f64 d4,d5', 'vfma.f32 s0,s0,s0', 'vfms.f32 s0,s0,s0', 'vfnma.f32 s0,s0,s0', 'vfnms.f32 s0,s0,s0', 'vmsr fpscr,r0', 'vmrs r1,fpscr', 'vmrs r0,mvfr0', 'vcmp.f32 s0,s0', 'vadd.f32 q0,q0,q0', 'vdiv.f32 s8,s16,s24']
assemblies = list(dict.fromkeys([row['asm'] for row in rows] + extras))
encodings = {}
for thumb in [False, True]:
    source = '.syntax unified\n.arch armv7-a\n.fpu neon-vfpv4\n' + ('.thumb\n' if thumb else '.arm\n') + '\n'.join(assemblies) + '\n'
    a = [args.llvm_mc, '-triple=armv7a-none-eabi', '-show-encoding']
    out = subprocess.run(a, input=source, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    encoded = re.findall('encoding: \\[([^\\]]+)\\]', out.stdout)
    assert len(encoded) == len(assemblies)
    for asm, raw in zip(assemblies, encoded):
        b = bytes((int(x.strip(), 16) for x in raw.split(',')))
        assert len(b) == 4
        word = int.from_bytes(b[:2], 'little') << 16 | int.from_bytes(b[2:], 'little') if thumb else int.from_bytes(b, 'little')
        encodings[asm, thumb] = word
for row in rows:
    row['arm'] = encodings[row['asm'], False]
    row['thumb'] = encodings[row['asm'], True]
result = dict(primary='Arm DDI0406C.d D11.1-4 and Tables D11-1/2', expectations='Independent bank/stride register model with exactly representable finite operands; no RAX arithmetic helpers. Generated expectations are reviewed test inputs, not a physical ARM oracle.', encoding='LLVM23 encodes each assembly form in ARM/Thumb; it does not derive semantic expectations.', cases=rows)
initials = []
compact = []
for row in rows:
    image = row['initial']
    if image not in initials:
        initials.append(image)
    item = {k: v for k, v in row.items() if k not in ['initial', 'expected']}
    item['initial'] = initials.index(image)
    item['changes'] = [[i, x] for i, x in enumerate(row['expected']) if x != image[i]]
    compact.append(item)
result = {k: v for k, v in result.items() if k != 'cases'}
result.update(initials=initials, cases=compact, control_words={asm: dict(arm=encodings[asm, False], thumb=encodings[asm, True]) for asm in extras})
encoded = json.dumps(result, indent=2) + '\n'
target = r / 'cases.json'
if args.write:
    target.write_text(encoded)
else:
    assert target.read_text() == encoded, 'stale short-vector fixture; inspect inputs and regenerate with --write'
print(len(rows), 'semantic cases,', len(assemblies), 'distinct encodings per instruction set; fixture', 'written' if args.write else 'verified')
