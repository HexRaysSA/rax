#!/usr/bin/env python3
"""Independent bare Cortex-A8 witness; compare every register and FPSCR bit."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cases', type=Path, required=True)
parser.add_argument('--out-dir', type=Path, required=True)
parser.add_argument('--llvm-mc', required=True)
parser.add_argument('--ld-lld', required=True)
parser.add_argument('--qemu', required=True)
args = parser.parse_args()
r = args.out_dir
r.mkdir(parents=True, exist_ok=True)
assert not list(r.iterdir()), 'choose an empty owned output directory'
fixture = json.loads(args.cases.read_text())
rows = []
for row in fixture['cases']:
    initial = fixture['initials'][row['initial']]
    expected = initial.copy()
    for index, bits in row['changes']:
        expected[index] = bits
    for thumb in [False, True]:
        rows.append(dict(name=row['name'], asm=row['asm'], thumb=thumb,
                         control=row['control'], initial=initial, expected=expected,
                         expected_fpscr=row['expected_fpscr'], bits=row['bits'],
                         shape=row['shape'], stride=row['stride'], length=row['length']))
# Explicit finite overlap controls exercise iteration order independently of
# the fixture's disjoint-bank data. Their full expected images are retained.
for asm, double, start, length, negative, expected_values in [
    ('vadd.f32 s9,s8,s10', False, 8, 4, False, [1.,4.,8.,13.,19.,6.,7.,8.]),
    ('vadd.f64 d5,d4,d6', True, 4, 4, False, [13.,4.,8.,9.]),
    ('vmov.f32 s8,s9', False, 8, 8, False, [2.,3.,4.,5.,6.,7.,8.,2.]),
    ('vmov.f64 d4,d5', True, 4, 4, False, [2.,3.,4.,2.]),
    ('vabs.f64 d4,d5', True, 4, 4, True, [2.,3.,4.,2.]),
]:
    def write(image, reg, value):
        raw = int.from_bytes(struct.pack('<d' if double else '<f', value), 'little')
        if double:
            image[reg] = raw
        else:
            shift = (reg & 1)*32
            image[reg//2] = (image[reg//2] & ~(0xffffffff << shift)) | (raw << shift)
    initial = [0]*32
    for i in range(len(expected_values)):
        write(initial, start+i, (i+1.)*(-1 if negative else 1))
    expected = initial.copy()
    for i, value in enumerate(expected_values):
        write(expected, start+i, value)
    for thumb in [False, True]:
        rows.append(dict(name='overlap/'+asm, asm=asm, thumb=thumb,
                         control=(length-1)<<16, initial=initial, expected=expected,
                         expected_fpscr=(length-1)<<16, bits=64 if double else 32,
                         shape='binary' if asm.startswith('vadd') else 'unary',
                         stride=1, length=length))
text = '''.syntax unified
.arch armv7-a
.fpu neon-vfpv4
.arm
.section .vectors,"ax"
 b reset
 b undefined
 .rept 6
 b undefined
 .endr
.text
.global _start
_start:
reset:
 ldr r8,=0x101f1000
 mrc p15,0,r0,c1,c0,2
 orr r0,r0,#0x00f00000
 mcr p15,0,r0,c1,c0,2
 isb
 mov r0,#0x40000000
 vmsr fpexc,r0
 vmrs r0,mvfr0
 bl hex
'''
images = []
for index, row in enumerate(rows):
    if row['initial'] not in images:
        images.append(row['initial'])
    image = images.index(row['initial'])
    text += f''' ldr r0,=data{image}
 vldmia r0!,{{d0-d15}}
 vldmia r0!,{{d16-d31}}
 ldr r0,={row['control']}
 vmsr fpscr,r0
'''
    if row['thumb']:
        text += f''' ldr r0,=probe{index}
 orr r0,r0,#1
 bx r0
.thumb
.thumb_func
probe{index}:
 {row['asm']}
 ldr r0,=returned{index}
 bx r0
.arm
.balign 4
returned{index}:
'''
    else:
        text += f" {row['asm']}\n"
    text += f''' vmrs r0,fpscr
 bl hex
 ldr r0,=buffer
 vstmia r0!,{{d0-d15}}
 vstmia r0!,{{d16-d31}}
 ldr r9,=buffer
 mov r10,#64
print{index}:
 ldr r0,[r9],#4
 bl hex
 subs r10,r10,#1
 bne print{index}
 b next{index}
 .ltorg
next{index}:
'''
text += ''' b success
undefined:
 mov r0,#85
 str r0,[r8]
 ldr r1,=failure
 b finish
success:
 ldr r1,=exit_block
finish:
 mov r0,#0x20
 svc #0x123456
 b .
hex:
 mov r2,#8
 mov r3,r0
hex_loop:
 lsr r0,r3,#28
 adr r4,digits
 ldrb r0,[r4,r0]
 str r0,[r8]
 lsl r3,r3,#4
 subs r2,r2,#1
 bne hex_loop
 bx lr
.balign 4
digits: .ascii "0123456789abcdef"
.balign 4
exit_block: .word 0x20026,0
failure: .word 0x20026,1
.ltorg
.data
.balign 8
'''
for i, image in enumerate(images):
    data = b''.join(struct.pack('<Q', value) for value in image)
    text += f'data{i}:\n.byte ' + ','.join(map(str, data)) + '\n'
text += '.balign 8\nbuffer: .space 256\n'
(r/'guest.s').write_text(text)
(r/'guest.ld').write_text('ENTRY(_start)\nSECTIONS { .vectors 0 : { *(.vectors) } .text 0x10000 : { *(.text*) } .data : { *(.data*) } }\n')
commands = [
    [args.llvm_mc, '-triple=armv7a-none-eabi', '-filetype=obj', str(r/'guest.s'), '-o', str(r/'guest.o')],
    [args.ld_lld, '-T', str(r/'guest.ld'), str(r/'guest.o'), '-o', str(r/'guest.elf')],
    [args.qemu, '-machine', 'versatilepb', '-cpu', 'cortex-a8', '-m', '128M',
     '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-nic', 'none',
     '-audio', 'none', '-semihosting-config', 'enable=on,target=native',
     '-device', 'loader,file='+str(r/'guest.elf')+',cpu-num=0'],
]
for index, command in enumerate(commands):
    out = subprocess.run(command, capture_output=True, timeout=120)
    (r/f'command-{index}.stdout').write_bytes(out.stdout)
    (r/f'command-{index}.stderr').write_bytes(out.stderr)
    assert out.returncode == 0, (index, out.returncode, out.stderr.decode(errors='replace'))
raw = out.stdout.decode()
assert int(raw[:8],16) == 0x11110222, 'unexpected Cortex-A8 VFP capabilities'
assert len(raw) == 8 + len(rows)*520, (len(raw), len(rows))
results = []
for index, row in enumerate(rows):
    start = 8 + index*520
    words = [int(raw[start+i*8:start+(i+1)*8], 16) for i in range(65)]
    observed = [words[1+2*i] | (words[2+2*i] << 32) for i in range(32)]
    difference = [[i, row['expected'][i], value] for i, value in enumerate(observed)
                  if value != row['expected'][i]]
    results.append(dict(index=index, name=row['name'], thumb=row['thumb'],
                        bits=row['bits'], shape=row['shape'], stride=row['stride'],
                        length=row['length'], fpscr=words[0],
                        expected_fpscr=row['expected_fpscr'], differences=difference,
                        matched=not difference and words[0] == row['expected_fpscr']))
record = dict(cases=len(rows), matched=sum(row['matched'] for row in results),
              mismatched=sum(not row['matched'] for row in results), mvfr0=raw[:8],
              commands=commands, cases_sha256=hashlib.sha256(args.cases.read_bytes()).hexdigest(),
              guest_source_sha256=hashlib.sha256(text.encode()).hexdigest(),
              raw_output_sha256=hashlib.sha256(out.stdout).hexdigest(), results=results,
              scope='Independent QEMU only. Every register/FPSCR difference is retained; no masking or automatic reclassification as passing.')
(r/'results.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({key:value for key,value in record.items() if key not in ['results','commands']}, indent=2))
