from pathlib import Path
import subprocess
import json
import hashlib
import datetime

h = Path('/Users/int/dev/rax-audit-work')
out = h / 'four-findings-a32-profile/simd-base-qemu-v2'
llvm = Path('/Users/int/local/bin')
qemu = '/opt/homebrew/bin/qemu-system-arm'
rows = []
(out / 'status.json').write_text(json.dumps({'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'running', 'expected_cases': 44}) + '\n')
(out / 'qualification.json').unlink(missing_ok=True)
for cpu, neon in [('cortex-a15', True), ('cortex-a15,neon=off,vfp-d32=off', False)]:
    for thumb in [False, True]:
        for case in json.loads((h/'four-findings-a32-profile/simd-base-v1/cases.json').read_text()):
            operation, instruction, restricted = case['name'], case['asm'], True
            name = f'neon{int(neon)}-thumb{int(thumb)}-{operation}'
            prefix = out / name
            assembly = '''.syntax unified
.arch armv7-a
.fpu neon-vfpv4
.arm
.text
.global _start
_start:
 b reset
 b undefined
 .rept 6
 b .
 .endr
reset:
 ldr r8,=0x09000000
 ldr r0,=_start
 mcr p15,0,r0,c12,c0,0
 mrc p15,0,r0,c1,c0,2
 orr r0,r0,#0x00f00000
 mcr p15,0,r0,c1,c0,2
 isb
 mov r0,#0x40000000
 vmsr fpexc,r0
 mov r0,#83
 str r0,[r8]
 vmrs r0,mvfr0
 bl hex
 vmrs r0,mvfr1
 bl hex
'''
            if thumb:
                assembly += 'ldr r0,=probe\n orr r0,r0,#1\n bx r0\n.thumb\n.thumb_func\n'
            assembly += 'probe:\n ldr r0,=scratch\n ' + instruction + '\n mov r0,#80\n str r0,[r8]\n'
            assembly += 'ldr r0,=exit\n bx r0\n' if thumb else 'b exit\n'
            assembly += '''.arm
undefined:
 mov r0,#85
 str r0,[r8]
exit:
 mov r0,#0x20
 ldr r1,=exit_block
 svc #0x123456
 b .
hex:
 mov r2,#8
 mov r3,r0
hex_loop:
 lsr r0,r3,#28
 adr r4,hex_digits
 ldrb r0,[r4,r0]
 str r0,[r8]
 lsl r3,r3,#4
 subs r2,r2,#1
 bne hex_loop
 bx lr
.balign 4
hex_digits:
.ascii "0123456789abcdef"
.balign 4
exit_block:
.word 0x20026,0
'''
            assembly += '\n.balign 8\nscratch:\n.space 256\n'
            prefix.with_suffix('.s').write_text(assembly)
            link = out / 'link.ld'
            if not link.exists():
                link.write_text('ENTRY(_start)\nSECTIONS { . = 0x40200000; .text : { *(.text*) } }\n')
            commands = [
                [str(llvm / 'llvm-mc'), '-triple=armv7a-none-eabi', '-filetype=obj', str(prefix.with_suffix('.s')), '-o', str(prefix.with_suffix('.o'))],
                [str(llvm / 'ld.lld'), '-T', str(link), str(prefix.with_suffix('.o')), '-o', str(prefix.with_suffix('.elf'))],
                [qemu, '-machine', 'virt', '-cpu', cpu, '-m', '16M', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-semihosting-config', 'enable=on,target=native', '-device', 'loader,file=' + str(prefix.with_suffix('.elf')) + ',cpu-num=0'],
            ]
            row = {'case': name, 'cpu': cpu, 'thumb': thumb, 'instruction': instruction, 'expected_endpoint': 'U' if restricted and not neon else 'P', 'commands': []}
            for index, args in enumerate(commands):
                try:
                    run = subprocess.run(args, capture_output=True, timeout=20)
                    stdout, stderr, code = run.stdout, run.stderr, run.returncode
                except subprocess.TimeoutExpired as failure:
                    stdout, stderr, code = failure.stdout or b'', failure.stderr or b'', None
                (out / f'{name}-{index}.stdout').write_bytes(stdout)
                (out / f'{name}-{index}.stderr').write_bytes(stderr)
                row['commands'].append({'args': args, 'exit_code': code})
                if index == 2:
                    row['observed'] = stdout.decode(errors='replace')
                    row['matched'] = code == 0 and len(stdout) == 18 and stdout[:1] == b'S' and stdout[-1:] == row['expected_endpoint'].encode()
                if code != 0:
                    break
            rows.append(row)
            (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            print(json.dumps({k: v for k, v in row.items() if k != 'commands'}), flush=True)
versions = {name: subprocess.run(args, capture_output=True, text=True, check=True).stdout for name, args in [('qemu', [qemu, '--version']), ('llvm', [str(llvm / 'llvm-mc'), '--version'])]}
assert len(rows) == 44 and all(row.get('matched', False) for row in rows), 'Inspect raw failed controls; no full passing claim'
(out / 'status.json').write_text(json.dumps({'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'passed', 'matched': 44}) + '\n')
hashes = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p.name != 'qualification.json'}
(out / 'qualification.json').write_text(json.dumps({'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'versions': versions, 'rows': rows, 'matched': sum(row.get('matched', False) for row in rows), 'sha256': hashes, 'scope': 'Independent QEMU profile controls only; no RAX execution or physical A32 proof.'}, indent=2) + '\n')
