#!/usr/bin/env python3
"""Actual A32/T32 ASEDIS/FPEXC Undefined outcomes on a shared ARMv7 subset.

The Cortex-A15 reference covers ASEDIS/FPEXC instruction access, not the modern
profile's reserved D32DIS field, FP16/FHM extensions or virtualization traps.
QEMU11.1 TCG ignores readable ASEDIS: its 44 known disagreements are reported
separately from primary-source access conformance; they are not passing matches.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time
from fp_system_oracle import source_fingerprint

ADVSIMD = ['vadd.i8 q0,q1,q2', 'vadd.f32 q0,q1,q2', 'vmov.i8 q0,#0x7f',
           'vld1.8 {d0,d1},[r0]', 'vst1.8 {d0,d1},[r0]', 'vdup.8 q0,r1',
           'vdup.32 d16,r1', 'vmov.8 d16[3],r1', 'vmov.16 d31[1],r1',
           'vmov.s8 r1,d16[3]', 'vmov.u16 r1,d31[1]']
VFP = ['vadd.f32 s0,s2,s4', 'vadd.f64 d16,d17,d18', 'vmov.32 d16[0],r1',
       'vmov.32 r1,d31[1]', 'vmov s0,r1', 'vmov r1,s31', 'vmov d31,r0,r1',
       'vmov r0,r1,d31', 'vmrs r2,fpscr', 'vmsr fpscr,r2']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guest_source():
    ops = ADVSIMD + VFP
    source = '''.syntax unified
.arm
.global _start
.align 5
_start:
    b init
    b undefined
    b supervisor
    b failed
    b failed
    b failed
    b failed
    b failed
init:
    ldr r0,=_start
    mcr p15,0,r0,c12,c0,0
    mov r7,#0
'''
    cases = []
    for thumb in [False, True]:
        for user in [False, True]:
            for asedis in [False, True]:
                for enabled in [False, True]:
                    for op, instruction in enumerate(ops):
                        case = {'thumb': thumb, 'user': user, 'asedis': asedis,
                                'enabled': enabled, 'instruction': instruction,
                                'expected_undefined': not enabled or (asedis and op < len(ADVSIMD))}
                        cases.append(case)
                        source += f'''
    mov r0,#0xf00000
    mcr p15,0,r0,c1,c0,2
    isb
    mov r0,#{0x40000000 if enabled else 0}
    vmsr fpexc,r0
    ldr r0,={0xf00000 | (int(asedis) << 31):#x}
    mcr p15,0,r0,c1,c0,2
    isb
    mrc p15,0,r3,c1,c0,2
    eor r3,r3,r0
    tst r3,#0x80000000
    bne profile_failed
    ldr r9,={"thumb" if thumb else "arm"}_slot_{op}{"+1" if thumb else ""}
    ldr r0,=data
    ldr r1,=0x12345678
    mov r2,#0
    mov r8,#0
'''
                        if user:
                            source += '    msr cpsr_c,#0x10\n'
                        source += '''    blx r9
    svc #0
    ldr r3,=observed
    add r8,r8,#48
    strb r8,[r3,r7]
    add r7,r7,#1
'''
                        if len(cases) % 16 == 0:
                            source += f'    b next_{len(cases)}\n.ltorg\nnext_{len(cases)}:\n'
    assert len(cases) == 336
    source += '''    cmp r7,#336
    bne failed
    ldr r1,=begin
    mov r0,#4
    svc #0x123456
    ldr r1,=observed
    mov r0,#4
    svc #0x123456
    ldr r1,=done
    mov r0,#4
    svc #0x123456
    mov r2,#0
    b finish
profile_failed:
    ldr r1,=profile_unavailable
    b report_failed
failed:
    ldr r1,=failure
report_failed:
    mov r0,#4
    svc #0x123456
    mov r2,#1
finish:
    ldr r1,=exit_args
    str r2,[r1,#4]
    mov r0,#0x20
    svc #0x123456
    b .
undefined:
    mov r8,#1
    mrs r3,spsr
    tst r3,#32
    addne lr,lr,#2
    movs pc,lr
supervisor:
    mrs r3,spsr
    bic r3,r3,#31
    orr r3,r3,#0x13
    msr spsr_cxsf,r3
    movs pc,lr
.ltorg
'''
    for thumb in [False, True]:
        source += '\n.thumb\n' if thumb else '\n.arm\n'
        for op, instruction in enumerate(ops):
            source += f'{"thumb" if thumb else "arm"}_slot_{op}:\n    {instruction}\n    bx lr\n'
    source += '''.arm
.align 4
data:
    .space 64,0
observed:
    .space 337,0
begin:
    .asciz "RAX_ASEDIS_BEGIN\\n"
done:
    .asciz "\\nRAX_ASEDIS_DONE\\n"
failure:
    .asciz "RAX_ASEDIS_FAILED\\n"
profile_unavailable:
    .asciz "RAX_ASEDIS_REFERENCE_PROFILE_UNAVAILABLE\\n"
.align 2
exit_args:
    .word 0x20026,0
'''
    return source, cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-system-arm')
    parser.add_argument('--reference-only', action='store_true')
    args = parser.parse_args()
    args.repo = args.repo.resolve()
    if not (args.repo/"src/isa/arm/aarch32/cp15.rs").is_file():
        raise ValueError("--repo must name a RAX source checkout")
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    owner = out/'.rax-fp-simd-access'
    if any(out.iterdir()) and (not owner.is_file() or owner.read_text() != 'version=1\n'):
        raise ValueError('Use an empty or owned version1 directory')
    owner.write_text('version=1\n')
    source, cases = guest_source()
    (out/'guest.s').write_text(source)
    (out/'cases.json').write_text(json.dumps(cases, indent=2)+'\n')
    ops = ADVSIMD + VFP
    (out/'instructions.s').write_text('.syntax unified\n.arm\n'+'\n'.join(ops)+'\n.thumb\n'+'\n'.join(ops)+'\n')
    (out/'link.ld').write_text('ENTRY(_start)\nSECTIONS {. = 0x40010000; .text : {*(.text*)}}\n')
    here = Path(__file__).resolve().parent
    manifest = {'version': 1, 'cases': 336, 'commands': [],
                'tool_sha256': digest(Path(__file__)),
                'scope': __doc__, 'reference_cpu': 'cortex-a15',
                'source_fingerprint': source_fingerprint(args.repo.resolve())}
    def run(name, command, expected=0, timeout=60, cwd=None, env=None):
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=cwd or out, env=env, text=True,
                                    capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            manifest['commands'].append({'name': name, 'args': command, 'code': 'timeout', 'seconds': time.monotonic()-start})
            (out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
            raise RuntimeError(f'{name} timed out; no passing result') from None
        (out/(name+'.stdout')).write_text(result.stdout)
        (out/(name+'.stderr')).write_text(result.stderr)
        manifest['commands'].append({'name': name, 'args': command, 'code': result.returncode, 'seconds': time.monotonic()-start})
        (out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        if expected is not None and result.returncode != expected:
            raise RuntimeError(f'{name}:code{result.returncode}; see retained diagnostics')
        return result
    llvm = args.llvm_bin.resolve()
    run('qemu-version', [args.qemu, '--version'])
    run('llvm-version', [str(llvm/'llvm-mc'), '--version'])
    flags = ['-triple=armv8.2a-none-eabi', '-mattr=+neon,+fullfp16,+fp16fml']
    run('encode', [str(llvm/'llvm-mc'), *flags, '-show-encoding', 'instructions.s'])
    run('assemble', [str(llvm/'llvm-mc'), *flags, '-filetype=obj', 'guest.s', '-o', 'guest.o'])
    run('link', [str(llvm/'ld.lld'), '-m', 'armelf', '-T', 'link.ld', 'guest.o', '-o', 'guest.elf'])
    run('qemu', [args.qemu, '-machine', 'virt', '-cpu', 'cortex-a15', '-accel', 'tcg,thread=single', '-m', '128M', '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none', '-semihosting-config', 'enable=on,target=native', '-kernel', str(out/'guest.elf')])
    text = (out/'qemu.stdout').read_text()+(out/'qemu.stderr').read_text()
    matched = re.search(r'RAX_ASEDIS_BEGIN\n([01]{336})\nRAX_ASEDIS_DONE\n', text)
    if not matched:
        raise RuntimeError('Reference did not emit every actual outcome and completion marker')
    observed = [int(b) for b in matched[1]]
    (out/'observed.bin').write_bytes(bytes(observed))
    encoded = re.findall(r'encoding: \[([^\]]+)\]', (out/'encode.stdout').read_text())
    assert len(encoded) == 42
    words = []
    for index, encoding in enumerate(encoded):
        raw = bytes(int(part,16) for part in encoding.split(','))
        assert len(raw) == 4
        words.append((int.from_bytes(raw[:2],'little')<<16)|int.from_bytes(raw[2:],'little') if index >= 21 else int.from_bytes(raw,'little'))
    primary_failed = 0
    with (out/'cases.bin').open('wb') as binary:
        for case, actual in zip(cases, observed):
            index = ops.index(case['instruction']) + (21 if case['thumb'] else 0)
            primary_failed += int(actual != int(case['expected_undefined']))
            binary.write(struct.pack('<IIIIII', int(case['thumb']), int(case['user']), int(case['asedis']), int(case['enabled']), words[index], actual))
    manifest['reference_report'] = {'cases': 336, 'denied': sum(observed), 'allowed': 336-sum(observed), 'primary_failed': primary_failed}
    manifest['artifact_sha256'] = {name:digest(out/name) for name in ['guest.s','guest.elf','cases.json','cases.bin','observed.bin']}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    differences = [i for i,(case,actual) in enumerate(zip(cases,observed)) if actual != int(case['expected_undefined'])]
    known = [i for i,case in enumerate(cases) if case['asedis'] and case['enabled'] and case['instruction'] in ADVSIMD]
    manifest['known_reference_differences'] = differences
    assert differences == known and len(differences) == 44, 'Unexpected reference discrepancy; raw results retained'
    assert sum(observed) == 168
    manifest['reference_report']['primary_matches'] = 292
    manifest['reference_report']['limitation'] = 'Readable ASEDIS is not enforced by this TCG reference; all 44 actual disagreements retained.'
    if args.reference_only:
        manifest['result'] = 'reference_only'
    else:
        if args.target_dir is None:
            raise ValueError('--target-dir is required for product validation')
        env = os.environ.copy()
        env['CARGO_BUILD_JOBS'] = '1'
        env['CARGO_TARGET_DIR'] = str(args.target_dir.resolve())
        run('rax-build', ['cargo','+stable','build','--locked','--offline','--lib','--no-default-features','--features','x86_64-suite,smir-jit'], cwd=args.repo.resolve(), env=env, timeout=1200)
        library = args.target_dir.resolve()/'debug/librax.rlib'
        before = digest(library)
        shutil.copyfile(library,out/'librax.rlib')
        assert before == digest(library) == digest(out/'librax.rlib')
        manifest['rax_library_sha256'] = before
        manifest['comparison_source_sha256'] = digest(here/'fp_simd_access_compare.rs')
        run('compare-build', ['rustc','+stable','--edition=2024',str(here/'fp_simd_access_compare.rs'),'--extern','rax='+str(out/'librax.rlib'),'-L','dependency='+str(library.parent/'deps'),'-o',str(out/'compare')])
        result = run('compare',[str(out/'compare'),str(out/'cases.bin')],expected=None)
        report = json.loads(result.stdout)
        manifest['report'] = report
        assert report['cases']==336 and report['primary_denied']==212 and report['primary_allowed']==124
        assert report['reference_differences']==44 and report['unexpected_reference_differences']==0
        assert result.returncode == int(report['failed'] != 0)
        assert source_fingerprint(args.repo.resolve()) == manifest['source_fingerprint']
        manifest['result'] = 'match' if result.returncode == 0 else 'mismatch'
        (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        if result.returncode:
            return result.returncode
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest.get('report',manifest['reference_report'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
