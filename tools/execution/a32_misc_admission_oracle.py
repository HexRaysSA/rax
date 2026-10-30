#!/usr/bin/env python3
"""Observe A/R-profile FP admission using QEMU system emulation and semihosting."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / 'docs/development/a32-fp-controls/feature-admission/misc-and-fma-cases.json'


def validate_cases(cases, expected_count=86):
    if len(cases) != expected_count:
        raise ValueError('unexpected instruction count')
    for case in cases:
        if case['kind'] not in {'Select', 'Convert', 'Round', 'Number', 'Fused', 'Baseline'}:
            raise ValueError('unknown capability family')
        if type(case['simd']) is not bool:
            raise ValueError('invalid SIMD classification')
        for mode in ['arm', 'thumb']:
            raw, data = case[mode + '_raw'], case[mode + '_bytes']
            if type(raw) is not int or not 0 <= raw < 1 << 32:
                raise ValueError('invalid instruction word')
            if len(data) != 4 or any(type(v) is not int or not 0 <= v < 256 for v in data):
                raise ValueError('invalid instruction bytes')
            encoded = bytes(data)
            if mode == 'thumb':
                encoded = encoded[2:] + encoded[:2]
            if int.from_bytes(encoded, 'little') != raw:
                raise ValueError('instruction word/bytes disagree')


def verify_encodings(output, cases, llvm_mc, thumb):
    name = 'thumb-encodings' if thumb else 'arm-encodings'
    source = output / (name + '.s')
    source.write_text('.syntax unified\n' + ('.thumb\n' if thumb else '.arm\n')
                      + '\n'.join(c['assembly'] for c in cases) + '\n')
    result = run(output, name, [llvm_mc, '--triple=armv8.2a', '-mattr=+fullfp16',
                               '--show-encoding', str(source)])
    encoded = re.findall(r'encoding: \[([^]]+)\]', result.stdout.decode())
    if len(encoded) != len(cases):
        raise ValueError('assembler did not encode the complete instruction matrix')
    mode = 'thumb' if thumb else 'arm'
    for case, field in zip(cases, encoded):
        data = [int(value.strip(), 16) for value in field.split(',')]
        if data != case[mode + '_bytes']:
            raise ValueError(f'{mode} encoding disagrees for {case["assembly"]}')


def guest(cases, thumb):
    lines = ['.syntax unified', '.arm', '.global _start', '.text', '_start:',
             'cpsid if', 'ldr r0, =vectors', 'mcr p15, 0, r0, c12, c0, 0',
             'mov r0, #(3 << 20)', 'mcr p15, 0, r0, c1, c0, 2', 'isb',
             'mov r0, #(1 << 30)', 'vmsr fpexc, r0',
             # MVFR1 is available on all three selected CPU models. Reading
             # MVFR2 can be undefined on pre-v8 CPUs, so its probe is guarded.
             'vmrs r6, mvfr1', 'mov r9, #0', 'mov r7, #0', '.word 0xeef57a10',
             'mov r8, r9', 'mov r5, #8', 'id_loop:',
             'mov r4, r6, lsr #28', 'lsl r6, r6, #4', 'bl hex_digit',
             'subs r5, r5, #1', 'bne id_loop',
             'mov r0, #3', 'ldr r1, =colon', 'svc #0x123456',
             'mov r6, r7', 'mov r5, #8', 'id2_loop:',
             'mov r4, r6, lsr #28', 'lsl r6, r6, #4', 'bl hex_digit',
             'subs r5, r5, #1', 'bne id2_loop',
             'add r8, r8, #48', 'strb r8, [r10]',
             'mov r0, #3', 'mov r1, r10', 'svc #0x123456',
             'mov r0, #3', 'ldr r1, =colon', 'svc #0x123456']
    # r10 is the writable one-byte semihosting buffer used by hex_digit.
    lines.insert(lines.index('vmrs r6, mvfr1'), 'ldr r10, =character')
    if thumb:
        lines += ['ldr r0, =matrix + 1', 'bx r0', '.thumb']
    lines += ['matrix:']
    access_disabled = False
    for case in cases:
        skipped = case.get('predicate_skip', False)
        if skipped and not access_disabled:
            lines += ['mov r0, #0', 'vmsr fpexc, r0',
                      'mcr p15, 0, r0, c1, c0, 2', 'isb']
            access_disabled = True
        lines.append('mov r9, #0')
        if skipped:
            lines += ['mov r0, #1', 'cmp r0, #0']
            if thumb:
                # IT EQ is a real one-instruction IT block. Emit its halfword
                # explicitly because the following instruction is raw data.
                lines.append('.hword 0xbf08')
        raw = case['thumb_raw' if thumb else 'arm_raw']
        if skipped and not thumb:
            if raw >> 28 != 14:
                raise ValueError('predicate probe requires conditional scalar encoding')
            raw &= 0x0fffffff  # EQ; Z is clear, so the instruction is skipped.
        if thumb:
            lines += [f'.hword 0x{raw >> 16:04x}, 0x{raw & 65535:04x}']
        else:
            lines += [f'.word 0x{raw:08x}']
        lines += ['cmp r9, #0', 'ite eq' if thumb else '',
                  'ldreq r1, =passed', 'ldrne r1, =undefined',
                  'mov r0, #3', 'svc #0xab' if thumb else 'svc #0x123456']
    lines += ['mov r0, #0x18', 'ldr r1, =0x20026',
              'svc #0xab' if thumb else 'svc #0x123456', 'b .', '.ltorg', '.arm',
              'hex_digit:', 'cmp r4, #10', 'addlo r4, r4, #48',
              'addhs r4, r4, #87', 'strb r4, [r10]',
              'mov r0, #3', 'mov r1, r10', 'svc #0x123456', 'bx lr',
              '.balign 32', 'vectors:', 'b unexpected', 'b undef_handler',
              'b unexpected', 'b unexpected', 'b unexpected', 'b unexpected',
              'b unexpected', 'b unexpected', 'undef_handler:',
              'mov r9, #1', 'movs pc, lr', 'unexpected:',
              'mov r0, #3', 'ldr r1, =error', 'svc #0x123456',
              'mov r0, #0x18', 'ldr r1, =0x20026', 'svc #0x123456',
              'passed: .byte 80', 'undefined: .byte 85', 'error: .byte 69',
              'colon: .byte 58', 'character: .byte 0', '.ltorg']
    return '\n'.join(line for line in lines if line) + '\n'


def run(output, name, command):
    try:
        result = subprocess.run(command, capture_output=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        (output / (name + '.stdout')).write_bytes(error.stdout or b'')
        (output / (name + '.stderr')).write_bytes(error.stderr or b'')
        (output / (name + '.json')).write_text(json.dumps(
            {'command': command, 'status': 'timeout', 'seconds': error.timeout}, indent=2) + '\n')
        raise
    (output / (name + '.stdout')).write_bytes(result.stdout)
    (output / (name + '.stderr')).write_bytes(result.stderr)
    record = {'command': command, 'code': result.returncode}
    (output / (name + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    if result.returncode:
        raise RuntimeError(f'{name} failed: inspect {output / (name + ".stderr")}')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--llvm-mc', default='llvm-mc')
    parser.add_argument('--ld', default='ld.lld')
    parser.add_argument('--qemu', default='qemu-system-arm')
    args = parser.parse_args()
    inputs = json.loads(CASES.read_text())
    cases, controls = inputs['cases'], inputs['controls']
    validate_cases(cases)
    validate_cases(controls, 40)
    args.output.mkdir(parents=True, exist_ok=False)
    versions = {}
    for name, executable in [('llvm-mc', args.llvm_mc), ('ld', args.ld), ('qemu', args.qemu)]:
        invoked = Path(shutil.which(executable) or executable).absolute()
        path = invoked.resolve(strict=True)
        # LLVM's linker selects its driver from argv[0], including symlink names.
        version = run(args.output, name + '-version', [str(invoked), '--version'])
        versions[name] = {'path': str(path), 'invoked': str(invoked),
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                          'version': version.stdout.decode()}
    for thumb in [False, True]:
        verify_encodings(args.output, cases + controls, args.llvm_mc, thumb)
    predicates = [dict(case, predicate_skip=True) for case in cases
                  if case['kind'] == 'Fused' and not case['simd']]
    if len(predicates) != 8:
        raise ValueError('unexpected conditional scalar fused matrix')
    matrix = cases + controls + predicates
    results = []
    models = [('cortex-a9', 'vexpress-a9', 0x60010000),
              ('cortex-a15', 'virt', 0x40010000), ('max', 'virt', 0x40010000)]
    with tempfile.TemporaryDirectory(prefix='a32-misc-oracle-', dir=os.environ['TMPDIR']) as tmp:
        for model, machine, address in models:
            for thumb in [False, True]:
                name = model + ('-thumb' if thumb else '-arm')
                source = args.output / (name + '.s')
                source.write_text(guest(matrix, thumb))
                obj = str(Path(tmp) / (name + '.o'))
                elf = args.output / (name + '.elf')
                linker = args.output / (name + '.ld')
                linker.write_text('ENTRY(_start)\nSECTIONS { . = ' + hex(address)
                                  + '; .text : { *(.text*) } }\n')
                run(args.output, name + '-assemble',
                    [args.llvm_mc, '--triple=armv8.2a', '-filetype=obj', str(source), '-o', obj])
                run(args.output, name + '-link',
                    [args.ld, '-T', str(linker), obj, '-o', str(elf)])
                result = run(args.output, name,
                             [args.qemu, '-machine', machine, '-cpu', model, '-m', '128M',
                              '-display', 'none', '-monitor', 'none', '-serial', 'none',
                              '-semihosting-config', 'enable=on,target=native',
                              '-kernel', str(elf), '-no-reboot'])
                # QEMU's semihosting console is stderr. Preserve both streams;
                # environmental diagnostics must not be silently normalized.
                raw = result.stderr.decode('ascii')
                if result.stdout:
                    raise RuntimeError(f'{name}: unexpected stdout console data')
                fields = raw.split(':')
                if len(fields) != 3 or len(fields[0]) != 8 or len(fields[1]) != 9:
                    raise RuntimeError(f'{name}: unexpected console {raw!r}')
                mvfr1 = int(fields[0], 16)
                mvfr2 = int(fields[1][:8], 16)
                mvfr2_undefined = int(fields[1][8:])
                expected = ''.join('P' if c.get('predicate_skip', False)
                                   or c['kind'] == 'Baseline'
                                   or (c['kind'] == 'Fused' and not c.get('half', False)
                                       and model != 'cortex-a9')
                                   or model == 'max' else 'U' for c in matrix)
                if len(fields[2]) != len(matrix) or any(c not in 'PU' for c in fields[2]):
                    raise RuntimeError(f'{name}: malformed admission observations {raw!r}')
                differences = [dict(assembly=c['assembly'], expected=e, observed=o)
                               for c, e, o in zip(matrix, expected, fields[2]) if e != o]
                results.append({'model': model, 'machine': machine, 'thumb': thumb,
                                'mvfr1': mvfr1, 'mvfr2': mvfr2,
                                'mvfr2_undefined': mvfr2_undefined,
                                'admission': fields[2], 'count': len(matrix),
                                'capability_count': len(cases), 'predicate_count': len(predicates),
                                'control_count': len(controls),
                                'primary_expectation': expected,
                                'differences_from_primary': differences,
                                'elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest()})
    receipt = {'status': 'observed', 'scope': 'QEMU A/R-profile emulation, not physical ARM execution',
               'cases_sha256': hashlib.sha256(CASES.read_bytes()).hexdigest(),
               'tools': versions,
               'observations': sum(r['count'] for r in results), 'results': results}
    (args.output / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
