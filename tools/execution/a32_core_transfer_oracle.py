#!/usr/bin/env python3
"""Observe A32/T32 core-extension transfers on QEMU Cortex-A15."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[2]
FORMS = [
    (0xee000a10, 32, False, True), (0xee100a10, 32, True, True),
    (0xee000b10, 32, False, True), (0xee100b10, 32, True, True),
    (0xee000b30, 16, False, True), (0xee100b30, 16, True, False),
    (0xee900b30, 16, True, True), (0xee400b10, 8, False, True),
    (0xee500b10, 8, True, False), (0xeed00b10, 8, True, True),
]
VECTORS = [0x8877665590f0b180 ^ (index * 0x0101010101010101) for index in range(32)]
RECORD = struct.Struct('<6I32Q')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def transfer_cases():
    cases = []
    for thumb in [False, True]:
        for word, bits, read, unsigned in FORMS:
            single = (word >> 8) & 15 == 10
            for fp in [0, 31]:
                for last in ([False] if single else [False, True]):
                    for rt in [0, 12, 14]:
                        bank = (((fp >> 1) << 16) | ((fp & 1) << 7) if single
                                else ((fp & 15) << 16) | ((fp >> 4) << 7))
                        raw = (word & ~0xf0080) | bank | (rt << 12)
                        shift = (fp & 1) * 32 if single else (64 - bits if last else 0)
                        if last and not single:
                            raw |= 1 << 21
                            if bits != 32:
                                raw |= 1 << 6
                                if bits == 8:
                                    raw |= 1 << 5
                        cases.append(dict(raw=raw, thumb=thumb, bits=bits, read=read,
                                          unsigned=unsigned, fp=fp, rt=rt,
                                          shift=shift, single=single))
    assert len(cases) == 216
    return cases


def guest(cases, result_path):
    code = ['.syntax unified', '.fpu neon', '.arm', '.global _start',
            '.type _start,%function', '_start:',
            'mrc p15,0,r0,c1,c0,2', 'orr r0,r0,#0xf00000',
            'mcr p15,0,r0,c1,c0,2', 'isb', 'mov r0,#0x40000000', 'vmsr fpexc,r0']

    def immediate(register, value):
        code.extend([f'movw r{register},#{value & 65535}',
                     f'movt r{register},#{value >> 16}'])

    def address(register, label):
        code.extend([f'movw r{register},#:lower16:{label}',
                     f'movt r{register},#:upper16:{label}'])

    for index, case in enumerate(cases):
        if index == len(cases) // 2:
            address(2, 'thumb_start+1')
            code.extend(['bx r2', '.thumb', '.balign 2', 'thumb_start:'])
        address(2, 'initial_vectors')
        code.extend(['vldmia r2!,{d0-d15}', 'vldmia r2!,{d16-d31}'])
        for register, value in [(0, 0x10203040), (12, 0x50607080), (14, 0x90a0b0c0)]:
            immediate(register, 0xdead89a5 if register == case['rt'] else value)
        immediate(4, 0xa800009f)
        code.append('vmsr fpscr,r4')
        code.append(('.inst.w ' if case['thumb'] else '.inst ') + hex(case['raw']))
        address(3, f'output_record_{index}')
        code.extend(['str r0,[r3,#8]', 'str r12,[r3,#12]', 'str r14,[r3,#16]',
                     'vmrs r4,fpscr', 'str r4,[r3,#20]', 'add r2,r3,#24',
                     'vstmia r2!,{d0-d15}', 'vstmia r2!,{d16-d31}'])
    address(2, 'arm_finish')
    code.extend(['bx r2', '.arm', '.balign 4', 'arm_finish:', 'mov r0,#1'])
    address(1, 'open_args')
    code.extend(['svc #0x123456', 'cmp r0,#-1', 'beq failed', 'mov r8,r0'])
    address(1, 'write_args')
    code.extend(['str r8,[r1]', 'mov r0,#5', 'svc #0x123456', 'cmp r0,#0', 'bne failed'])
    address(1, 'close_args')
    code.extend(['str r8,[r1]', 'mov r0,#2', 'svc #0x123456', 'cmp r0,#0', 'bne failed'])
    address(1, 'success')
    code.extend(['mov r0,#4', 'svc #0x123456', 'mov r2,#0', 'b finish',
                 'failed:', 'mov r2,#1', 'finish:'])
    address(1, 'exit_args')
    code.extend(['str r2,[r1,#4]', 'mov r0,#0x20', 'svc #0x123456', 'b .',
                 'success:', '.asciz "RAX_TRANSFER_ORACLE_OK\\n"', 'filename:',
                 '.byte ' + ','.join(str(value) for value in os.fsencode(result_path)),
                 'filename_end:', '.byte 0', '.balign 4', 'open_args:',
                 '.word filename,5,filename_end-filename', 'write_args:',
                 f'.word 0,output,{len(cases) * RECORD.size}', 'close_args:', '.word 0',
                 'exit_args:', '.word 0x20026,0', '.balign 8', 'initial_vectors:'])
    code.extend('.quad ' + hex(value) for value in VECTORS)
    code.extend(['.balign 8', 'output:'])
    for index, case in enumerate(cases):
        code.extend([f'output_record_{index}:',
                     f'.word {case["raw"]},{int(case["thumb"])}', '.space 272'])
    return '\n'.join(code) + '\n'


def compare(cases, data):
    if len(data) != len(cases) * RECORD.size:
        raise ValueError('incomplete or oversized oracle records')
    differences = []
    for index, case in enumerate(cases):
        record = RECORD.unpack_from(data, index * RECORD.size)
        raw, thumb, r0, r12, r14, fpscr, *actual = record
        if raw != case['raw'] or thumb != case['thumb']:
            raise ValueError(f'record {index} has the wrong instruction identity')
        registers = {0: 0x10203040, 12: 0x50607080, 14: 0x90a0b0c0}
        registers[case['rt']] = 0xdead89a5
        wanted = VECTORS.copy()
        register = case['fp'] // 2 if case['single'] else case['fp']
        low_mask = (1 << case['bits']) - 1
        if case['read']:
            value = (wanted[register] >> case['shift']) & low_mask
            if not case['unsigned'] and value & (1 << (case['bits'] - 1)):
                value -= 1 << case['bits']
            registers[case['rt']] = value & 0xffffffff
        else:
            mask = low_mask << case['shift']
            wanted[register] = ((wanted[register] & ~mask)
                                | ((registers[case['rt']] & low_mask) << case['shift']))
        expected_registers = [registers[number] for number in [0, 12, 14]]
        if [r0, r12, r14] != expected_registers or actual != wanted or fpscr != 0xa800009f:
            differences.append(dict(index=index, case=case, actual_registers=[r0, r12, r14],
                                    expected_registers=expected_registers, actual_vectors=actual,
                                    expected_vectors=wanted, fpscr=fpscr))
    return differences


def run(output, label, argv, commands):
    record = dict(label=label, argv=argv,
                  utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    commands.append(record)
    try:
        result = subprocess.run(argv, cwd=output, capture_output=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        (output / (label + '.stdout')).write_bytes(error.stdout or b'')
        (output / (label + '.stderr')).write_bytes(error.stderr or b'')
        record.update(status='timeout', timeout_seconds=error.timeout)
        raise
    (output / (label + '.stdout')).write_bytes(result.stdout)
    (output / (label + '.stderr')).write_bytes(result.stderr)
    record.update(status='terminal', exit_code=result.returncode)
    if result.returncode:
        raise RuntimeError(f'{label} exited with {result.returncode}; see {label}.stderr')
    return result


def executable(name):
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(name)
    # LLVM's shared linker binary selects its driver from argv[0] (ld.lld).
    return os.path.abspath(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--llvm-mc', default='llvm-mc')
    parser.add_argument('--ld', default='ld.lld')
    parser.add_argument('--qemu', default='qemu-system-arm')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT / 'target'):
        parser.error('select a scratch directory outside the repository target directory')
    llvm_mc, linker, qemu = map(executable, [args.llvm_mc, args.ld, args.qemu])
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    receipt = dict(status='running', commands=commands,
                   scope='QEMU Cortex-A15 software oracle; no physical A32 execution')
    try:
        cases = transfer_cases()
        (output / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
        (output / 'guest.s').write_text(guest(cases, output / 'results.bin'))
        (output / 'link.ld').write_text(
            'ENTRY(_start)\nPHDRS { ram PT_LOAD FLAGS(7); }\n'
            'SECTIONS { . = 0x40010000; .text : { *(.text*) *(.rodata*) *(.data*) } :ram '
            '.bss : { *(.bss*) *(COMMON) } :ram }\n')
        receipt['tool_versions'] = {}
        for name, tool in [('llvm-mc', llvm_mc), ('ld', linker), ('qemu', qemu)]:
            version = run(output, name + '-version', [tool, '--version'], commands)
            receipt['tool_versions'][name] = version.stdout.decode(errors='replace')
        run(output, 'assemble', [llvm_mc, '-triple=armv7-none-eabi', '-mattr=+neon',
                                 '-filetype=obj', 'guest.s', '-o', 'guest.o'], commands)
        run(output, 'link', [linker, '-m', 'armelf', '-T', 'link.ld', 'guest.o',
                             '-o', 'guest.elf'], commands)
        result = run(output, 'qemu', [qemu, '-machine', 'virt', '-cpu', 'cortex-a15',
                     '-accel', 'tcg,thread=single', '-m', '128M', '-nodefaults',
                     '-display', 'none', '-monitor', 'none', '-serial', 'none',
                     '-semihosting-config', 'enable=on,target=native',
                     '-kernel', str(output / 'guest.elf')], commands)
        if b'RAX_TRANSFER_ORACLE_OK' not in result.stdout + result.stderr:
            raise RuntimeError('guest did not report successful semihosting completion')
        data = (output / 'results.bin').read_bytes()
        differences = compare(cases, data)
        receipt.update(cases=len(cases), result_bytes=len(data), differences=differences,
                       result_sha256=hashlib.sha256(data).hexdigest())
        if differences:
            raise RuntimeError(f'{len(differences)} oracle differences')
        receipt['status'] = 'qualified'
    except BaseException as error:
        receipt.update(status='failed', error=repr(error))
        raise
    finally:
        inputs = [Path(__file__), Path(llvm_mc), Path(linker), Path(qemu),
                  ROOT / 'docs/architecture/arm/asl/arm_instrs.asl']
        inputs += [output / name for name in ['cases.json', 'guest.s', 'link.ld',
                                              'guest.o', 'guest.elf']]
        receipt['inputs_sha256'] = {str(path): digest(path) for path in inputs if path.is_file()}
        receipt['build_cleanup'] = []
        for name in ['guest.o', 'guest.elf']:
            path = output / name
            if path.exists():
                receipt['build_cleanup'].append(dict(name=name, bytes=path.stat().st_size,
                                                      sha256=digest(path)))
                path.unlink()
        receipt['utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status=receipt['status'], cases=receipt['cases'],
                          differences=len(receipt['differences']),
                          result_sha256=receipt['result_sha256'])))


if __name__ == '__main__':
    main()
