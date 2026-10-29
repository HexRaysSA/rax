#!/usr/bin/env python3
"""Independently execute optional SVE and scalar SME access profiles in QEMU."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WORDS = (0x45420020, 0x4502b020, 0x64628020, 0x45029820, 0x64a2e420,
         0x052b2420, 0x65020020, 0x45026820, 0x4522e020)
SME_SCALAR = (0x04bf5820, 0x04215820, 0x04615820)


def cases():
    result = []

    def add(name, word, model, zen=3, smen=0, expected='13cA0', init=True):
        result.append(dict(name=name, opcode=word, model=model, zen=zen, smen=smen,
                           expected=expected, init_sve=init))

    for word in WORDS:
        add('permitted', word, 'max,sve-max-vq=1,sme=off')
        add('denied', word, 'max,sve-max-vq=1,sme=off', zen=0, expected='119I0')
        for zen in (0, 3):
            add('both-absent', word, 'max,sve=off,sme=off', zen=zen,
                expected='100I0', init=False)
    for word in SME_SCALAR:
        for zen in (0, 3):
            add('scalar-sme-denied', word, 'max,sve-max-vq=1', zen=zen,
                expected='11dI0')
            add('scalar-sme-absent', word, 'max,sve-max-vq=1,sme=off', zen=zen,
                expected='100I0')
        add('scalar-sme-permitted', word, 'max,sve-max-vq=1', zen=0, smen=3)
    return result


def scalar_value_cases():
    """Boundary immediates, wrap, SP/XZR and source/destination overlap."""
    result = []
    initial_sp = 0x8000
    initial_base = 0xffff_ffff_ffff_fff0

    def add(kind, imm, rd=0, rn=1):
        base_opcode = {'rdsvl': 0x04bf5800, 'addsvl': 0x04205800,
                       'addspl': 0x04605800}[kind]
        word = base_opcode | ((imm & 63) << 5) | rd
        if kind != 'rdsvl':
            word |= rn << 16
        unit = 2 if kind == 'addspl' else 16  # SVL=128 bits: /64 or /8 bytes.
        base = 0 if kind == 'rdsvl' else initial_sp if rn == 31 else initial_base
        expected = (base + imm * unit) & 0xffff_ffff_ffff_ffff
        if rd == 31:
            capture = 'sp'
            if kind == 'rdsvl':
                expected = initial_sp  # XZR destination leaves SP unchanged.
        else:
            capture = f'x{rd}'
        result.append(dict(name=f'{kind}-r{rd}-n{rn}-i{imm}', opcode=word,
                           model='max,sve-max-vq=1', zen=0, smen=3, init_sve=True,
                           expected=f'13cA0:{expected:016x}', capture=capture,
                           initial_sp=initial_sp, initial_base=initial_base))

    for kind in ('rdsvl', 'addsvl', 'addspl'):
        for imm in (-32, -1, 0, 1, 31):
            add(kind, imm)
    for kind in ('addsvl', 'addspl'):
        for rd, rn in ((1, 1), (31, 1), (0, 31), (31, 31)):
            add(kind, -1, rd, rn)
    add('rdsvl', 1, rd=31)
    return result


def conditional_predicate_cases():
    """Keep SVE-only, SME-only and both-absent models explicit."""
    word = 0x25207810  # LLVM 23: PTRUE PN8.B
    rows = (
        ('conditional-sve-denied', 'max,sve-max-vq=1,sme=off', 0, 0, '119I0', True),
        ('conditional-sme-not-streaming', 'max,sve=off,sme=on', 3, 3, '11dI2', False),
        ('conditional-sme-denied', 'max,sve=off,sme=on', 3, 0, '11dI0', False),
        ('conditional-both-absent', 'max,sve=off,sme=off', 3, 3, '100I0', False),
    )
    return [dict(name=name, opcode=word, model=model, zen=zen, smen=smen,
                 expected=expected, init_sve=init)
            for name, model, zen, smen, expected, init in rows]


def value_guest(original, case):
    replacements = {
        '    mov x0, #0x1234\ninstruction:':
            f'    ldr x1, ={case["initial_base"]}\n'
            f'    ldr x9, ={case["initial_sp"]}\n    mov sp, x9\n'
            '    mov x0, #0x1234\ninstruction:',
        '    .inst OPCODE\nafter_access:':
            f'    .inst OPCODE\n    mov x18, {case["capture"]}\nafter_access:',
        '    strb wzr, [x1, #5]\n':
            "    mov w9, #':'\n    strb w9, [x1, #5]\n"
            '    mov x4, x18\n    mov x16, #16\nvalue_hex:\n'
            '    sub x16, x16, #1\n    and x17, x4, #15\n'
            '    ldrb w17, [x15, x17]\n    add x9, x1, #6\n'
            '    strb w17, [x9, x16]\n    lsr x4, x4, #4\n'
            '    cbnz x16, value_hex\n    strb wzr, [x1, #22]\n',
    }
    for before, after in replacements.items():
        if original.count(before) != 1:
            raise ValueError(('changed value oracle source template', before))
        original = original.replace(before, after)
    return original


def run(output, scratch, mc, linker, qemu, values=False, conditional=False):
    output.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    elfs = output / 'elfs'
    elfs.mkdir(exist_ok=True)
    source = ROOT / 'docs/development/a64-sve-access/guest.s'
    script = source.with_suffix('.ld')
    sources = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in (source, script)}
    tools = {str(tool): dict(sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),
                             version=subprocess.check_output([str(tool), '--version'],
                                                             text=True).splitlines()[0])
             for tool in (mc, linker, qemu)}
    records = []
    selected = conditional_predicate_cases() if conditional else scalar_value_cases() if values else cases()
    inputs = dict(cases=selected, sources=sources, tools=tools)
    (output / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    with tempfile.TemporaryDirectory(prefix='sve-profile-', dir=scratch) as temporary:
        for number, case in enumerate(inputs['cases']):
            stem = f'{number:03d}-{case["name"]}-{case["opcode"]:08x}'
            obj, elf = Path(temporary) / (stem + '.o'), elfs / (stem + '.elf')
            guest = source
            if values:
                guest = output / (stem + '.s')
                guest.write_text(value_guest(source.read_text(), case))
            definitions = dict(TEST_EL=1, CPACR=(case['zen'] << 16) | (3 << 20)
                               | (case['smen'] << 24), HCR=1 << 31, CPTR2=0,
                               CPTR3=(1 << 8) | (1 << 12), SECURE=0,
                               OPCODE=case['opcode'], INIT_SVE=int(case['init_sve']))
            commands = [
                [str(mc), '-triple=aarch64', '-filetype=obj',
                 *[f'--defsym={name}={value}' for name, value in definitions.items()],
                 str(guest), '-o', str(obj)],
                [str(linker), '-T', str(script), str(obj), '-o', str(elf)],
            ]
            builds = []
            for command in commands:
                process = subprocess.run(command, capture_output=True, text=True)
                builds.append(dict(command=command, code=process.returncode,
                                   stdout=process.stdout, stderr=process.stderr))
                if process.returncode:
                    raise RuntimeError(builds)
            command = [str(qemu), '-machine', 'virt,secure=on,virtualization=on',
                       '-cpu', case['model'], '-m', '128M', '-display', 'none',
                       '-monitor', 'none', '-serial', 'none', '-semihosting-config',
                       'enable=on,target=native', '-device', f'loader,file={elf},cpu-num=0',
                       '-no-reboot']
            try:
                process = subprocess.run(command, capture_output=True, text=True, timeout=30)
                code, stdout, stderr = process.returncode, process.stdout, process.stderr
            except subprocess.TimeoutExpired as error:
                code = None
                stdout = (error.stdout or b'').decode()
                stderr = (error.stderr or b'').decode()
            (output / (stem + '.stdout')).write_text(stdout)
            (output / (stem + '.stderr')).write_text(stderr)
            row = dict(case=case, command=command, code=code, stdout=stdout, stderr=stderr,
                       elf_sha256=hashlib.sha256(elf.read_bytes()).hexdigest(), builds=builds)
            records.append(row)
            (output / 'partial.json').write_text(json.dumps(records, indent=2) + '\n')
            if code != 0 or stdout or stderr != case['expected']:
                raise RuntimeError(('independent oracle counterexample retained', row))
            print(f'{number + 1}/{len(inputs["cases"])} {stem}: {stderr}', flush=True)
    report = dict(status='passed', cases=len(records), records=records, tools=tools,
                  sources=sources, boundary='Independent QEMU software execution. This is not physical SVE/SME hardware validation.')
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--llvm-mc', type=Path, required=True)
    parser.add_argument('--ld-lld', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--scalar-values', action='store_true')
    mode.add_argument('--conditional-predicates', action='store_true')
    args = parser.parse_args()
    report = run(args.output, args.scratch, args.llvm_mc, args.ld_lld, args.qemu,
                 values=args.scalar_values, conditional=args.conditional_predicates)
    print(json.dumps(dict(status=report['status'], cases=report['cases'])))


if __name__ == '__main__':
    main()
