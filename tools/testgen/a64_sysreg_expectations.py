#!/usr/bin/env python3
"""Correct two primary/QEMU-qualified historical read-only ID write cases.

The full historical corpus inputs/revision remain unknown. This focused tool
never calls RAX and preserves every byte outside the two qualified assertions.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / 'docs/development/a64-el0-id-policy/legacy-sysreg-correction.json'
MANIFEST = ROOT / 'tests/generated/manifest.toml'
NAMES = {'test_aarch64_system_register_system_combo_3_0_d5180000',
         'test_aarch64_system_register_system_field_o0_1_max_0_d5180000'}
OLD = '''!matches!(exit, Ok(CpuExit::Undefined(_)))
            && !matches!(exit, Err(ArmError::UndefinedInstruction(_))),
        "expected allocated encoding'''
NEW = '''matches!(exit, Ok(CpuExit::Undefined(_)))
            || matches!(exit, Err(ArmError::UndefinedInstruction(_))),
        "expected Undefined for read-only ID write'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_oracle(oracle):
    if not oracle['passed'] or {c['model'] for c in oracle['cases']} != {'cortex-a53', 'max'} or len(oracle['cases']) != 2:
        raise ValueError('incomplete independent CPU-profile controls')
    for case in oracle['cases']:
        values = case['values']
        if len(values) != 15 or values[0] == 0 or values[0] != values[1] or values[2:5] != [4, 10, 0x1234] or values[5:] != [1 << 25] * 10:
            raise ValueError('independent EL1 Undefined/read-only controls disagree')
    for name, expected in oracle['source_sha256'].items():
        if digest((INPUT.parent / name).read_bytes()) != expected:
            raise ValueError('changed independent oracle source')


def qualified_input(record=None):
    record = json.loads(INPUT.read_text()) if record is None else record
    if record['word'] != '0xd5180000' or record['expected'] != 'Undefined' or set(record['tests']) != NAMES or len(record['tests']) != 2:
        raise ValueError('changed read-only ID correction scope')
    word = int(record['word'], 16)
    # L=0, op0=3, op1=0, CRn=0, CRm=0, op2=0: MSR MIDR_EL1,X0.
    if word & 0xffff_ffe0 != 0xd518_0000 or word & 31:
        raise ValueError('changed primary MIDR write encoding')
    for path_key, hash_key in [('primary_source', 'primary_sha256'), ('primary_excerpt', 'primary_excerpt_sha256'), ('oracle', 'oracle_sha256'), ('test_helper', 'test_helper_sha256')]:
        if digest((ROOT / record[path_key]).read_bytes()) != record[hash_key]:
            raise ValueError('changed qualified input: ' + path_key)
    validate_oracle(json.loads((ROOT / record['oracle']).read_text()))
    return record


def corrected_source(record, source=None):
    output = ROOT / record['output']
    source = output.read_text() if source is None else source
    if digest(source.encode()) not in {record['original_sha256'], record['corrected_sha256']}:
        raise ValueError('unqualified historical source revision')
    for name in record['tests']:
        matches = list(re.finditer(r'(?ms)^fn ' + re.escape(name) + r'\(\) \{.*?^\}', source))
        if len(matches) != 1:
            raise ValueError('missing or duplicate historical case')
        match = matches[0]
        body = match.group()
        if 'let encoding: u32 = 0xD5180000;' not in body:
            raise ValueError('changed historical word')
        if body.count(OLD) == 1:
            body = body.replace(OLD, NEW, 1)
        elif body.count(NEW) != 1:
            raise ValueError('changed historical assertion')
        source = source[:match.start()] + body + source[match.end():]
    if digest(source.encode()) != record['corrected_sha256']:
        raise ValueError('correction changed bytes outside the qualified cases')
    return output, source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    record = qualified_input()
    output, source = corrected_source(record)
    entries = {'sysreg_correction': 'tools/testgen/a64_sysreg_expectations.py',
               'sysreg_correction_input': str(INPUT.relative_to(ROOT)),
               'sysreg_correction_sha256': digest(source.encode())}
    manifest = MANIFEST.read_text()
    for key, value in entries.items():
        entry = f'{key} = "{value}"'
        pattern = rf'(?m)^{key} = "[^"\n]*"$'
        if re.search(pattern, manifest):
            manifest = re.sub(pattern, entry, manifest)
        else:
            anchor = '\n[corpora.arm_aarch32_oracle_cases]'
            if manifest.count(anchor) != 1:
                raise ValueError('changed corpus manifest structure')
            manifest = manifest.replace(anchor, entry + '\n' + anchor, 1)
    if args.write:
        output.write_text(source)
        MANIFEST.write_text(manifest)
    elif output.read_text() != source or MANIFEST.read_text() != manifest:
        raise ValueError('stale read-only ID expectations; use --write')
    print(json.dumps(dict(tests=2, oracle_profiles=2, oracle_writes=20, output=record['output'], sha256=digest(source.encode()))))


if __name__ == '__main__':
    main()
