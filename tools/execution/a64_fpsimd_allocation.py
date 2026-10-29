#!/usr/bin/env python3
"""Derive structural A64 FP/SIMD allocation before execution-time FP access.

Feature predicates are true during structural derivation. Existing profile
admission remains responsible for the selected extension set. Newer BF16/I8MM
patterns use the separately qualified optional-feature table and restrictions.
"""
import argparse
import collections
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from asl_decode_allocation import enumerate_encoding

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'docs/architecture/arm/asl/arm_instrs.asl'
SOURCE_SHA256 = '3c91ece6d0509f7ce9e8b2d8fa623787d7c7acb4cb24040a75cec5aa2789e611'
AST_SHA256 = 'ce6db4f519aee638657105850744fd62f51e833d5da02026eb08a26b7184fdb1'
OPTIONAL = ROOT / 'docs/development/a64-optional-fp-profile/encodings.json'
OPTIONAL_SHA256 = 'c65ab483ef449fc55f1e5348aa25ab30821092e98b5e44490c0627c030081ad8'
TABLE = ROOT / 'src/isa/arm/aarch64/cpu/fp_profile/allocation_encodings.rs'
DOCUMENTS = ROOT / 'docs/development/a64-fpsimd-allocation'


def primary_records():
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError('unqualified primary ASL revision')
    source = SOURCE.read_text()
    boundaries = list(re.finditer(r'(?m)^    __encoding (\S+)\n|^__instruction ', source))
    records = []
    for index, match in enumerate(boundaries):
        if not match.group(1):
            continue
        end = boundaries[index + 1].start() if index + 1 < len(boundaries) else len(source)
        block = source[match.start():end]
        opcode = re.search(r"__opcode '([^']+)'", block)
        if '__instruction_set A64' not in block or not opcode:
            continue
        pattern = opcode.group(1).replace(' ', '')
        if pattern[3:7] not in ('0111', '1111'):
            continue
        if re.search(r'__guard (.*)', block).group(1) != 'TRUE':
            raise ValueError(('unqualified guard', match.group(1)))
        decode = block.split('__decode', 1)[1].split('__execute', 1)[0]
        if '__postdecode' in decode:
            raise ValueError(('unqualified postdecode', match.group(1)))
        field_records = re.findall(r'__field (\S+) (\d+) \+: (\d+)', block)
        fields = {name: (int(low), int(width)) for name, low, width in field_records}
        if len(fields) != len(field_records):
            raise ValueError(('duplicate primary field', match.group(1)))
        records.append(dict(name=match.group(1), pattern=pattern, fields=fields, decode=decode))
    if len(records) != 562:
        raise ValueError(('unqualified primary description count', len(records)))
    return records


def parse(records, parser, saved_ast):
    if saved_ast:
        raw = saved_ast.read_bytes()
        if hashlib.sha256(raw).hexdigest() != AST_SHA256:
            raise ValueError('unqualified saved intermediate AST')
    else:
        chunks = []
        for index, row in enumerate(records):
            fields = '\n'.join(f'        __field {name} {low} +: {width}'
                               for name, (low, width) in row['fields'].items())
            chunks.append(f"__instruction admission_{index}\n    __encoding {row['name']}\n"
                          f"        __instruction_set A64\n{fields}\n"
                          f"        __opcode '{row['pattern']}'\n        __guard TRUE\n"
                          f"        __decode{row['decode']}\n    __execute\n\n")
        with tempfile.TemporaryDirectory(prefix='a64-allocation-') as directory:
            source = Path(directory) / 'decode.asl'
            source.write_text(''.join(chunks))
            raw = subprocess.check_output([str(parser), 'instructions', str(source), '--format', 'json'])
    parsed = json.loads(raw)
    if len(parsed) != len(records):
        raise ValueError('lost primary descriptions')
    encodings = []
    for primary, instruction in zip(records, parsed):
        if len(instruction['encodings']) != 1 or instruction['post_decode'] or instruction['execute']:
            raise ValueError('unexpected derived instruction structure')
        encoding = instruction['encodings'][0]
        fields = {field['name']: (field['begin'], field['width']) for field in encoding['fields']}
        if encoding['name'] != primary['name'] or fields != primary['fields']:
            raise ValueError('changed primary field identity')
        pattern = ''.join({'Zero': '0', 'One': '1', 'Either': 'x'}[x] for x in encoding['opcode'])
        if pattern != primary['pattern']:
            raise ValueError('changed primary opcode')
        encodings.append(encoding)
    return encodings


def compress(mask, values, *, bits=32):
    current = {(mask, value) for value in values}
    primes = set()
    while current:
        merged, used = set(), set()
        for mask, value in current:
            for bit in range(bits):
                flag = 1 << bit
                if mask & flag and (mask, value ^ flag) in current:
                    used.add((mask, value))
                    merged.add((mask ^ flag, value & ~flag))
        primes |= current - used
        current = merged
    return primes


def outputs(parsed):
    terms = collections.defaultdict(set)
    proof = []
    for encoding in parsed:
        row = enumerate_encoding(encoding)
        full_mask = row['mask'] | sum(1 << bit for bit in row['positions'])
        cubes = compress(full_mask, row['accepted'])
        accepted = set(row['accepted'])
        for value in range(row['assignments']):
            word = row['value'] | sum(((value >> j) & 1) << bit
                                      for j, bit in enumerate(row['positions']))
            if any(word & mask == expected for mask, expected in cubes) != (word in accepted):
                raise ValueError('cube compression changed structural admission')
        for cube in cubes:
            terms[cube].add(row['name'])
        proof.append({key: value for key, value in row.items() if key != 'accepted'} |
                     {'accepted_assignments': len(accepted),
                      'cubes': [dict(mask=m, value=v) for m, v in sorted(cubes)]})
    if hashlib.sha256(OPTIONAL.read_bytes()).hexdigest() != OPTIONAL_SHA256:
        raise ValueError('unqualified newer optional encoding corpus')
    optional = json.loads(OPTIONAL.read_text())
    for row in optional['records']:
        if row['feature'] not in ('BF16', 'I8MM'):
            continue
        terms[(row['mask'], row['value'])].add(row['name'])
    records = [dict(mask=mask, value=value, names=sorted(names))
               for (mask, value), names in sorted(terms.items())]
    buckets = [[] for _ in range(4096)]
    for row in records:
        for high in range(256):
            if high & (row['mask'] >> 24) != row['value'] >> 24:
                continue
            for opcode in range(16):
                if opcode & ((row['mask'] >> 12) & 15) == (row['value'] >> 12) & 15:
                    buckets[(high << 4) | opcode].append((row['mask'], row['value']))
    offsets, entries = [0], []
    for bucket in buckets:
        entries.extend(bucket)
        offsets.append(len(entries))
    if len(entries) > 65535:
        raise ValueError('bucket offsets no longer fit u16')
    lines = ['// Generated by tools/execution/a64_fpsimd_allocation.py; do not edit.',
             f'// Primary ASL SHA-256: {SOURCE_SHA256}',
             '// Profile selection and the qualified newer-field restrictions remain separate.',
             'const ALLOCATION_OFFSETS: &[u16; 4097] = &[']
    for start in range(0, len(offsets), 16):
        lines.append('    ' + ', '.join(map(str, offsets[start:start + 16])) + ',')
    lines += ['];', 'const ALLOCATION_ENCODINGS: &[(u32, u32)] = &[']
    for mask, value in entries:
        lines.append(f'    (0x{mask >> 16:04x}_{mask & 65535:04x}, '
                     f'0x{value >> 16:04x}_{value & 65535:04x}),')
    lines += ['];', '']
    metadata = dict(primary_source=str(SOURCE.relative_to(ROOT)), primary_sha256=SOURCE_SHA256,
                    scope='Generated legacy/BF16/I8MM base allocation. CPU feature/version policy and the explicit indexed FP8 implementation supplement remain required.',
                    newer_optional_corpus=str(OPTIONAL.relative_to(ROOT)),
                    newer_optional_sha256=hashlib.sha256(OPTIONAL.read_bytes()).hexdigest(),
                    descriptions=len(parsed), assignments=sum(x['assignments'] for x in proof),
                    distinct_cubes=len(records), bucket_entries=len(entries),
                    maximum_bucket_entries=max(map(len, buckets)), records=records)
    return '\n'.join(lines), json.dumps(metadata, indent=2) + '\n', json.dumps(proof, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--parser', type=Path, help='ASL parser executable built with serde')
    source.add_argument('--ast', type=Path, help='pinned qualified intermediate for offline development')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    result = outputs(parse(primary_records(), args.parser, args.ast))
    for path, expected in zip((TABLE, DOCUMENTS / 'encodings.json', DOCUMENTS / 'structural-proof.json'), result):
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected)
        elif path.read_text() != expected:
            raise ValueError(f'stale generated output: {path}')
    report = json.loads(result[1])
    print(json.dumps({key: report[key] for key in ('descriptions', 'assignments', 'distinct_cubes',
                                                  'bucket_entries', 'maximum_bucket_entries')}))


if __name__ == '__main__':
    main()
