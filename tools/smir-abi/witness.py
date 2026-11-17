#!/usr/bin/env python3
"""Pinned Clang layout witnesses for existing targets, never SMIR/native execution."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/abi'
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
TARGETS = (
    'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
    'x86_64-apple-darwin', 'arm64-apple-darwin',
    'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc',
)


def compiler():
    selected = os.environ.get('SMIR_ABI_CLANG', '/Users/int/dev/llvm-project/build/bin/clang')
    version = subprocess.run([selected, '--version'], check=True, capture_output=True,
                             text=True).stdout
    if PIN not in version:
        raise ValueError('ABI_WITNESS_COMPILER_PIN:' + version.splitlines()[0])
    return selected, version


def parse_layouts(output):
    records = {}
    for block in output.split('*** Dumping AST Record Layout'):
        name = re.search(r'Type: (?:struct|union|class) (\w+)\s', block)
        if not name:
            continue
        record = {}
        for key in ('Size', 'DataSize', 'Alignment'):
            match = re.search(r'\b' + key + r':(\d+)', block)
            if match is None:
                if key == 'DataSize':
                    record[key] = None  # Microsoft AST dump omits data size.
                    continue
                raise ValueError('ABI_WITNESS_LAYOUT_PARSE')
            record[key] = int(match[1])
        for key in ('BaseOffsets', 'VBaseOffsets', 'FieldOffsets'):
            match = re.search(key + r': \[([^]]*)\]', block)
            if match is None:
                if key == 'FieldOffsets':
                    raise ValueError('ABI_WITNESS_LAYOUT_PARSE')
                record[key] = []  # C record dumps omit C++ base metadata.
                continue
            record[key] = [int(item.strip()) for item in match[1].split(',') if item.strip()]
        records[name[1]] = record
    if not records:
        raise ValueError('ABI_WITNESS_ZERO_LAYOUTS')
    return records


def array_constant(ir, name):
    line = next((line for line in ir.splitlines() if line.startswith('@' + name + ' =')), '')
    match = re.search(r'constant \[\d+ x i64\] \[([^]]*)\]', line)
    if not match:
        raise ValueError('ABI_WITNESS_CONSTANT_PARSE:' + name)
    return [int(value) for value in re.findall(r'i64 (-?\d+)', match[1])]


def compile_witness(clang, target, source, output):
    cpp = source.suffix == '.cpp'
    argv = [clang, '-target', target, '-std=c++23' if cpp else '-std=c23',
            '-ffreestanding', '-nostdinc', '-S', '-emit-llvm',
            '-Xclang', '-fdump-record-layouts-simple',
            '-Xclang', '-fdump-record-layouts-complete', str(source), '-o', str(output)]
    # Comparison profile for the common C layouts: only this explicit target
    # gets quad long double. The other profiles retain their actual defaults.
    if target == TARGETS[0]:
        argv += ['-mlong-double-128']
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode:
        raise ValueError('ABI_WITNESS_COMPILE:' + result.stderr)
    ir = output.read_text()
    return {'argv': argv, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'ir_sha256': hashlib.sha256(ir.encode()).hexdigest(),
            'layouts': parse_layouts(result.stdout), 'diagnostics': result.stderr,
            'properties': array_constant(ir, 'member_properties' if cpp else 'abi_properties')}


def run(directory):
    clang, version = compiler()
    directory.mkdir(parents=True, exist_ok=True)
    results = {}
    for index, target in enumerate(TARGETS):
        results[target] = {}
        for language, source in [('c', FIXTURES / 'layouts.c'),
                                 ('cxx', FIXTURES / 'cxx-layouts.cpp')]:
            results[target][language] = compile_witness(
                clang, target, source, directory / f'{index}-{language}.ll')
    return {'revision': 'abi-witness-draft-v1', 'compiler': version,
            'native_execution': False, 'smir_frontend': False, 'targets': results}


def profile_snapshot(receipt):
    return {
        'revision': 'abi-compiler-profile-snapshot-v1', 'source_revision': PIN,
        'native_execution': False,
        'meaning': 'Existing-target snapshot regression; C model and hand-derived layout expectations are independent checks.',
        'targets': {target: {language: {'properties': row['properties'],
                                       'layouts': {name: item for name, item in row['layouts'].items()
                                                   if not name.startswith('__')}}
                             for language, row in rows.items()}
                    for target, rows in receipt['targets'].items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path,
                        help='Evidence directory; does not regenerate checked-in fixtures.')
    parser.add_argument('--snapshot-output', type=Path,
                        help='Explicit destination for an existing-target regression snapshot.')
    args = parser.parse_args()
    receipt = run(args.output)
    (args.output / 'witness.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if args.snapshot_output is not None:
        args.snapshot_output.write_text(json.dumps(profile_snapshot(receipt), indent=2) + '\n')
    print(f"{len(receipt['targets'])} existing targets; 12 compilations; 0 native executions")


if __name__ == '__main__':
    main()
