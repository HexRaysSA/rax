#!/usr/bin/env python3
"""Snapshot structural SMIR/LLVM inventories, never infer semantic support."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / 'docs/specifications/smir/portable'


def enum_variants(path, name):
    source = path.read_text()
    body = source.split(f'pub enum {name} {{', 1)[1].split('\n}', 1)[0]
    variants = re.findall(r'^    ([A-Z][A-Za-z0-9_]*)\s*(?:\{|\(|,)', body, re.MULTILINE)
    if not variants or len(variants) != len(set(variants)):
        raise ValueError(f'invalid inventory: {name}')
    return variants


def snapshot():
    sources = {
        'operations': ('src/smir/ir/ops.rs', 'OpKind'),
        'architectures': ('src/smir/ir/types.rs', 'SourceArch'),
        'terminators': ('src/smir/ir/mod.rs', 'Terminator'),
    }
    document = {'smir': {}, 'llvm_instructions': []}
    for group, (relative, name) in sources.items():
        path = ROOT / relative
        document['smir'][group] = {
            'source': relative,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'variants': enum_variants(path, name),
            'portable_semantic_review': 'not-performed',
        }
    instructions = (SPEC / 'references/Instruction.def').read_text()
    rows = re.findall(r'^HANDLE_([A-Z_]+)_INST\s*\(\s*(\d+),\s*(\w+)\s*,\s*(\w+)\s*\)', instructions, re.MULTILINE)
    if not rows:
        raise ValueError('empty LLVM instruction inventory')
    for category, number, name, implementation in rows:
        document['llvm_instructions'].append({
            'number': int(number), 'name': name, 'category': category,
            'llvm_class': implementation, 'lowering': 'not-implemented',
            'test': None,
        })
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    output = SPEC / 'inventory.json'
    document = snapshot()
    if args.check:
        if json.loads(output.read_text()) != document:
            raise SystemExit('SMIR/LLVM inventory drift; review and regenerate explicitly')
    else:
        output.write_text(json.dumps(document, indent=2) + '\n')
    print(f"{len(document['smir']['operations']['variants'])} OpKind variants; "
          f"{len(document['llvm_instructions'])} LLVM instructions; no semantic support inferred")


if __name__ == '__main__':
    main()
