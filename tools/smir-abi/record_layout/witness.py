"""Pinned AST/layout witness over a CLOSED source corpus, never a wire producer.

Type-spelling lookup below is deliberately finite: unknown source types fail.
Production source binding uses checked.py actual qrefs, not these spellings.
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess

from witness import compiler
from .model import ArrayType, Model, RecordType, ScalarType

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'docs/specifications/smir/portable/conformance/abi/record-layout/pinned-records.cpp'


def integer(node):
    if 'value' in node:
        return int(node['value'])
    values = [integer(child) for child in node.get('inner', [])]
    return next((value for value in values if value is not None), None)


def project(ast):
    nodes = {}
    def collect(node):
        if node.get('kind') == 'CXXRecordDecl' and node.get('completeDefinition') and node.get('name'):
            nodes[node['name']] = node
        for child in node.get('inner', []):
            collect(child)
    collect(ast)
    def dynamic(name):
        node = nodes[name]
        return bool(node.get('definitionData', {}).get('isPolymorphic')) or any(
            base.get('isVirtual') or dynamic(base['type']['qualType']) for base in node.get('bases', []))
    records = {}
    scalars = {'char': ScalarType(1, 1, 8, True), 'int': ScalarType(4, 4, 32, True),
               'unsigned char': ScalarType(1, 1, 8, True), 'unsigned int': ScalarType(4, 4, 32, True)}
    types = {**scalars, **{name: RecordType(name) for name in nodes},
             'const Empty': RecordType('Empty'), 'Empty[3]': ArrayType(RecordType('Empty'), 3)}
    def alignment(node):
        return next((integer(c) for c in node.get('inner', []) if c.get('kind') == 'AlignedAttr'), None)
    for name, node in nodes.items():
        facts = node.get('definitionData', {})
        fields = []
        access = 'private' if node['tagUsed'] == 'class' else 'public'
        for child in node.get('inner', []):
            if child.get('kind') == 'AccessSpecDecl':
                access = child['access']
            if child.get('kind') != 'FieldDecl':
                continue
            spelling = child['type']['qualType']
            if spelling not in types:
                raise ValueError('WITNESS_UNKNOWN_TYPE:' + spelling)
            width = next((integer(c) for c in child.get('inner', [])
                          if c.get('kind') == 'ConstantExpr'), None) if child.get('isBitfield') else None
            fields.append(dict(name=child.get('name'), type=types[spelling], bit_width=width,
                               explicit_align=alignment(child), anonymous=False, access=access,
                               no_unique_address=any(c.get('kind') == 'NoUniqueAddressAttr'
                                                     for c in child.get('inner', []))))
        records[name] = dict(kind=node['tagUsed'], language='cpp23', explicit_align=alignment(node),
                             pod03=bool(facts.get('isPOD')), trivial=bool(facts.get('isTrivial')),
                             standard_layout=bool(facts.get('isStandardLayout')),
                             polymorphic=bool(facts.get('isPolymorphic')), dynamic=dynamic(name),
                             empty=bool(facts.get('isEmpty')), fields=fields,
                             bases=[dict(type=types[b['type']['qualType']], virtual=bool(b.get('isVirtual')),
                                         access=b['access']) for b in node.get('bases', [])])
    return records


def parse_layouts(simple, full):
    result = {}
    for block in simple.split('*** Dumping AST Record Layout'):
        match = re.search(r'Type: (?:struct|class|union) (\w+)\n', block)
        if not match:
            continue
        fields = re.search(r'FieldOffsets: \[([^\]]*)\]', block)
        result[match[1]] = dict(fields=[int(x) for x in fields[1].split(',') if x.strip()])
    for block in full.split('*** Dumping AST Record Layout'):
        name = re.search(r'^\s*0 \| (?:struct|class|union) (\w+)(?: \(empty\))?\n', block)
        values = re.search(r'\[sizeof=(\d+), dsize=(\d+), align=(\d+),\s*\|\s*nvsize=(\d+), nvalign=(\d+)\]', block)
        if name and values and name[1] in result:
            result[name[1]].update(zip(('size', 'data_size', 'align', 'nvsize', 'nvalign'), map(int, values.groups())))
    return result


def run(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    clang, version = compiler()
    common = [clang, '-target', 'x86_64-unknown-linux-gnu', '-std=c++23', '-ffreestanding', '-nostdinc']
    commands = [common + ['-fsyntax-only', '-Xclang', '-ast-dump=json', str(SOURCE)],
                common + ['-fsyntax-only', '-Xclang', '-fdump-record-layouts-complete', str(SOURCE)],
                common + ['-fsyntax-only', '-Xclang', '-fdump-record-layouts-complete',
                          '-Xclang', '-fdump-record-layouts-simple', str(SOURCE)]]
    results = []
    for index, command in enumerate(commands):
        item = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (output / f'{index}.stdout').write_text(item.stdout)
        (output / f'{index}.stderr').write_text(item.stderr)
        results.append(item)
        if item.returncode:
            raise ValueError('WITNESS_COMPILER_FAILURE:' + item.stderr)
    records = project(json.loads(results[0].stdout))
    oracle = parse_layouts(results[2].stdout, results[1].stdout)
    model = Model(records)
    rows = []
    for name in records:
        actual = model.layout(name)
        expected = oracle[name]
        calculated = {k: getattr(actual, k) for k in ('size', 'align', 'data_size', 'nvsize', 'nvalign', 'fields')}
        rows.append(dict(record=name, match=calculated == expected, calculated=calculated, compiler=expected))
    receipt = dict(commands=commands, exits=[r.returncode for r in results], compiler=version,
                   source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(), records=rows,
                   scope='Closed existing-target AST/source geometry witness, not a production metadata producer, native execution, SMIR target or complete C++ proof.')
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt
