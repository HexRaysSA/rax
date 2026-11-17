#!/usr/bin/env python3
"""Pinned-Clang source-cell oracle; no actual source/runtime authority.

Arrays stay symbolic. Evaluation O(graph rows + selected path edges), relation
O(axis count); compiler frontend and guarded build costs are separate.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/llvm/source-cells'
SCHEMA = ROOT / 'docs/specifications/smir/portable/llvm/source-cell-witness.schema.json'
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
COMPILER_SHA = '192ac975b062d522570b5f7bd06a235a1918f7c0a0d66f70df2eecdd628d24b7'
U64 = (1 << 64) - 1


class CellError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise CellError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def bounded_int(value, maximum=U64):
    need(type(value) is int and 0 <= value <= maximum, 'CELL_INTEGER')
    return value


def exact(value, names):
    need(type(value) is dict and set(value) == set(names.split()), 'CELL_SHAPE')


def validate_schema(rule, value, definitions=None, depth=0):
    """Closed JSON Schema subset used by this exact local executable grammar."""
    need(depth <= 128, 'CELL_SCHEMA_RESOURCE')
    definitions = rule.get('$defs', {}) if definitions is None else definitions
    if '$ref' in rule:
        return validate_schema(definitions[rule['$ref'].split('/')[-1]], value, definitions, depth + 1)
    if 'oneOf' in rule:
        matches = 0
        for branch in rule['oneOf']:
            try:
                validate_schema(branch, value, definitions, depth + 1)
                matches += 1
            except CellError:
                pass
        need(matches == 1, 'CELL_SCHEMA')
        return
    if 'const' in rule:
        need(type(value) is type(rule['const']) and value == rule['const'], 'CELL_SCHEMA')
    if 'enum' in rule:
        need(value in rule['enum'] and type(value) is str, 'CELL_SCHEMA')
    kind = rule.get('type')
    if kind == 'object':
        need(type(value) is dict and set(value) == set(rule['required']), 'CELL_SCHEMA')
        for name, child in rule['properties'].items():
            validate_schema(child, value[name], definitions, depth + 1)
    elif kind == 'array':
        need(type(value) is list and rule.get('minItems', 0) <= len(value) <= rule['maxItems'], 'CELL_SCHEMA')
        for child in value:
            validate_schema(rule['items'], child, definitions, depth + 1)
    elif kind == 'integer':
        need(type(value) is int and rule.get('minimum', 0) <= value <= rule['maximum'], 'CELL_SCHEMA')
    elif kind == 'boolean':
        need(type(value) is bool, 'CELL_SCHEMA')
    elif kind == 'null':
        need(value is None, 'CELL_SCHEMA')
    elif kind == 'string':
        need(type(value) is str and len(value) <= rule.get('maxLength', 4096), 'CELL_SCHEMA')
        if 'pattern' in rule:
            need(re.fullmatch(rule['pattern'], value) is not None, 'CELL_SCHEMA')


class Evaluator:
    def __init__(self, raw, context_id):
        need(type(context_id) is str and re.fullmatch('[0-9a-f]{64}', context_id), 'CELL_CONTEXT')
        self.context_id = context_id
        schema = json.loads(SCHEMA.read_text())
        validate_schema(schema['$defs']['raw'], raw, schema['$defs'])
        need(raw['format'] == 'clang-source-cell-raw' and raw['revision'] == 1,
             'CELL_ORACLE_REVISION')
        need(raw['char_bits'] == 8 and raw['pointer_bits'] == 64 and raw['little_endian'] is True,
             'CELL_TARGET')
        need(len(raw['records']) <= 256, 'CELL_RESOURCE')
        self.records, self.names = {}, {}
        for row in raw['records']:
            need(row['id'] == str(row['source_offset']) + ':' + row['name'], 'CELL_DECLARATION_ID')
            need(row['id'] not in self.records and row['name'] not in self.names, 'CELL_DUPLICATE')
            self.records[row['id']] = row
            self.names[row['name']] = row['id']
        for row in self.records.values():
            for name in ('fields', 'bases'):
                need([v['index'] for v in row[name]] == list(range(len(row[name]))), 'CELL_DECLARATION_ORDER')
            for base in row['bases'] + row['virtual_bases']:
                need(base['record'] in self.records, 'CELL_REFERENCE')
            pending = [f['type'] for f in row['fields']]
            visited = 0
            while pending:
                typ = pending.pop(); visited += 1
                need(visited <= 32768, 'CELL_RESOURCE')
                if typ['kind'] == 'record':
                    need(typ['record'] in self.records, 'CELL_REFERENCE')
                elif typ['kind'] == 'array':
                    pending.append(typ['element'])

    def select(self, query):
        exact(query, 'label root view steps')
        need(type(query['label']) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,127}', query['label']), 'CELL_LABEL')
        need(type(query['root']) is str and query['root'] in self.names and
             type(query['view']) is str and query['view'] in ('complete', 'nonvirtual'), 'CELL_ROOT')
        need(type(query['steps']) is list and len(query['steps']) <= 128, 'CELL_RESOURCE')
        root = self.names[query['root']]
        node = self.records[root]
        typ = dict(kind='record', record=root, size_bits=node['size_bits'], align_bits=node['align_bits'], qualifiers=[])
        route, axes, coefficients = [], [], []
        constant = 0
        owner, owner_route, owner_constant, owner_coefficients = (root if query['view'] == 'complete' else None), [], 0, []
        role, leaf_view, gap = 'root', query['view'], None
        for position, step in enumerate(query['steps']):
            need(type(step) is dict and 'kind' in step, 'CELL_SHAPE')
            kind = step['kind']
            if kind in ('member', 'base'):
                need(typ['kind'] == 'record', 'CELL_STEP_TYPE')
                current = self.records[typ['record']]
                exact(step, 'kind declaration_index' + (' virtual' if kind == 'base' else ''))
                index = bounded_int(step['declaration_index'], (1 << 32) - 2)
                table = current['fields' if kind == 'member' else 'bases']
                need(index < len(table), 'CELL_DECLARATION_INDEX')
                edge = table[index]
                if kind == 'member':
                    need(edge['bit_width'] is None, 'CELL_BITFIELD_SCOPE')
                    constant += edge['offset_bits']
                    route.append(dict(kind='member', declaring_class=current['id'], declaration_index=index))
                    typ = copy.deepcopy(edge['type'])
                    role, leaf_view = 'member', 'complete' if typ['kind'] == 'record' else None
                else:
                    need(type(step['virtual']) is bool and step['virtual'] == edge['virtual'], 'CELL_VIRTUAL_FLAG')
                    target = self.records[edge['record']]
                    if edge['virtual']:
                        if owner is None:
                            gap = gap or dict(code='CELL_NV_MOST_DERIVED_UNAVAILABLE', step_index=position)
                            route.append(dict(kind='virtual_base', record=edge['record']))
                        else:
                            placements = [v for v in self.records[owner]['virtual_bases'] if v['record'] == edge['record']]
                            need(len(placements) == 1, 'CELL_VIRTUAL_TARGET')
                            constant = owner_constant + placements[0]['offset_bits']
                            coefficients = list(owner_coefficients)
                            route = copy.deepcopy(owner_route) + [dict(kind='virtual_base', record=edge['record'])]
                    else:
                        constant += edge['offset_bits']
                        route.append(dict(kind='nonvirtual_base', declaring_class=current['id'], declaration_index=index))
                    typ = dict(kind='record', record=edge['record'], size_bits=target['size_bits'],
                               align_bits=target['align_bits'], qualifiers=[])
                    role, leaf_view = ('virtual_base' if edge['virtual'] else 'nonvirtual_base'), 'nonvirtual'
            elif kind == 'element':
                exact(step, 'kind selection')
                exact(step['selection'], 'first count')
                need(typ['kind'] == 'array', 'CELL_STEP_TYPE')
                first, count = bounded_int(step['selection']['first']), bounded_int(step['selection']['count'])
                need(count > 0 and first + count <= typ['extent'], 'CELL_ARRAY_BOUNDS')
                need(len(axes) < 16, 'CELL_RESOURCE')
                axes.append(dict(position=len(axes), origin=copy.deepcopy(route), extent=typ['extent'], first=first, count=count))
                route.append(dict(kind='element', axis=len(axes) - 1))
                typ = copy.deepcopy(typ['element'])
                coefficients.append(typ['size_bits'])
                role, leaf_view = 'element', 'complete' if typ['kind'] == 'record' else None
            else:
                raise CellError('CELL_STEP_KIND')
            if kind in ('member', 'element') and typ['kind'] == 'record':
                owner, owner_route = typ['record'], copy.deepcopy(route)
                owner_constant, owner_coefficients = constant, list(coefficients)
            need(constant <= U64 and len(coefficients) == len(axes), 'CELL_GEOMETRY_OVERFLOW')
        if gap is not None:
            return dict(status='unavailable', **gap)
        width = (self.records[typ['record']]['nonvirtual_size_bits'] if typ['kind'] == 'record' and
                 leaf_view == 'nonvirtual' else typ['size_bits'])
        low = constant + sum(c * a['first'] for c, a in zip(coefficients, axes))
        high = constant + sum(c * (a['first'] + a['count'] - 1) for c, a in zip(coefficients, axes))
        need(high <= U64 and high + width <= U64, 'CELL_GEOMETRY_OVERFLOW')
        return dict(status='resolved', canonical_pattern=dict(context=self.context_id, root=root, route=route),
            most_derived_pattern=None if owner is None else dict(context=self.context_id, record=owner, route=owner_route),
            root_view=query['view'], leaf_view=leaf_view, leaf_type=typ, role=role, axes=axes,
            offset_constant_bits=constant, offset_coefficients_bits=coefficients, width_bits=width,
            offset_min_bits=low, offset_max_bits=high)


def compare(left, right):
    need(left['status'] == right['status'] == 'resolved', 'CELL_RELATION_UNAVAILABLE')
    same_view = left['root_view'] == right['root_view'] and left['leaf_view'] == right['leaf_view']
    if left['canonical_pattern'] != right['canonical_pattern'] or len(left['axes']) != len(right['axes']):
        relation = 'disjoint'
    else:
        pairs = list(zip(left['axes'], right['axes']))
        if any(a['origin'] != b['origin'] or a['extent'] != b['extent'] or
               max(a['first'], b['first']) >= min(a['first'] + a['count'], b['first'] + b['count']) for a, b in pairs):
            relation = 'disjoint'
        else:
            relation = 'equal' if all(a == b for a, b in pairs) else 'overlap'
    return dict(relation=relation, same_coverage_view=same_view)


def compile_witness(oracle, source, target, queries):
    oracle, source = Path(oracle).resolve(), Path(source).resolve()
    need(source.stat().st_size <= 1024 * 1024 and type(queries) is list and len(queries) <= 4096, 'CELL_RESOURCE')
    before = {str(q): digest(q) for q in (oracle, source, Path(__file__), SCHEMA)}
    need((oracle.parent / 'build-receipt.json').is_file(), 'CELL_BUILD_IDENTITY')
    receipt = json.loads((oracle.parent / 'build-receipt.json').read_text())
    need(receipt['exit'] == 0 and receipt['binary_sha256'] == before[str(oracle)]
         and receipt['compiler_sha256'] == COMPILER_SHA, 'CELL_BUILD_IDENTITY')
    run = subprocess.run([str(oracle), str(source), target], capture_output=True, text=True, timeout=60)
    need(run.returncode == 0, 'CELL_ORACLE_SCOPE' if 'SOURCE-CELL-ORACLE-SCOPE' in run.stderr else 'CELL_COMPILER_REJECTED')
    raw = json.loads(run.stdout)
    need(PIN in raw['clang_version'], 'CELL_LLVM_PIN')
    context = dict(llvm_revision=PIN, compiler_sha256=COMPILER_SHA, oracle_sha256=before[str(oracle)],
        source_sha256=before[str(source)], target=target, language='cpp23', raw_sha256=hashlib.sha256(canonical(raw)).hexdigest())
    context['id'] = hashlib.sha256(canonical(context)).hexdigest()
    model = Evaluator(raw, context['id'])
    results = []
    labels = set()
    for query in queries:
        schema = json.loads(SCHEMA.read_text())
        validate_schema(schema['$defs']['query'], query, schema['$defs'])
        need(query.get('label') not in labels, 'CELL_DUPLICATE_LABEL')
        labels.add(query.get('label'))
        results.append(dict(selector=copy.deepcopy(query), result=model.select(query)))
    witness = dict(format='clang-source-cell-witness', revision=1, binding='unbound',
        runtime_authority=False, source_fact_authority=False, context=context, raw=raw, queries=results)
    validate_schema(json.loads(SCHEMA.read_text()), witness)
    need(all(digest(Path(q)) == h for q, h in before.items()), 'CELL_INPUT_DRIFT')
    return witness


def build_oracle(llvm, output):
    llvm, output = Path(llvm).resolve(), Path(output).resolve()
    need(not output.is_relative_to(ROOT) and not output.is_relative_to(llvm), 'CELL_BUILD_OUTPUT')
    output.mkdir(parents=True, exist_ok=False)
    compiler = llvm / 'build/bin/clang++'
    need(digest(compiler) == COMPILER_SHA, 'CELL_COMPILER_PIN')
    need(subprocess.check_output(['git', '-C', str(llvm), 'rev-parse', 'HEAD'], text=True).strip() == PIN, 'CELL_LLVM_PIN')
    argv = [str(compiler), '-std=c++17', '-fno-rtti', '-fno-exceptions']
    if os.uname().sysname == 'Darwin':
        argv += ['-isysroot', subprocess.check_output(['/usr/bin/xcrun', '--show-sdk-path'], text=True).strip()]
    argv += ['-I' + str(llvm / n) for n in ('clang/include', 'build/tools/clang/include', 'llvm/include', 'build/include')]
    cpp = Path(__file__).with_suffix('.cpp')
    deps = subprocess.check_output(argv + ['-MM', '-MT', 'oracle', str(cpp)], text=True)
    headers = [Path(n).resolve() for n in shlex.split(deps.replace('\\\n', ''))[1:]]
    libraries = sorted((llvm / 'build/lib').glob('libclang*.a'))
    flags = shlex.split(subprocess.check_output([str(llvm / 'build/bin/llvm-config'), '--ldflags', '--libs', '--system-libs'], text=True))
    llvm_files = [Path(n) for n in shlex.split(subprocess.check_output([str(llvm / 'build/bin/llvm-config'), '--libfiles'], text=True))]
    binary = output / 'source-cell-oracle'
    argv += [str(cpp)] + [str(p) for p in libraries] + flags
    if os.uname().sysname == 'Darwin':
        argv += ['-L/opt/homebrew/opt/zstd/lib', '-Wl,-rpath,' + str(llvm / 'build/lib')]
    argv += ['-o', str(binary)]
    files = sorted(set(headers + libraries + llvm_files + [cpp, compiler.resolve(), Path(__file__), llvm / 'build/bin/llvm-config']))
    before = {str(p): digest(p) for p in files}
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    (output / 'build.stdout').write_text(result.stdout)
    (output / 'build.stderr').write_text(result.stderr)
    need(all(digest(Path(p)) == h for p, h in before.items()), 'CELL_BUILD_DRIFT')
    receipt = dict(command=argv, exit=result.returncode, inputs=before,
        compiler_sha256=digest(compiler),
        scope='Native AST/layout oracle build only; system SDK/toolchain not fully attested',
        compiler_version=subprocess.check_output([str(compiler), '--version'], text=True))
    if result.returncode == 0:
        receipt['binary_sha256'] = digest(binary)
    (output / 'build-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    need(result.returncode == 0, 'CELL_BUILD_FAILED')
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build'); build.add_argument('--llvm', type=Path, required=True); build.add_argument('--output', type=Path, required=True)
    run = sub.add_parser('run'); run.add_argument('--oracle', type=Path, required=True); run.add_argument('--source', type=Path, required=True)
    run.add_argument('--target', required=True); run.add_argument('--queries', type=Path, required=True); run.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'build':
        print(build_oracle(args.llvm, args.output)); return
    value = compile_witness(args.oracle, args.source, args.target, json.loads(args.queries.read_text()))
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(status='compiler-witness', interpreter_optimization=sys.flags.optimize,
                         output_sha256=digest(args.output))))


if __name__ == '__main__':
    main()
