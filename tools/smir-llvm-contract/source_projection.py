#!/usr/bin/env python3
"""Pinned AST to inert original-source/portable-layout reference projection."""
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
import hashlib
import importlib
import importlib.util
import json
import os
import re
import selectors
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path(__file__).resolve().parent
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
OPTIONS = ['-xc++', '-std=c++23', '-target', 'x86_64-unknown-linux-gnu',
           '-nostdinc', '-pedantic-errors', '-nostdinc++']
SCHEMA = ROOT / 'docs/specifications/smir/portable/llvm/source-projection.schema.json'
SCHEMA_SHA256 = 'a79832a0e33e6bd2d1146503b8177197bdbbce138c4c7b96d38360f4f431be7f'
MAX_SOURCE = 1 << 20
MAX_JSON = 64 << 20


class ProjectionError(ValueError):
    def __init__(self, code, detail='', kind='semantic'):
        self.code, self.detail, self.kind = code, detail, kind
        super().__init__(code + (': ' + detail if detail else ''))


def require(value, code, detail=''):
    if not value:
        raise ProjectionError('E-SOURCE-PROJECTION-' + code, detail,
                              'resource' if code == 'RESOURCE' else
                              'unavailable' if code.endswith('-SCOPE') else 'semantic')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def read_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'INPUT', 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def freeze(value):
    if type(value) is dict:
        return MappingProxyType({k: freeze(v) for k, v in value.items()})
    if type(value) is list:
        return tuple(freeze(v) for v in value)
    return value


def thaw(value):
    if isinstance(value, MappingProxyType):
        return {k: thaw(v) for k, v in value.items()}
    if type(value) is tuple:
        return [thaw(v) for v in value]
    return value


@dataclass(frozen=True)
class Projection:
    request: object
    source_sha256: str
    compiler_sha256: str
    oracle_sha256: str
    record_oracle_sha256: str
    options_sha256: str
    declarations: tuple
    execution_types: tuple
    abi: object
    native_comparisons: tuple
    obligations: tuple
    module_content_digest: str
    original_roots: tuple
    format: str = field(default='clang-original-source-projection', init=False)
    revision: int = field(default=1, init=False)
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)

    def report(self):
        return {name: thaw(getattr(self, name)) for name in self.__dataclass_fields__}


def load_file_module(name, path, *, package=False):
    path = path.resolve()
    existing = sys.modules.get(name)
    if existing is not None:
        require(Path(existing.__file__).resolve() == path, 'INPUT', 'module identity ' + name)
        return existing
    spec = importlib.util.spec_from_file_location(name, path,
        submodule_search_locations=[str(path.parent)] if package else None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def apis():
    paths = [ROOT / 'tools/smir-format/execution', ROOT / 'tools/smir-abi']
    for p in reversed(paths):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    context = importlib.import_module('candidate.context')
    require(Path(context.__file__).resolve() == (paths[0] / 'candidate/context.py').resolve(),
            'INPUT', 'original RootContext module')
    nominal = importlib.import_module('nominal')
    require(Path(nominal.__file__).resolve() == (paths[1] / 'nominal.py').resolve(),
            'INPUT', 'original nominal module')
    package = 'rax_abi_record_layout'
    load_file_module(package, paths[1] / 'record_layout/__init__.py', package=True)
    checked = importlib.import_module(package + '.checked')
    model = importlib.import_module(package + '.model')
    source = importlib.import_module('candidate.source_data_projection').source_api()
    codec = load_file_module('_rax_llvm_projection_codec', ROOT / 'tools/smir-format/codec.py')
    site = importlib.import_module('site_config')
    return context, nominal, checked, model, source, codec, site


def bounded_read(path, maximum, budget):
    size = path.stat().st_size
    require(0 <= size <= maximum, 'RESOURCE', str(path))
    budget.charge(work=2 * size + 1, copied_bytes=2 * size + 1)
    with path.open('rb') as stream:
        value = stream.read(size + 1)
    require(len(value) == size, 'INPUT', 'file changed during read')
    return value


def file_sha(path, budget):
    size = path.stat().st_size
    require(0 <= size <= 512 << 20, 'RESOURCE', 'artifact size')
    budget.charge(work=2 * size, copied_bytes=2 * size)
    digest = hashlib.sha256()
    seen = 0
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(65536), b''):
            seen += len(part)
            require(seen <= size, 'INPUT', 'binary changed while hashing')
            digest.update(part)
    require(seen == size, 'INPUT', 'binary changed while hashing')
    return digest.hexdigest()


def capture(value, budget, depth=0, active=None, count=None):
    active = set() if active is None else active
    count = [0, 0] if count is None else count
    count[0] += 1
    count[1] += 64
    budget.charge(work=2, edges=1, copied_bytes=64)
    require(depth <= min(128, budget.max_depth) and count[0] <= 200000, 'RESOURCE', 'capture bound')
    if type(value) is str:
        budget.charge(work=4 * len(value), copied_bytes=16 * len(value))
        try:
            encoded = value.encode('utf8')
        except UnicodeError as error:
            raise ProjectionError('E-SOURCE-PROJECTION-INPUT', 'invalid UTF8') from error
        count[1] += 12 * len(encoded)
        require(count[1] <= MAX_JSON, 'RESOURCE', 'capture size')
        require(len(encoded) <= 4096 and '\0' not in value, 'INPUT', 'text bound')
        budget.charge(work=len(encoded), copied_bytes=4 * len(encoded))
        return value
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        require(value.bit_length() <= 64, 'INPUT', 'integer bound')
        return value
    require(type(value) in (dict, list) and id(value) not in active, 'INPUT', 'shape/cycle')
    budget.charge(work=len(value), copied_bytes=64 * len(value))
    active.add(id(value))
    try:
        if type(value) is list:
            return [capture(x, budget, depth + 1, active, count) for x in value]
        require(all(type(k) is str for k in value), 'INPUT', 'object keys')
        return {capture(k, budget, depth + 1, active, count):
                capture(v, budget, depth + 1, active, count) for k, v in value.items()}
    finally:
        active.remove(id(value))


def shape(rule, value, definitions, budget, depth=0):
    budget.work(1)
    require(depth <= min(128, budget.max_depth), 'RESOURCE', 'schema depth')
    if '$ref' in rule:
        return shape(definitions[rule['$ref'].rsplit('/', 1)[1]], value, definitions, budget, depth + 1)
    for key in ('anyOf', 'oneOf'):
        if key in rule:
            matched = 0
            for branch in rule[key]:
                try:
                    shape(branch, value, definitions, budget, depth + 1)
                    matched += 1
                except ProjectionError as error:
                    if error.code != 'E-SOURCE-PROJECTION-SCHEMA':
                        raise
            require(matched == 1 if key == 'oneOf' else matched > 0, 'SCHEMA')
    if 'const' in rule:
        require(type(value) is type(rule['const']) and value == rule['const'], 'SCHEMA')
    if 'enum' in rule:
        require(any(type(value) is type(x) and value == x for x in rule['enum']), 'SCHEMA')
    kind = rule.get('type')
    expected = {'object': dict, 'array': list, 'integer': int, 'boolean': bool,
                'string': str, 'null': type(None)}
    if kind:
        require(type(value) is expected[kind], 'SCHEMA')
    if kind == 'object':
        require(set(value) == set(rule['required']), 'SCHEMA')
        for key, child in value.items():
            shape(rule['properties'][key], child, definitions, budget, depth + 1)
    elif kind == 'array':
        require(rule.get('minItems', 0) <= len(value) <= rule.get('maxItems', 4096), 'SCHEMA')
        for child in value:
            shape(rule['items'], child, definitions, budget, depth + 1)
    elif kind == 'integer':
        require(rule.get('minimum', -(1 << 63)) <= value <= rule.get('maximum', (1 << 64) - 1), 'SCHEMA')
    elif kind == 'string':
        require(rule.get('minLength', 0) <= len(value) <= rule.get('maxLength', 4096), 'SCHEMA')
        if 'pattern' in rule:
            require(re.fullmatch(rule['pattern'], value) is not None, 'SCHEMA')


def schema(budget):
    raw = bounded_read(SCHEMA, 1 << 20, budget)
    require(sha(raw) == SCHEMA_SHA256, 'SCHEMA', 'identity')
    document = json.loads(raw)
    for relative, digest in document['x-source-schemas'].items():
        require(sha(bounded_read(ROOT / relative, 4 << 20, budget)) == digest, 'SCHEMA', relative)
    return document, raw


def run_tool(binary, arguments, budget):
    """Read both pipes incrementally; never buffer unbounded compiler output."""
    before = file_sha(binary, budget)
    process = subprocess.Popen([str(binary), *map(str, arguments)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    start = time.monotonic()
    try:
        while selector.get_map():
            if time.monotonic() - start > 30:
                raise ProjectionError('E-SOURCE-PROJECTION-RESOURCE', 'compiler timeout', 'resource')
            for item, _ in selector.select(0.1):
                budget.charge(work=65536, copied_bytes=65536)
                part = os.read(item.fileobj.fileno(), 65536)
                if not part:
                    selector.unregister(item.fileobj)
                    continue
                require(sum(map(len, output.values())) + len(part) <= MAX_JSON, 'RESOURCE', 'compiler output')
                output[item.data].extend(part)
        result = process.wait(timeout=1)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
    require(file_sha(binary, budget) == before, 'INPUT', 'tool changed')
    if result:
        diagnostic = output['stderr'].decode('utf8', 'replace')[:4096]
        code = ('RESOURCE' if 'E-WITNESS-RESOURCE' in diagnostic or
                'E-SOURCE-PROJECTION-RESOURCE' in diagnostic else
                'SOURCE-SCOPE' if re.search(r'E-(?:WITNESS|SMIR|SOURCE-PROJECTION)-', diagnostic)
                else 'COMPILER-REJECTED')
        require(False, code, diagnostic)
    budget.charge(work=4 * len(output['stdout']), copied_bytes=4 * len(output['stdout']))
    try:
        document = json.loads(output['stdout'])
    except (ValueError, UnicodeError) as error:
        raise ProjectionError('E-SOURCE-PROJECTION-INPUT', 'invalid oracle JSON') from error
    return capture(document, budget), before


BUILTINS = {
    'Bool': ('bool', 1, False), 'SChar': ('signed char', 8, True),
    'UChar': ('unsigned char', 8, False), 'Short': ('short', 16, True),
    'UShort': ('unsigned short', 16, False), 'Int': ('int', 32, True),
    'UInt': ('unsigned int', 32, False), 'Long': ('long', 64, True),
    'ULong': ('unsigned long', 64, False), 'LongLong': ('long long', 64, True),
    'ULongLong': ('unsigned long long', 64, False),
    'Float': ('float', 32, False), 'Double': ('double', 64, False), 'Void': ('void', 0, False),
}


def qref(identity):
    return {'module': {'kind': 'self'}, 'id': identity}


def some(value):
    return {'some': value}


def decl_key(value):
    return (value['canonical_offset'],
            None if value['definition_offset'] is None else value['definition_offset']['some'],
            value['qualified_name'])


def json_bound(value, budget):
    """Charge traversal before computing a conservative JSON allocation bound."""
    pending, bound, nodes = [value], 0, 0
    while pending:
        budget.charge(work=1, copied_bytes=64)
        current = pending.pop()
        nodes += 1
        require(nodes <= 200000, 'RESOURCE', 'generated graph bound')
        bound += 64
        if type(current) is str:
            bound += 12 * len(current)
        elif type(current) is dict:
            budget.charge(work=len(current), copied_bytes=32 * len(current))
            pending.extend(current.keys())
            pending.extend(current.values())
        elif type(current) is list:
            budget.charge(work=len(current), copied_bytes=16 * len(current))
            pending.extend(current)
        require(bound <= MAX_JSON * 16, 'RESOURCE', 'generated JSON bound')
    return bound


def build_identity(record, sidecar, budget):
    record_receipt = read_json(bounded_read(record.parent / 'build-receipt.json', 4 << 20, budget))
    side_receipt = read_json(bounded_read(sidecar.parent / 'sidecar-build-receipt.json', 4 << 20, budget))
    compiler = Path(record_receipt['compiler']['path'])
    compiler_hash = file_sha(compiler, budget)
    require(record_receipt['exit'] == side_receipt['exit'] == 0 and not side_receipt['drift'] and
            PIN in record_receipt['compiler']['version'] and
            side_receipt['compiler'] == record_receipt['compiler'] and
            compiler_hash == record_receipt['compiler']['sha256'], 'INPUT', 'compiler/build identity')
    require(file_sha(record, budget) == record_receipt['binary']['sha256'] and
            file_sha(sidecar, budget) == side_receipt['binary']['sha256'], 'INPUT', 'binary/build identity')
    def expected(entries):
        inputs, seen = {}, set()
        for filename, digest in entries:
            budget.charge(work=8, copied_bytes=256)
            require(type(filename) is str and filename not in seen and '\0' not in filename and
                    Path(filename).is_absolute(), 'INPUT', 'duplicate/invalid build path')
            require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) is not None,
                    'INPUT', 'build digest')
            seen.add(filename)
            canonical = str(Path(filename).resolve())
            require(canonical not in inputs or inputs[canonical] == digest,
                    'INPUT', 'conflicting build aliases')
            inputs[canonical] = digest
        return inputs
    require(type(record_receipt['input_hashes']) is list and type(side_receipt['input_hashes']) is dict,
            'INPUT', 'build input tables')
    for entry in record_receipt['input_hashes']:
        require(type(entry) is dict and set(entry) == {'path', 'sha256'}, 'INPUT', 'build input row')
    left = expected((x['path'], x['sha256']) for x in record_receipt['input_hashes'])
    right = expected(side_receipt['input_hashes'].items())
    require(all(left[name] == right[name] for name in left.keys() & right.keys()),
            'INPUT', 'conflicting shared build input expectations')
    inputs = {**left, **right}
    for filename, digest in inputs.items():
        require(file_sha(Path(filename), budget) == digest, 'INPUT', 'build input changed: ' + filename)
    return compiler, compiler_hash


def match_graph(raw, sidecar, budget):
    require(raw['format'] == 'clang-record-input-draft-v2' and raw['status'] == 'source-witness', 'INPUT')
    require(raw['language'] == 'cpp23' and raw['target'] == sidecar['target'] and
            PIN in raw['library_version'] and PIN in sidecar['library_version'], 'INPUT', 'compiler pin')
    old = {x['id']: x for x in raw['types']}
    new = {x['id']: x for x in sidecar['types']}
    require(len(old) == len(raw['types']) and len(new) == len(sidecar['types']), 'DECLARATION-JOIN', 'duplicate types')
    require(len(raw['record_roots']) == len(sidecar['roots']), 'DECLARATION-JOIN', 'root count')
    forward, reverse, declarations = {}, {}, {}
    pending = [(x['id'], y) for x, y in zip(raw['record_roots'], sidecar['roots'])]
    while pending:
        budget.charge(work=16, edges=1, copied_bytes=128)
        a, z = pending.pop()
        require(a in old and z in new, 'DECLARATION-JOIN', 'type reference')
        if a in forward:
            require(forward[a] == z, 'DECLARATION-JOIN', 'conflicting typed path')
            continue
        require(z not in reverse, 'DECLARATION-JOIN', 'nonbijective types')
        forward[a], reverse[z] = z, a
        x, node = old[a], new[z]
        require(x['const'] == node['const'] and x['volatile'] == node['volatile'], 'DECLARATION-JOIN', 'cv')
        d = node['data']; kind = d['kind']
        if kind == 'record':
            require(x['kind'] == 'record' and x['record_name'] == d['declaration']['qualified_name'] and
                    x['complete'] == d['complete'], 'DECLARATION-JOIN', 'record declaration')
            key = decl_key(d['declaration'])
            previous = declarations.setdefault(x['source_decl'], key)
            require(previous == key and len(set(declarations.values())) == len(declarations),
                    'DECLARATION-JOIN', 'canonical declaration')
            if d['complete']:
                input_record = x['record_input']['some']
                require(all(input_record[k] == d['traits']['some'][k] for k in
                            ('pod03', 'trivial', 'standard_layout', 'polymorphic', 'dynamic', 'empty')),
                        'DECLARATION-JOIN', 'record traits')
                for group in ('fields', 'bases'):
                    require(len(input_record[group]) == len(d[group]), 'DECLARATION-JOIN', group)
                    for index, (left, right) in enumerate(zip(input_record[group], d[group])):
                        require(right['index'] == index, 'DECLARATION-JOIN', 'declaration order')
                        if group == 'bases':
                            require(left['virtual'] == right['virtual'], 'DECLARATION-JOIN', 'base virtual')
                        pending.append((left['type']['id'], right['type']))
        elif kind == 'builtin':
            name, bits, signed = BUILTINS[d['builtin']]
            require(d['value_bits'] == bits and d['signed'] == signed, 'BUILTIN-SCOPE')
            expected = 'void' if name == 'void' else 'float' if name in ('float', 'double') else 'scalar'
            require(x['kind'] == expected, 'DECLARATION-JOIN', 'builtin kind')
            if expected == 'scalar':
                require(x['integer_family'] == 'builtin' and x['value_bits'] == bits and x['signed'] == signed,
                        'DECLARATION-JOIN', 'builtin precision')
        elif kind == 'array':
            require(x['kind'] == 'array' and x['count'] == (None if d['count'] is None else d['count']['some']),
                    'DECLARATION-JOIN', 'array extent')
            pending.append((x['element']['id'], d['element']))
        else:
            require(x['kind'] == kind and x['portable_pointer_kind'] == 'data_ptr', 'DECLARATION-JOIN', 'data pointer')
            if kind == 'reference':
                require(x['reference_category'] == d['category'], 'DECLARATION-JOIN', 'reference category')
            pending.append((x['pointee']['id'], d['pointee']))
    return old, new, forward, reverse


class LayoutBudget:
    def __init__(self, original):
        self.original = original

    def work(self, count=1):
        self.original.work(count)

    def reserve(self, count):
        self.original.reserve_bytes(count)


def derive(request, raw, sidecar, modules, budget):
    _, nominal_api, checked_api, model_api, _, _, site_api = modules
    old, new, forward, reverse = match_graph(raw, sidecar, budget)
    roots = {decl_key(new[i]['data']['declaration']): i for i in sidecar['roots']}
    require(len(roots) == len(sidecar['roots']), 'IDENTITY-CONFLICT', 'duplicate root')
    selected = []
    for row in request['roots']:
        key = decl_key(row['declaration'])
        require(key in roots and key not in selected, 'INPUT', 'requested root')
        selected.append(key)
    require(selected, 'INPUT', 'no record root')
    pending = [roots[x] for x in selected]
    reached = set()
    while pending:
        identity = pending.pop()
        if identity in reached:
            continue
        budget.charge(work=8, edges=1, copied_bytes=128)
        require(identity in new and identity in reverse, 'DECLARATION-JOIN')
        reached.add(identity)
        d = new[identity]['data']
        if d['kind'] == 'record':
            pending.extend(x['type'] for name in ('fields', 'bases') for x in d[name])
        elif d['kind'] == 'array':
            pending.append(d['element'])
        elif d['kind'] in ('pointer', 'reference'):
            pending.append(d['pointee'])
    ids = {identity: index for index, identity in enumerate(sorted(reached))}
    rows, layouts, complete = {}, {}, {}
    family = tuple(request['family'][x] for x in ('namespace', 'name', 'abi_major'))
    expected_unit = nominal_api.unit_identity(*family, request['logical_unit_key'])
    require(request['private_unit'] == expected_unit and request['abi_site'] == site_api.identity() and
            request['site'] == site_api.site_record(), 'COORDINATE', 'unit/site')
    domain = request['domain']
    require(domain['id'] == 0 and domain['abi_identity'] == request['abi_site'] and
            all(domain[x] == 'portable' for x in ('isa', 'abi', 'personality')), 'COORDINATE', 'portable domain')
    declarations, declaration_seen = [], set()
    for key, identity in sorted(ids.items(), key=lambda pair: pair[1]):
        budget.charge(work=64, copied_bytes=1024)
        node = new[key]; d = node['data']; kind = d['kind']
        qualifiers = [q for q in ('const', 'volatile') if node[q]]
        flags = ['complete', 'trivial_copy', 'trivial_destroy']
        source_identity = dict(language='cpp23', linkage='builtin', entity=kind,
                               definition='00' * 32, library=None, unit=None)
        source = dict(id=identity, domain=0, identity=source_identity, kind=kind,
                      qualifiers=qualifiers, bits=0, signed=False, elements=[], extent=None,
                      representation='none', execution=None, layout=None, flags=[], methods=[],
                      enumerators=[], record_input=None)
        if kind == 'builtin':
            name, bits, signed = BUILTINS[d['builtin']]
            source.update(kind='void' if name == 'void' else 'scalar', bits=bits, signed=signed)
            source_identity['entity'] = name
            if name == 'void':
                complete[identity] = False
            else:
                source['flags'] = flags
                complete[identity] = True
        elif kind in ('pointer', 'reference'):
            source.update(bits=64, elements=[qref(ids[d['pointee']])], flags=flags)
            if kind == 'reference':
                source['flags'] = sorted(flags + [d['category'] + '_ref'])
            complete[identity] = True
        elif kind == 'array':
            require(d['count'] is not None and d['count']['some'] > 0, 'SOURCE-SCOPE', 'incomplete/zero array')
            source.update(elements=[qref(ids[d['element']])], extent=some(d['count']['some']), flags=flags)
            complete[identity] = True
        else:
            require(not d['lambda'] and d['user_declared_methods'] == 0, 'TRAIT-SCOPE', 'user method/lambda')
            linkage = d['ast_linkage']
            if linkage == 'External':
                source_identity['linkage'] = 'external'
                require(not d['local_class'] and not d['anonymous_namespace'], 'COORDINATE', 'external private declaration')
            elif linkage in ('Internal', 'UniqueExternal'):
                source_identity['linkage'] = 'internal'
            elif linkage == 'None' and d['local_class']:
                source_identity['linkage'] = 'local'
            else:
                raise ProjectionError('E-SOURCE-PROJECTION-LINKAGE-SCOPE', linkage, 'unavailable')
            decl = d['declaration']
            source_identity['entity'] = decl['qualified_name']
            if source_identity['linkage'] in ('internal', 'local'):
                source_identity['unit'] = some(request['private_unit'])
                source_identity['entity'] += '@decl:' + str(decl['canonical_offset'])
            source_identity['library'] = request['library']
            if decl_key(decl) not in declaration_seen:
                declaration_seen.add(decl_key(decl))
                declarations.append(dict(declaration=decl, ast_linkage=linkage, nominal=qref(identity)))
            complete[identity] = d['complete']
            if d['complete']:
                t = d['traits']['some']
                require(not t['dynamic'] and not t['polymorphic'] and not any(x['virtual'] for x in d['bases']),
                        'SOURCE-SCOPE', 'dynamic/virtual record')
                require(not t['needs_copy_resolution'] and not t['needs_destructor_resolution'] and
                        all(t[x] for x in ('simple_copy', 'trivial_copy_ctor', 'trivially_copyable',
                                           'simple_destructor', 'trivial_destructor')), 'TRAIT-SCOPE')
                observed = old[reverse[key]]['record_input']['some']
                record = capture(observed, budget)
                for group in ('fields', 'bases'):
                    for value in record[group]:
                        ref = value['type']
                        require(ref['module'] == {'kind': 'self'} and ref['id'] in forward, 'DECLARATION-JOIN')
                        value['type'] = qref(ids[forward[ref['id']]])
                require(all(x['bit_width'] is None and not x['anonymous'] for x in record['fields']),
                        'SOURCE-SCOPE', 'bitfield/anonymous record field')
                source['record_input'] = some(record)
                source['flags'] = sorted(flags + ([record['kind']] if record['kind'] in ('class', 'union') else []))
        rows[identity] = source
    # Portable primitive geometry is selected ABI data, never native_size_bits.
    scalar_table = importlib.import_module('layout').SCALARS
    def plain_layout(identity, size, align):
        return dict(id=identity, type=qref(identity), size=size, align=align, data_size=size,
                    nonvirtual_size=size, nonvirtual_align=align, fields=[], bases=[], vptrs=[])
    for identity, source in rows.items():
        if source['kind'] == 'scalar':
            layouts[identity] = plain_layout(identity, *scalar_table[source['identity']['entity']])
        elif source['kind'] in ('pointer', 'reference'):
            layouts[identity] = plain_layout(identity, 8, 8)
        if identity in layouts:
            source['layout'] = some(identity)
    abi = dict(payload_revision=3, identity=request['abi_site'], site=request['site'],
               types=list(rows.values()), layouts=list(layouts.values()), domains=[domain],
               signatures=[], storage_bindings=[], recipes=[], personalities=[], unwind=[],
               catches=[], bridges=[], journals=[])
    n = len(rows) + 1
    bound = json_bound(abi, budget)
    # Conservative precharge for full graph comparison/V3 traversals. Existing
    # independent model performs additional incremental canonical ledger charges.
    budget.charge(work=64 * n**4 * bound * (n.bit_length() + 1), copied_bytes=128 * n*n * bound)
    graph = nominal_api.NominalGraph(abi, 'projection', families={'projection': family})
    checked = checked_api.CheckedRecords(graph, LayoutBudget(budget))
    for identity, source in rows.items():
        if source['kind'] != 'record' or not complete[identity]:
            continue
        reference = checked.bind(qref(identity))
        result = checked.model.layout(reference.key)
        record = source['record_input']['some']
        fields = []
        for index, (field_row, offset) in enumerate(zip(record['fields'], result.fields)):
            normalized = checked.records[reference.key]['fields'][index]
            width = 8 * checked.model.type_layout(normalized['type']).size
            flags = (['no_unique_address'] if field_row['no_unique_address'] else [])
            if field_row['access'] != 'public':
                flags.append(field_row['access'])
            fields.append(dict(declaration_index=index, name=field_row['name']['some'],
                               type=field_row['type'], offset_bits=offset, width_bits=width, flags=sorted(flags)))
        bases = [dict(type=base['type'], offset=result.bases[index], virtual=False,
                      declaration_index=some(index), origin_path=[index],
                      adjustment=dict(kind='fixed', offset=result.bases[index]))
                 for index, base in enumerate(record['bases'])]
        layouts[identity] = dict(id=identity, type=qref(identity), size=result.size, align=result.align,
                                data_size=result.data_size, nonvirtual_size=result.nvsize,
                                nonvirtual_align=result.nvalign, fields=fields, bases=bases, vptrs=[])
    # Class aliases are compared while all record outputs remain unselected;
    # publishing one alias's layout early would create a false conflict with a
    # later top-CV variant of the same actual canonical class.
    for identity, source in rows.items():
        if source['kind'] == 'record' and complete[identity]:
            source['layout'] = some(identity)
    active = set()
    def array_layout(identity):
        budget.work(8)
        if identity in layouts:
            return layouts[identity]
        require(identity not in active, 'LAYOUT', 'by-value cycle')
        source = rows[identity]
        require(source['kind'] == 'array', 'SOURCE-SCOPE', 'incomplete by-value type')
        active.add(identity)
        try:
            element = array_layout(source['elements'][0]['id'])
            count = source['extent']['some']
            require(element['size'] <= model_api.MAX_OBJECT // count, 'LAYOUT', 'extent')
            layouts[identity] = plain_layout(identity, element['size'] * count, element['align'])
            source['layout'] = some(identity)
            return layouts[identity]
        finally:
            active.remove(identity)
    for identity, source in rows.items():
        if source['kind'] == 'array':
            array_layout(identity)
    executions = [dict(id=0, kind='raw', bits=8)]
    for identity, source in rows.items():
        if not complete[identity]:
            continue
        eid = identity + 1
        kind = source['kind']
        if kind == 'scalar':
            value = (dict(id=eid, kind='float', format='binary' + str(source['bits']))
                     if source['identity']['entity'] in ('float', 'double')
                     else dict(id=eid, kind='int', bits=source['bits']))
        elif kind in ('pointer', 'reference'):
            value = dict(id=eid, kind='data_ptr', space='guest_data')
        elif kind == 'record':
            value = dict(id=eid, kind='array', element=qref(0), count=layouts[identity]['size'])
        else:
            child = source['elements'][0]['id']
            require(complete[child], 'SOURCE-SCOPE', 'incomplete array element')
            value = dict(id=eid, kind='array', element=qref(child + 1), count=source['extent']['some'])
        executions.append(value)
        source.update(execution=some(qref(eid)), representation='storage' if kind == 'record' else 'value')
    abi['types'] = sorted(rows.values(), key=lambda x: x['id'])
    abi['layouts'] = sorted(layouts.values(), key=lambda x: x['id'])
    graph = nominal_api.NominalGraph(abi, 'projection', families={'projection': family})
    for source in abi['types']:
        if 'complete' in source['flags']:
            source['identity']['definition'] = graph.fingerprint(qref(source['id']))
    comparisons = []
    compared = set()
    for identity, source in rows.items():
        if source['kind'] != 'record' or not complete[identity]:
            continue
        sid = next(k for k, v in ids.items() if v == identity)
        decl = new[sid]['data']['declaration']
        if decl_key(decl) in compared:
            continue
        compared.add(decl_key(decl))
        native = capture(old[reverse[sid]]['native_layout'], budget)
        def remap(value):
            if type(value) is dict:
                if set(value) == {'module', 'id'}:
                    require(value['module'] == {'kind': 'self'} and value['id'] in forward, 'DECLARATION-JOIN')
                    return qref(ids[forward[value['id']]])
                return {k: remap(v) for k, v in value.items()}
            if type(value) is list:
                return [remap(v) for v in value]
            return value
        native = remap(native)
        portable = layouts[identity]
        comparable = {k: v for k, v in portable.items() if k != 'id'}
        comparisons.append(dict(declaration=decl, status='equal' if native == comparable else 'different',
                                native=native, portable=portable))
    return abi, executions, declarations, comparisons


def assemble(request, executions, abi):
    family = dict(request['family'], abi_minor=request['abi_minor'])
    return {
        1: dict(payload_revision=2, types=executions, memory_layouts=[]),
        2: dict(payload_revision=2, manifest=dict(identity='00' * 32, key=family, kind='object',
            entry=None, site=request['abi_site'], personality=request['personality'], foreign_isa='none',
            dependencies=[], exports=[]), symbols=[], comdats=[], initializers=[], finalizers=[]),
        3: dict(payload_revision=2, functions=[]), 4: dict(payload_revision=1, segments=[]),
        5: dict(payload_revision=2, relocations=[], constant_initializers=[]),
        6: dict(payload_revision=1, imports=[]), 7: dict(payload_revision=1, segments=[]),
        8: dict(payload_revision=1, functions=[]),
        9: dict(payload_revision=1, capabilities=[], requirements=[], limits=[]), 10: abi,
    }


def _source_profile(original: bytes) -> None:
    """Finite main-buffer byte exclusions; not a general C++ lexer."""
    require(not any(token in original for token in (b'#', b'%:', b'??=')) and
            re.search(rb'\\[ \t\v\f]*[\r\n]', original) is None and
            re.search(rb'\b__[A-Za-z0-9_]*\b', original) is None,
            'SOURCE-SCOPE', 'directives/reserved macros/splices')


def project(request, source_path, record_oracle_path, sidecar_path, *, budget):
    modules = apis()
    context_api, _, _, _, source_api, codec_api, _ = modules
    require(type(budget) is source_api.SourceQueryBudget, 'INPUT', 'canonical budget required')
    request = capture(request, budget)
    definitions, schema_bytes = schema(budget)
    shape(definitions['$defs']['request'], request, definitions['$defs'], budget)
    source_path, record_oracle_path, sidecar_path = map(Path, (source_path, record_oracle_path, sidecar_path))
    compiler, compiler_before = build_identity(record_oracle_path, sidecar_path, budget)
    original = bounded_read(source_path, MAX_SOURCE, budget)
    budget.charge(work=8 * len(original) + 1, copied_bytes=256)
    _source_profile(original)
    configured = os.environ.get('SMIR_SOURCE_PROJECTION_DIR')
    parent = Path(configured) if configured is not None else None
    if parent is not None:
        parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='smir-source-projection-', dir=parent) as folder:
        snapshot = Path(folder) / 'unit.cpp'
        budget.charge(work=len(original), copied_bytes=len(original))
        snapshot.write_bytes(original)
        raw, record_hash = run_tool(record_oracle_path, [snapshot, request['oracle_unit'], 'cpp23'], budget)
        sidecar, sidecar_hash = run_tool(sidecar_path, [snapshot], budget)
        shape(definitions['$defs']['sidecar'], sidecar, definitions['$defs'], budget)
        require(sidecar['source_sha256'] == sha(original) and sidecar['options'] == OPTIONS and
                sidecar['llvm_pin'] == PIN and raw['source_owner'] == request['oracle_unit'], 'DECLARATION-JOIN')
        abi, executions, declarations, comparisons = derive(request, raw, sidecar, modules, budget)
    schemas = {name: json.loads(bounded_read(ROOT / f'docs/specifications/smir/portable/schema/{name}/candidate.json',
                                            4 << 20, budget)) for name in ('execution', 'runtime', 'abi')}
    codec = codec_api.CandidateCodec(schemas)
    roots = assemble(request, executions, abi)
    bound = json_bound(roots, budget)
    budget.charge(work=128 * bound, copied_bytes=128 * bound)
    encoded = codec.encode(roots, kind=1, entry=codec_api.NO_ENTRY)
    decoded = codec.decode(encoded)
    owner = context_api.RootContext(decoded.roots)
    stamp = owner.prepare_source_data(budget=budget)
    owner.verify_abi()
    owner.verify_execution()
    report = codec_api.reference_report(encoded)
    require(report['reference_verified'] and report['functions'] == 0 and not report['production_admitted'], 'INPUT')
    require(owner.prepare_source_data(budget=budget) is stamp, 'INPUT', 'original afterguard')
    require(bounded_read(source_path, MAX_SOURCE, budget) == original and
            bounded_read(SCHEMA, 1 << 20, budget) == schema_bytes, 'INPUT', 'source/schema changed')
    compiler_hash = file_sha(compiler, budget)
    require(compiler_hash == compiler_before, 'INPUT', 'compiler changed')
    obligations = (
        'Original logical unit and domain runtime/build/library identities are declared input coordinates, not independent artifact proof.',
        'Static AST/source/layout agreement does not issue private facts or prove C++ body/lifetime/access semantics.',
        'No LLVM backend, source calls, runtime alias, interpretation/JIT/native guest or compiler freeze admission.',
        'Current Rust finite record coverage remains a separate unavailable gate until explicitly extended.')
    budget.charge(work=bound * 8, copied_bytes=bound * 16)
    result = Projection(freeze(request), sha(original), compiler_hash, sidecar_hash, record_hash,
                        sha(json.dumps(OPTIONS, separators=(',', ':')).encode()),
                        tuple(freeze(x) for x in declarations), tuple(freeze(x) for x in executions), freeze(abi),
                        tuple(freeze(x) for x in comparisons), obligations, decoded.content_digest,
                        tuple(freeze(dict(section=n, digest=h.hex())) for n, h in stamp.root_digests))
    shape(definitions['$defs']['projection'], result.report(), definitions['$defs'], budget)
    return result


def build_oracles(llvm, output):
    """Build actual tools from pinned read-only LLVM and existing producer sources."""
    llvm, output = Path(llvm).resolve(), Path(output).resolve()
    require(not output.is_relative_to(ROOT) and not output.is_relative_to(llvm), 'INPUT', 'external build output')
    output.mkdir(parents=True, exist_ok=False)
    builder = load_file_module('_rax_llvm_projection_old_builder', TOOL / 'record_layout/builder.py')
    record = builder.build(llvm, output / 'record')
    previous = json.loads((record.parent / 'build-receipt.json').read_text())
    original = previous['argv']
    first_source = next(i for i, x in enumerate(original) if x.endswith('.cpp'))
    options = original[:first_source]
    source = TOOL / 'source_projection.cpp'
    executable = output / 'source-projection-sidecar'
    command = [x for x in original if not x.endswith('.cpp')]
    command[first_source:first_source] = [str(source)]
    command[command.index('-o') + 1] = str(executable)
    dependency = builder.command(options + ['-MM', '-MT', 'projection', str(source)])
    require(dependency.returncode == 0, 'INPUT', 'native dependency query')
    import shlex
    tokens = shlex.split(dependency.stdout.replace('\\\n', ''))
    require(tokens and tokens[0] == 'projection:', 'INPUT', 'dependency syntax')
    paths = {Path(x['path']) for x in previous['input_hashes']}
    paths.update(Path(x).resolve() for x in tokens[1:])
    paths.update((source, Path(__file__).resolve(), SCHEMA))
    before = {str(x): builder.digest(x) for x in sorted(paths)}
    temporary = output / 'sidecar-tmp'
    temporary.mkdir()
    result = builder.command(command, env=dict(os.environ, TMPDIR=str(temporary)))
    (output / 'sidecar-build.stdout').write_text(result.stdout)
    (output / 'sidecar-build.stderr').write_text(result.stderr)
    drift = [x for x, h in before.items() if builder.digest(Path(x)) != h]
    receipt = dict(command=command, exit=result.returncode, compiler=previous['compiler'],
                   input_hashes=before, drift=drift,
                   scope='Native compiler AST-only tool build; non-system headers/static libraries guarded, not full SDK/shared-library attestation')
    if not result.returncode:
        receipt['binary'] = dict(path=str(executable), sha256=builder.digest(executable))
    (output / 'sidecar-build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    require(not drift and result.returncode == 0, 'INPUT', 'native build failed or inputs changed')
    return dict(record=str(record), sidecar=str(executable))


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build')
    build.add_argument('--llvm', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    run = commands.add_parser('project')
    run.add_argument('--request', type=Path, required=True)
    run.add_argument('--source', type=Path, required=True)
    run.add_argument('--record-oracle', type=Path, required=True)
    run.add_argument('--sidecar', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'build':
            result = build_oracles(args.llvm, args.output)
        else:
            api = apis()[4]
            budget = api.SourceQueryBudget(max_work=10**18, max_edges=10**10,
                                           max_copied_bytes=10**16, max_depth=128)
            request = read_json(bounded_read(args.request, 1 << 20, budget))
            result = project(request, args.source, args.record_oracle, args.sidecar, budget=budget).report()
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except ProjectionError as error:
        print(json.dumps(dict(status='rejected', code=error.code, kind=error.kind, detail=error.detail)))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
