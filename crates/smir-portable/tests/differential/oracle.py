#!/usr/bin/env python3
"""Independent frozen Python/C++ wire oracles and stage-labelled corpus preparation.

No guest instruction is executed. Generated schema tables contain data only;
C++ decoding/re-encoding comes from the independent frozen implementation.
"""
import argparse
from collections import deque
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT / 'docs/specifications/smir/portable'
CORPUS = ROOT / 'crates/smir-portable/conformance/differential'
OWNER_ROOTS = (2, 4, 5, 6, 7, 9, 10)
PAYLOAD_REVISIONS = {1: 2, 2: 2, 3: 2, 4: 1, 5: 2, 6: 1, 7: 1, 8: 1, 9: 1, 10: 3}
MAX_CASE_BYTES = 1024 * 1024


def development_inputs():
    """Current source cut for development only; never a frozen candidate pin."""
    paths = {Path(__file__).resolve(), CORPUS / 'cases.jsonl',
             CORPUS / 'development-manifest.json'}
    for folder in ('tools/smir-format', 'tools/smir-abi', 'tools/smir-runtime-contract'):
        paths.update(path for path in (ROOT / folder).rglob('*')
                     if path.is_file() and path.suffix in {'.py', '.cpp', '.hpp', '.h'}
                     and '__pycache__' not in path.parts)
    paths.update((SPEC / 'schema').rglob('*.json'))
    paths.update((ROOT / 'crates/smir-portable/src').rglob('*.rs'))
    paths.update((ROOT / 'crates/smir-portable/tests/differential').glob('*.rs'))
    paths.update(ROOT / 'crates/smir-portable' / name
                 for name in ('Cargo.toml', 'Cargo.lock', 'build.rs'))
    paths.update((SPEC / 'conformance/abi/candidate').glob('*.json'))
    recipes = [json.loads(line) for line in (CORPUS / 'cases.jsonl').read_text().splitlines()]
    paths.update(fixture_path(row['fixture']) for row in recipes)
    return [dict(path=str(path.relative_to(ROOT)), sha256=sha(path))
            for path in sorted(paths) if path.is_file()]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def codec_module():
    path = ROOT / 'tools/smir-format/codec.py'
    name = '_frozen_smir_differential_codec'
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def schemas():
    return {name: json.loads((SPEC / 'schema' / name / 'candidate.json').read_text())
            for name in ('execution', 'runtime', 'abi')}


def merged_records(tables):
    result = {}
    for table in tables.values():
        for name, definition in table['records'].items():
            if name in result and result[name] != definition:
                raise ValueError(f'conflicting frozen record: {name}')
            result[name] = definition
    return result


def specimen(records, codec, kind, variant=None, depth=0):
    if depth > 64:
        raise ValueError('nonterminating schema specimen')
    if kind.startswith('vec:'):
        return []
    if kind.startswith('opt:'):
        return None
    if kind in codec.RecordCodec.INTEGERS:
        return 0
    primitives = {'bool': False, 'hex': '', 'utf8': '', 'token': 'none',
                  'digest32': '00' * 32, 'bytes': b''}
    if kind in primitives:
        return primitives[kind]
    definition = records[kind]
    discriminator = definition.get('discriminator')
    chosen = variant if discriminator else None
    if discriminator and chosen is None:
        chosen = sorted(definition['variants'])[0]
    fields = definition['variants'][chosen] if discriminator else definition['fields']
    result = {name: specimen(records, codec, child, depth=depth + 1)
              for name, child in fields}
    if discriminator:
        result[discriminator] = chosen
    return result


def record_paths(records, roots):
    """Shortest actual schema edge path; O(record vertices+field edges)."""
    found = {}
    queue = deque((name, section, []) for section, name in sorted(roots.items()))
    while queue:
        name, section, path = queue.popleft()
        if name in found:
            continue
        found[name] = (section, path)
        definition = records[name]
        layouts = definition.get('variants', {None: definition.get('fields', [])})
        for variant, fields in sorted(layouts.items(), key=lambda row: str(row[0])):
            for field, kind in fields:
                child = kind.split(':')[-1]
                if child in records:
                    queue.append((child, section, [*path, (name, variant, field, kind)]))
    return found


def wrap(value, kind):
    for wrapper in reversed(kind.split(':')[:-1]):
        if wrapper == 'vec':
            value = [value]
        elif wrapper == 'opt':
            value = {'some': value}
        else:
            raise ValueError(f'unknown schema wrapper: {wrapper}')
    return value


def wire_specimen(codec, tables, records, paths, name, variant):
    roots = {section: specimen(records, codec, record)
             for section, record in codec.CandidateCodec.ROOTS.items()}
    section, path = paths[name]
    value = specimen(records, codec, name, variant)
    for parent, tag, field, kind in reversed(path):
        enclosing = specimen(records, codec, parent, tag)
        enclosing[field] = wrap(value, kind)
        value = enclosing
    roots[section] = value
    for section, root in roots.items():
        root['payload_revision'] = PAYLOAD_REVISIONS[section]
    roots[2]['manifest']['kind'] = 'object'
    roots[2]['manifest']['entry'] = None
    return codec.CandidateCodec(tables).encode(roots)


def fixture_path(name):
    if name.startswith('function-addresses:'):
        return SPEC / 'conformance/execution/function-addresses/cases.json'
    return SPEC / 'conformance/execution/candidate' / name


def fixture_roots(name):
    path = fixture_path(name)
    document = json.loads(path.read_text())
    if name.startswith('function-addresses:'):
        identifier = name.split(':', 1)[1]
        matches = [case for case in document['cases'] if case['id'] == identifier]
        if len(matches) != 1 or matches[0]['scope'] != 'abi-and-execution':
            raise ValueError('whole-object corpus requires a unique ABI-and-execution source fixture')
        document = matches[0]
    roots = {int(number): value for number, value in document['sections'].items()}
    for section, value in {
        5: {'payload_revision': 2, 'relocations': [], 'constant_initializers': []},
        7: {'payload_revision': 1, 'segments': []},
        9: {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []},
    }.items():
        roots.setdefault(section, value)
    roots[2]['manifest'].update(kind='object', entry=None)
    if name == 'service-wrapper.json':
        roots[9]['capabilities'] = ['memory']
    return roots


def edit(roots, mutation):
    target = roots
    path = mutation['path']
    for part in path[:-1]:
        target = target[int(part) if isinstance(target, list) or target is roots else part]
    key = int(path[-1]) if isinstance(target, list) or target is roots else path[-1]
    if mutation['operation'] == 'set':
        target[key] = mutation['value']
    elif mutation['operation'] == 'duplicate':
        target[key].append(copy.deepcopy(target[key][mutation['index']]))
    elif mutation['operation'] == 'repeat':
        count = mutation['count']
        if type(count) is not int or not 0 <= count <= 65_536:
            raise ValueError('owned repetition budget')
        target[key] = [copy.deepcopy(mutation['value']) for _ in range(count)]
    else:
        raise ValueError('unknown owned corpus mutation')


def owner_entries(codec, decoded):
    return [dict(kind='abi-contract' if section == 10 else 'runtime-contract',
                 section=section, path=[], record_type=codec.CandidateCodec.ROOTS[section],
                 canonical_record_hex=codec.RecordCodec(merged_records(schemas())).encode(
                     codec.CandidateCodec.ROOTS[section], decoded.roots[section]).hex())
            for section in OWNER_ROOTS]


def cpp_schema(records):
    def fields(layout):
        return '{' + ','.join('{' + json.dumps(name) + ',' + json.dumps(kind) + '}'
                              for name, kind in layout) + '}'
    rows = []
    for name, record in sorted(records.items()):
        variants = '{' + ','.join('{' + json.dumps(tag) + ',' + fields(layout) + '}'
                                  for tag, layout in sorted(record.get('variants', {}).items())) + '}'
        rows.append('{' + json.dumps(name) + ',{' + json.dumps(record.get('discriminator', ''))
                    + ',' + fields(record.get('fields', [])) + ',' + variants + '}}')
    return 'const rax::smir::records::Schema smir_test_schema = {\n' + ',\n'.join(rows) + '\n};\n'


def build_cpp(records, output):
    compiler = os.environ.get('CXX')
    sdk = None
    if sys.platform == 'darwin':
        sdk = subprocess.check_output(['/usr/bin/xcrun', '--show-sdk-path'], text=True).strip()
        if compiler is None:
            compiler = subprocess.check_output(['/usr/bin/xcrun', '--find', 'clang++'], text=True).strip()
    compiler = compiler or shutil.which('clang++')
    if compiler is None:
        raise ValueError('C++20 compiler unavailable; oracle cannot be skipped')
    executable = shutil.which(compiler)
    if executable is None:
        raise ValueError('CXX must name an executable path, not a shell command')
    table = output / 'schema.inc'
    table.write_text(cpp_schema(records))
    binary = output / 'cpp-record-oracle'
    command = [executable, '-std=c++20', '-Wall', '-Wextra', '-Werror',
               '-DSMIR_RECORD_TEST_SCHEMA=' + json.dumps(str(table)),
               str(ROOT / 'tools/smir-format/cpp_probe.cpp'), '-o', str(binary)]
    if sdk is not None:
        command[1:1] = ['-isysroot', sdk]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if completed.returncode:
        raise ValueError(f'C++ oracle compilation failed: {completed.stderr}')
    version = subprocess.run([executable, '--version'], capture_output=True, text=True,
                             check=True, timeout=10).stdout
    return dict(path=str(binary), sha256=sha(binary), argv=command,
                compiler=str(Path(executable).resolve()), compiler_sha256=sha(Path(executable)),
                compiler_version=version, schema_sha256=sha(table), sdk=sdk)


def prepare(output, *, development=False):
    output.mkdir(parents=True, exist_ok=False)
    before = development_inputs() if development else None
    if development:
        (output / 'inputs-before.json').write_text(json.dumps(before, indent=2) + '\n')
    codec = codec_module()
    tables = schemas()
    records = merged_records(tables)
    full = codec.CandidateCodec(tables)
    paths = record_paths(records, codec.CandidateCodec.ROOTS)
    cases = []

    def save(case, data):
        if len(data) > MAX_CASE_BYTES:
            raise ValueError('owned case exceeds explicit transport budget')
        path = output / f'case-{len(cases):04}.smo'
        path.write_bytes(data)
        row = dict(case, path=str(path), bytes=len(data), sha256=sha(path))
        try:
            decoded = full.decode(data)
        except (codec.DecodeError, codec.RecordError) as error:
            row['python_wire'] = dict(outcome='rejected', code=str(error))
        else:
            independent = hashlib.sha256(b'SMIR0.2\0\x02\0\0\0')
            sections = []
            for section in decoded.envelope['sections']:
                number = section['kind']
                if number not in codec.CandidateCodec.ROOTS:
                    continue
                raw = bytes.fromhex(section['hex'])
                normalized = raw[:4] + bytes(32) + raw[36:] if number == 2 else raw
                independent.update(number.to_bytes(2, 'little'))
                independent.update(len(normalized).to_bytes(8, 'little'))
                independent.update(normalized)
                payload = output / f'case-{len(cases):04}-root-{number}.bin'
                payload.write_bytes(raw)
                sections.append(dict(section=number, record_type=full.ROOTS[number], path=str(payload),
                                     value=decoded.roots[number]))
            if independent.hexdigest() != decoded.content_digest:
                raise ValueError('independent identity preimage disagrees')
            if codec.encode_candidate(decoded.envelope) != data:
                raise ValueError('Python roundtrip changed canonical input')
            row['python_wire'] = dict(outcome='decoded', identity=decoded.content_digest,
                                      owner_entries=owner_entries(codec, decoded), sections=sections)
        cases.append(row)

    for line in (CORPUS / 'cases.jsonl').read_text().splitlines():
        case = json.loads(line)
        roots = fixture_roots(case['fixture'])
        for mutation in case.get('mutations', []):
            edit(roots, mutation)
        try:
            data = full.encode(roots, metadata=case.get('metadata', []))
        except (codec.DecodeError, codec.RecordError, ValueError) as error:
            raise ValueError(f'authored case {case["id"]} cannot encode: {error}') from error
        if case.get('payload_mutations'):
            envelope = codec.decode_candidate(data)
            for mutation in case['payload_mutations']:
                section = next(row for row in envelope['sections']
                               if row['kind'] == mutation['section'])
                raw = bytearray.fromhex(section['hex'])
                if 'truncate' in mutation:
                    length = mutation['truncate']
                    if type(length) is not int or not 0 <= length < len(raw):
                        raise ValueError('authored payload truncation boundary changed')
                    section['hex'] = raw[:length].hex()
                    continue
                offset = mutation['offset']
                if mutation.get('operation') == 'xor':
                    value = mutation['value']
                    if type(value) is not int or not 0 < value < 256 or not 0 <= offset < len(raw):
                        raise ValueError('authored payload XOR boundary changed')
                    raw[offset] ^= value
                    section['hex'] = raw.hex()
                    continue
                original = bytes.fromhex(mutation['before_hex'])
                if raw[offset:offset + len(original)] != original:
                    raise ValueError(f'payload mutation source guard changed: {case["id"]} root{mutation["section"]}@{offset}')
                raw[offset:offset + len(original)] = bytes.fromhex(mutation['after_hex'])
                section['hex'] = raw.hex()
            # Repair framing offsets/lengths only. Never reseal the content identity.
            data = codec.encode_candidate(envelope)
        for mutation in case.get('byte_mutations', []):
            data = bytearray(data)
            if mutation['operation'] == 'xor':
                data[mutation['offset']] ^= mutation['value']
            elif mutation['operation'] == 'truncate':
                data = data[:mutation['length']]
            else:
                raise ValueError('unknown byte mutation')
            data = bytes(data)
        save(case, data)
    for name, (_, path) in sorted(paths.items()):
        for variant in sorted(records[name].get('variants', {'record': []})):
            tag = variant if 'discriminator' in records[name] else None
            case = dict(id=f'wire/{name}/{variant}', partition='boundary',
                        oracle_scope='wire-only', static_expectation='not-compared',
                        record=name, variant=tag, schema_section=paths[name][0])
            save(case, wire_specimen(codec, tables, records, paths, name, tag))
    cpp = build_cpp(records, output)
    sources = [ROOT / 'tools/smir-format/codec.py', ROOT / 'tools/smir-format/codec.hpp',
               ROOT / 'tools/smir-format/cpp_probe.cpp', Path(__file__),
               CORPUS / 'cases.jsonl', CORPUS / 'manifest.json',
               CORPUS / 'frozen-inputs.json']
    sources += [SPEC / 'schema' / owner / 'candidate.json' for owner in tables]
    sources += [fixture_path(name)
                for name in sorted({case['fixture'] for case in cases if 'fixture' in case})]
    inputs = development_inputs() if development else [
        dict(path=str(path.relative_to(ROOT)), sha256=sha(path)) for path in sources]
    if development and inputs != before:
        (output / 'inputs-after.json').write_text(json.dumps(inputs, indent=2) + '\n')
        previous = {row['path']: row['sha256'] for row in before}
        current = {row['path']: row['sha256'] for row in inputs}
        changed = sorted(path for path in previous.keys() | current.keys()
                         if previous.get(path) != current.get(path))
        raise ValueError('development source inputs changed during corpus preparation: ' + repr(changed))
    report = dict(protocol='smir-diff-v1', mode='development' if development else 'frozen',
                  compiler_freeze_passed=False, full_p2_qualified=False,
                  cases=cases, cpp=cpp,
                  record_inventory=dict(reachable=sorted(paths),
                                        outside_object_roots=sorted(set(records) - set(paths)),
                                        wire_variant_cases=sum(case['oracle_scope'] == 'wire-only' for case in cases)),
                  inputs=inputs)
    (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(path=str(output / 'prepared.json'), cases=len(cases))))


def verify_reference(path):
    codec = codec_module()
    data = path.read_bytes()
    if len(data) > MAX_CASE_BYTES:
        raise ValueError('reference case transport budget')
    try:
        # Independent context policy, never read from a module's own requests.
        result = codec.reference_report(data, capabilities=('memory',))
    except ValueError as error:
        code = str(error)
        unavailable = code.split(':', 1)[0] in {
            'REFERENCE-DEPENDENCY-SCOPE', 'REFERENCE-COMDAT-SCOPE',
            'REFERENCE-FOREIGN-SCOPE', 'REFERENCE-REQUIREMENT-SCOPE',
            'REFERENCE-INDEPENDENT-NATIVE-EVIDENCE-REQUIRED',
            'REFERENCE-INDEPENDENT-IMPORT-REGISTRATION-REQUIRED',
            'REFERENCE-MANDATORY-CAPABILITY-GRANT',
            'REFERENCE-IMPORT-CAPABILITY-GRANT',
        }
        result = dict(outcome='oracle-unavailable' if unavailable else 'rejected', code=code)
    else:
        result = dict(outcome='reference-verified', identity=result['content_digest'])
    loaded = sorted({Path(module.__file__).resolve() for module in sys.modules.values()
                     if isinstance(getattr(module, '__file__', None), str)
                     and str(Path(module.__file__).resolve()).startswith(str(ROOT) + os.sep)
                     and Path(module.__file__).is_file()})
    result['inputs'] = [dict(path=str(source.relative_to(ROOT)), sha256=sha(source)) for source in loaded]
    print(json.dumps(result))


class StaticScopeUnavailable(Exception):
    """The frozen validator has no sound adapter for this static comparison."""


def verify_static_reference(path, *, declaration_calls=False):
    codec = codec_module()
    data = path.read_bytes()
    if len(data) > MAX_CASE_BYTES:
        raise ValueError('static reference transport budget')
    decoded = codec.CandidateCodec(schemas()).decode(data)
    roots = decoded.roots
    try:
        manifest = roots[2]['manifest']
        if (manifest['foreign_isa'] != 'none' or roots[2]['comdats'] or
                roots[9]['requirements'] or any(d['isa'] != 'portable' for d in roots[10]['domains']) or
                any(i['kind'] in {'host', 'foreign'} for i in roots[6]['imports'])):
            raise StaticScopeUnavailable('STATIC_ORACLE_SCOPE')

        def declared_use(value):
            if isinstance(value, dict):
                if value.get('kind') == 'dependency' and set(value) == {'kind', 'slot'}:
                    return True
                return any(declared_use(child) for name, child in value.items()
                           if not (declaration_calls and name == 'source_plan'
                                   and value.get('op') in {'call', 'invoke', 'tailcall'}))
            if isinstance(value, list):
                return any(declared_use(child) for child in value)
            return False

        if declared_use(roots):
            raise StaticScopeUnavailable('STATIC_ORACLE_USED_DEPENDENCY')
        # Do not remove declarations, invent provider records, select a deployment
        # or inject success callbacks. Every actual local predicate still runs.
        folder = ROOT / 'tools/smir-format/execution'
        sys.path.insert(0, str(folder))
        try:
            from candidate.context import RootContext
            from candidate.bindings import runtime_package_module
            context = RootContext(roots)
            context.verify_abi()
            context.verify_execution()
            runtime = runtime_package_module('linking')
            requested = set(roots[9]['capabilities'])
            if requested <= runtime.CAPABILITIES and not requested <= {'memory'}:
                raise StaticScopeUnavailable('STATIC_ORACLE_GRANT_CONTEXT')

            def unsupported_comparison(*args):
                raise StaticScopeUnavailable('STATIC_ORACLE_COMDAT_SCOPE')

            binding = runtime.Context(
                site=roots[10]['identity'], execution=context.execution,
                nominal=lambda reference: context.abi_entity('nominal', reference),
                function=context.function, symbol=context.runtime_symbol,
                execution_equal=context.types.equal,
                nominal_compatible=context.abi_graph.boundary_compatible,
                storage_layout=context.memory_layout,
                symbol_body=unsupported_comparison, symbol_identity=unsupported_comparison,
                abi_entity=context.abi_entity, target_entity=context.target_entity,
                native_symbol=context.native_symbol, nominal_layout=context.abi_graph.layout,
                grants=frozenset({'memory'}),
                signature_compatible=context.abi_graph.signature_compatible)
            runtime.validate({number: roots[number] for number in runtime.ROOTS}, binding)
            context.assert_snapshot()
        finally:
            sys.path.remove(str(folder))
        result = dict(outcome='static-reference-verified', identity=decoded.content_digest,
                      scope=('actual ABI/execution/runtime static checks; original dependency call-plan declarations; NO deployment selection'
                             if declaration_calls else
                             'actual local ABI/execution/runtime checks; declarations unused; NO deployment selection'))
        if declaration_calls:
            result['unresolved_provider_deployment'] = True
    except StaticScopeUnavailable as error:
        result = dict(outcome='oracle-unavailable', code=str(error))
    except ValueError as error:
        result = dict(outcome='rejected', code=str(error))
    loaded = sorted({Path(module.__file__).resolve() for module in sys.modules.values()
                     if isinstance(getattr(module, '__file__', None), str)
                     and str(Path(module.__file__).resolve()).startswith(str(ROOT) + os.sep)
                     and Path(module.__file__).is_file()})
    result['inputs'] = [dict(path=str(source.relative_to(ROOT)), sha256=sha(source)) for source in loaded]
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    prepare_parser = sub.add_parser('prepare')
    prepare_parser.add_argument('--output', type=Path, required=True)
    prepare_parser.add_argument('--development', action='store_true')
    sub.add_parser('verify-reference').add_argument('path', type=Path)
    sub.add_parser('verify-static-reference').add_argument('path', type=Path)
    sub.add_parser('verify-source-declarations').add_argument('path', type=Path)
    args = parser.parse_args()
    if args.operation == 'prepare':
        prepare(args.output, development=args.development)
    elif args.operation == 'verify-static-reference':
        verify_static_reference(args.path)
    elif args.operation == 'verify-source-declarations':
        verify_static_reference(args.path, declaration_calls=True)
    else:
        verify_reference(args.path)


if __name__ == '__main__':
    main()
