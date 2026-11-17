"""Actual opt-in AST programs and independent existing-target IR/host witnesses."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from builder import REPOSITORY, build, digest

FIXTURES = REPOSITORY / 'docs/specifications/smir/portable/conformance/llvm/record-layout'
SCHEMA = REPOSITORY / 'docs/specifications/smir/portable/llvm/source-program-witness.schema.json'


def validate(schema, value, definitions=None):
    """Execute this closed JSON Schema subset; reject unknown schema keywords."""
    definitions = schema.get('$defs', {}) if definitions is None else definitions
    allowed = {'$schema', '$id', '$comment', '$defs', '$ref', 'anyOf', 'type', 'properties',
               'required', 'additionalProperties', 'items', 'maxItems', 'minimum', 'maximum',
               'minLength', 'maxLength', 'pattern', 'const', 'enum'}
    if set(schema) - allowed:
        raise ValueError('unsupported schema keyword')
    if '$ref' in schema:
        return validate(definitions[schema['$ref'].removeprefix('#/$defs/')], value, definitions)
    if 'anyOf' in schema:
        for candidate in schema['anyOf']:
            try:
                validate(candidate, value, definitions)
                return
            except ValueError:
                pass
        raise ValueError('no schema alternative')
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        raise ValueError('constant')
    if 'enum' in schema and not any(type(value) is type(v) and value == v for v in schema['enum']):
        raise ValueError('enum')
    kind = schema.get('type')
    types = {'object': dict, 'array': list, 'integer': int, 'string': str, 'boolean': bool, 'null': type(None)}
    if kind and type(value) is not types[kind]:
        raise ValueError('type')
    if kind == 'object':
        if set(value) != set(schema['required']) or schema['additionalProperties'] is not False:
            raise ValueError('exact fields')
        for key, child in value.items():
            validate(schema['properties'][key], child, definitions)
    if kind == 'array':
        if len(value) > schema['maxItems']:
            raise ValueError('array limit')
        for child in value:
            validate(schema['items'], child, definitions)
    if kind == 'integer' and not schema['minimum'] <= value <= schema['maximum']:
        raise ValueError('integer bound')
    if kind == 'string':
        if not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', 1 << 30):
            raise ValueError('string bound')
        if 'pattern' in schema and re.fullmatch(schema['pattern'], value) is None:
            raise ValueError('pattern')


def links(report):
    records = {r['id'] for r in report['records']}
    types = {r['id']: r for r in report['types']}
    methods = {r['id']: r for r in report['methods']}
    if (len(records) != len(report['records']) or len(types) != len(report['types']) or
            len(methods) != len(report['methods'])):
        raise ValueError('duplicate source identity')
    owners, identities = set(), set()
    for typ in types.values():
        if typ['element_record'] is not None and typ['element_record'] not in records:
            raise ValueError('record reference')
        if any(int(n) > (1 << 63) - 1 for n in typ['array_extents']):
            raise ValueError('extent')
    for method in methods.values():
        if method['record'] not in records or any(t not in types for t in method['parameters']):
            raise ValueError('method reference')
    for program in report['programs']:
        if (program['owner_label'] in owners or program['id'] in identities or
                program['owner_label'] != 'program_' + str(program['id']) or
                program['source_method'] not in methods):
            raise ValueError('program source/owner')
        owners.add(program['owner_label'])
        identities.add(program['id'])
        source_method = methods[program['source_method']]
        if source_method['record'] != program['source_record']:
            raise ValueError('program record association')
        if not source_method['has_definition'] or source_method['implicit']:
            raise ValueError('program definition')
        complete = program['variant'].startswith('complete_')
        if program['coverage'] != ('complete' if complete else 'nonvirtual'):
            raise ValueError('coverage')
        delegate = program['delegate']
        constructor = program['variant'].endswith('constructor')
        if source_method['name'].rsplit('::', 1)[-1].startswith('~') == constructor:
            raise ValueError('program method variant')
        expected_cleanup = ('matching_variant_after_target_completion' if delegate is not None else
                            'reverse_completed_prefix' if constructor else 'body_then_reverse_covered')
        if program['cleanup'] != expected_cleanup:
            raise ValueError('program cleanup')
        if delegate is not None:
            if (delegate['target_method'] not in methods or program['steps'] or
                    delegate['target_method'] == program['source_method'] or
                    delegate['target_variant'] != program['variant'] or
                    methods[delegate['target_method']]['name'].rsplit('::', 1)[-1].startswith('~') or
                    methods[delegate['target_method']]['record'] != program['source_record']):
                raise ValueError('delegation')
        for index, step in enumerate(program['steps']):
            if (step['order'] != index or step['type'] not in types or
                    step['declaring_record'] != program['source_record'] or
                    (not complete and step['kind'] == 'virtual_base') or
                    ((step['destruction'] == 'none') != (step['destructor_method'] is None)) or
                    (program['variant'].endswith('destructor') and step['initializer'] is not None) or
                    (step['destructor_method'] is not None and step['destructor_method'] not in methods)):
                raise ValueError('slot reference/order')
            if step['destructor_method'] is not None:
                target = methods[step['destructor_method']]
                element = types[step['type']]['element_record']
                expected_destruction = 'complete' if step['kind'] == 'member' else 'base'
                if (element is None or target['record'] != element or target['parameters'] or
                        not target['name'].rsplit('::', 1)[-1].startswith('~') or
                        step['destruction'] != expected_destruction):
                    raise ValueError('destructor association')


class SourceLifetimePrograms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.llvm = Path(os.environ.get('LLVM_REFERENCE_CHECKOUT', '/Users/int/dev/llvm-project'))
        parent = Path(os.environ.get('SMIR_RECORD_WITNESS_DIR', '/tmp/rax-portable-smir-01/LLVM/source-program-runs')).resolve()
        if parent.is_relative_to(REPOSITORY.resolve()) or parent.is_relative_to(cls.llvm.resolve()):
            raise ValueError('source-program outputs must be outside both checkouts')
        parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='programs-', dir=parent))
        source_paths = {Path(__file__), SCHEMA, *FIXTURES.glob('source-*-programs.cpp'),
                        *Path(__file__).parent.glob('*.cpp'), Path(__file__).parent / 'producer.hpp',
                        Path(__file__).parent / 'builder.py'}
        source_before = {p: digest(p) for p in source_paths}
        cls.binary = build(cls.llvm, cls.output / 'build')
        if any(digest(p) != h for p, h in source_before.items()):
            raise ValueError('source-program test/build inputs changed during setup')
        receipt = json.loads((cls.output / 'build/build-receipt.json').read_text())
        paths = {Path(r['path']) for r in receipt['input_hashes']}
        paths.update([Path(__file__), SCHEMA, *FIXTURES.glob('source-*-programs.cpp')])
        cls.before = {p: digest(p) for p in paths}
        cls.schema = json.loads(SCHEMA.read_text())
        cls.observations = []

    @classmethod
    def tearDownClass(cls):
        drift = [str(p) for p, h in cls.before.items() if digest(p) != h]
        (cls.output / 'observations.json').write_text(json.dumps(dict(
            scope='Actual AST source order; independent existing-target IR and host-native finite cases only. No SMIR, runtime authority or Scope proof.',
            source_inputs=[dict(path=str(p), sha256=h) for p, h in sorted(cls.before.items())],
            drift=drift, observations=cls.observations), indent=2) + '\n')
        assert not drift, drift
        print('Source-program artifacts retained:', cls.output)

    def produce(self, name, *, source=None, reject=None):
        path = FIXTURES / name if source is None else self.output / name
        if source is not None:
            path.write_text(source)
        process = subprocess.run([str(self.binary), str(path), 'source_program_unit', 'cpp23', '--source-programs'],
                                 text=True, capture_output=True, timeout=30)
        self.observations.append(dict(kind='AST', source=str(path), sha256=digest(path),
                                      exit=process.returncode, stderr=process.stderr))
        (self.output / (name + '.stdout')).write_text(process.stdout)
        if reject:
            self.assertNotEqual(process.returncode, 0)
            self.assertIn(reject, process.stderr)
            self.assertEqual(process.stdout, '')
            return None
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        validate(self.schema, report)
        links(report)
        return report

    def test_complete_base_order_and_symbolic_arrays_from_actual_ast(self):
        report = self.produce('source-construction-programs.cpp')
        names = {r['id']: r['name'] for r in report['records']}
        programs = {p['variant']: p for p in report['programs'] if names[p['source_record']] == 'Diamond'}
        self.assertEqual(set(programs), {'complete_constructor', 'base_constructor', 'complete_destructor', 'base_destructor'})
        def label(step):
            return step['member'] or names[next(t['element_record'] for t in report['types'] if t['id'] == step['type'])]
        complete = [label(s) for s in programs['complete_constructor']['steps']]
        base = [label(s) for s in programs['base_constructor']['steps']]
        self.assertEqual(complete, ['Virtual', 'Left', 'Right', 'first', 'second', 'array'])
        self.assertEqual(base, complete[1:])
        self.assertEqual([label(s) for s in programs['complete_destructor']['steps']], complete[::-1])
        self.assertEqual([label(s) for s in programs['base_destructor']['steps']], base[::-1])
        members = programs['complete_constructor']['steps'][-3:]
        self.assertEqual([s['initializer']['textual_index'] for s in members], [2, 0, 4])
        self.assertEqual([s['initializer']['sema_index'] for s in members], [3, 4, 5])
        array_type = next(t for t in report['types'] if t['id'] == members[-1]['type'])
        self.assertEqual(array_type['array_extents'], ['2'])
        self.assertEqual(members[-1]['array_progress'], 'symbolic_prefix_reverse_cleanup')
        self.assertEqual(len({p['owner_label'] for p in programs.values()}), 4)
        uninitialized = self.produce('uninitialized.cpp', source='struct A { int value; A(){} ~A(){} };')
        for program in uninitialized['programs']:
            self.assertIsNone(program['steps'][0]['initializer'])
            self.assertEqual(program['steps'][0]['destruction'], 'none')
        references = self.produce('reference.cpp', source='struct P { P(){} ~P(){} }; struct A { P& value; A(P& p):value(p){} ~A(){} };')
        owners = {r['id']: r['name'] for r in references['records']}
        for program in references['programs']:
            if owners[program['source_record']] == 'A':
                self.assertEqual(program['steps'][0]['destruction'], 'none')
                self.assertIsNone(program['steps'][0]['destructor_method'])

    def test_delegation_retains_actual_target_and_distinct_program_owner(self):
        report = self.produce('source-delegating-programs.cpp')
        delegates = [p for p in report['programs'] if p['delegate'] is not None]
        self.assertEqual(len(delegates), 2)
        for p in delegates:
            target = next(q for q in report['programs'] if q['source_method'] == p['delegate']['target_method'] and q['variant'] == p['variant'])
            self.assertNotEqual(target['id'], p['id'])
            self.assertNotEqual(target['owner_label'], p['owner_label'])
            self.assertEqual(p['cleanup'], 'matching_variant_after_target_completion')

    def test_unsupported_source_shapes_diagnose_without_partial_output(self):
        for name, source, code in [
            ('dependent.cpp', 'template<class T> struct A { T x; A():x(){} ~A(){} };', 'E-SOURCE-PROGRAM-DEPENDENT'),
            ('union.cpp', 'union A { int x; A():x(0){} ~A(){} };', 'E-SOURCE-PROGRAM-UNION'),
            ('unresolved.cpp', 'struct A { A(); ~A(){} };', 'E-SOURCE-PROGRAM-NO-DEFINITION'),
            ('member-pointer.cpp', 'struct A { int A::* p; A():p(nullptr){} ~A(){} };', 'E-SOURCE-PROGRAM-TYPE'),
            ('try.cpp', 'struct A { A() try {} catch(...) {} ~A(){} };', 'E-SOURCE-PROGRAM-FUNCTION-TRY'),
            ('defaulted.cpp', 'struct A { A()=default; ~A(){} };', 'E-SOURCE-PROGRAM-NO-DEFINITION'),
            ('abstract.cpp', 'struct A { A(){} virtual void f()=0; ~A(){} };', 'E-SOURCE-PROGRAM-ABSTRACT'),
            ('rank.cpp', 'struct A { int a' + '[1]' * 17 + '; A():a{}{} ~A(){} };', 'E-SOURCE-PROGRAM-ARRAY-EXTENT'),
        ]:
            with self.subTest(name=name):
                self.produce(name, source=source, reject=code)

    def test_closed_schema_and_reference_associations_reject_corruption(self):
        original = self.produce('source-delegating-programs.cpp')
        for change in (lambda d: d.update(runtime_authority=True), lambda d: d.update(unknown=0),
                       lambda d: d['programs'][0].update(id=True)):
            damaged = copy.deepcopy(original)
            change(damaged)
            with self.assertRaises(ValueError):
                validate(self.schema, damaged)
        damaged = copy.deepcopy(original)
        damaged['programs'][0]['source_method'] = 99999
        with self.assertRaises(ValueError):
            links(damaged)
        for change, reason in [
            (lambda d: d['programs'][0].update(cleanup='body_then_reverse_covered'), 'program cleanup'),
            (lambda d: next(m for m in d['methods'] if m['id'] == d['programs'][0]['source_method']).update(has_definition=False), 'program definition'),
        ]:
            damaged = copy.deepcopy(original)
            change(damaged)
            validate(self.schema, damaged)  # Structurally valid does not imply coherent source semantics.
            with self.assertRaisesRegex(ValueError, reason):
                links(damaged)
        damaged = self.produce('source-construction-programs.cpp')
        step = next(s for p in damaged['programs'] for s in p['steps'] if s['destructor_method'] is not None)
        element = next(t['element_record'] for t in damaged['types'] if t['id'] == step['type'])
        wrong = next(m for m in damaged['methods'] if m['record'] != element and
                     m['name'].rsplit('::', 1)[-1].startswith('~'))
        step['destructor_method'] = wrong['id']
        validate(self.schema, damaged)
        with self.assertRaisesRegex(ValueError, 'destructor association'):
            links(damaged)
        for delegated in (False, True):
            damaged = copy.deepcopy(original)
            program = next(p for p in damaged['programs'] if p['variant'].endswith('constructor') and
                           (p['delegate'] is not None) == delegated)
            destructor = next(m['id'] for m in damaged['methods'] if m['record'] == program['source_record'] and
                              m['name'].rsplit('::', 1)[-1].startswith('~'))
            if delegated:
                program['delegate']['target_method'] = destructor
            else:
                program['source_method'] = destructor
            validate(self.schema, damaged)
            with self.assertRaisesRegex(ValueError, 'delegation' if delegated else 'program method variant'):
                links(damaged)

    def test_default_cli_and_json_stay_separate(self):
        arguments = [str(self.binary), str(FIXTURES / 'source-delegating-programs.cpp'), 'default_unit']
        implicit = subprocess.run(arguments, text=True, capture_output=True, timeout=30)
        explicit = subprocess.run(arguments + ['cpp23'], text=True, capture_output=True, timeout=30)
        self.assertEqual(implicit.returncode, 0, implicit.stderr)
        self.assertEqual(implicit.stdout, explicit.stdout)
        self.assertEqual(json.loads(implicit.stdout)['format'], 'clang-record-input-draft-v2')
        self.assertNotIn('programs', json.loads(implicit.stdout))
        opt_default = subprocess.run(arguments + ['--source-programs'], text=True, capture_output=True, timeout=30)
        opt_explicit = subprocess.run(arguments + ['cpp23', '--source-programs'], text=True, capture_output=True, timeout=30)
        self.assertEqual(opt_default.returncode, 0, opt_default.stderr)
        self.assertEqual(opt_default.stdout, opt_explicit.stdout)
        rejected = subprocess.run(arguments + ['c23', '--source-programs'], text=True, capture_output=True, timeout=30)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn('E-SOURCE-PROGRAM-CXX-REQUIRED', rejected.stderr)

    def test_independent_pinned_ir_has_distinct_virtual_base_coverage(self):
        argv = [str(self.llvm / 'build/bin/clang++'), '-std=c++23', '-target', 'x86_64-unknown-linux-gnu',
                '-nostdinc', '-O0', '-S', '-emit-llvm', str(FIXTURES / 'source-construction-programs.cpp'), '-o', '-']
        process = subprocess.run(argv, text=True, capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        (self.output / 'construction.ll').write_text(process.stdout)
        def body(name):
            return re.search(r'^define[^@]*@' + name + r'\([^\n]*\).*?\{(.*?)^}', process.stdout, re.M | re.S).group(1)
        self.assertIn('@_ZN7VirtualC2Ev', body('_ZN7DiamondC1Ev'))
        self.assertNotIn('@_ZN7VirtualC2Ev', body('_ZN7DiamondC2Ev'))
        self.assertIn('@_ZN7VirtualD2Ev', body('_ZN7DiamondD1Ev'))
        self.assertNotIn('@_ZN7VirtualD2Ev', body('_ZN7DiamondD2Ev'))
        self.observations.append(dict(kind='existing-target-IR', argv=argv, exit=process.returncode, native=False))

    def test_independent_host_normal_partial_array_and_delegation_cleanup(self):
        source = self.output / 'host.cpp'
        source.write_text('''extern "C" void exercise();
extern "C" void exercise_delegate();
int events[64], count, failure;
extern "C" void event(int value) { events[count++]=value; if(value==failure) throw value; }
bool match(const int* expected,int size) { if(count!=size)return false; for(int i=0;i<size;++i)if(events[i]!=expected[i])return false; return true; }
int main() {
  int normal[]={10,20,30,40,50,60,61,-61,-60,-50,-40,-30,-20,-10};
  exercise(); if(!match(normal,14))return 1;
  count=0;failure=61;try{exercise();return 2;}catch(int){}
  int partial[]={10,20,30,40,50,60,61,-60,-50,-40,-30,-20,-10};
  if(!match(partial,13))return 3;
  count=0;failure=200;try{exercise_delegate();return 4;}catch(int){}
  int delegate[]={107,200,300};if(!match(delegate,3))return 5;
  count=0;failure=107;try{exercise_delegate();return 6;}catch(int){}
  int target[]={107};return match(target,1)?0:7;
}
''')
        binary = self.output / 'host-cleanup'
        argv = [str(self.llvm / 'build/bin/clang++'), '-std=c++23', '-O0',
                str(FIXTURES / 'source-construction-programs.cpp'),
                str(FIXTURES / 'source-delegating-programs.cpp'), str(source), '-o', str(binary)]
        if os.uname().sysname == 'Darwin':
            sdk = subprocess.check_output(['/usr/bin/xcrun', '--show-sdk-path'], text=True).strip()
            argv[1:1] = ['-isysroot', sdk]
        compiled = subprocess.run(argv, text=True, capture_output=True, timeout=30)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        executed = subprocess.run([str(binary)], text=True, capture_output=True, timeout=10)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.observations.append(dict(kind='host-native-C++-only', argv=argv, compiler_exit=compiled.returncode,
                                      binary_sha256=digest(binary), native_exit=executed.returncode,
                                      scenarios=['normal', 'partial-array', 'delegating-body-throw', 'target-throw']))
