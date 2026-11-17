"""Actual pinned compiler/original-owner witnesses; no substituted positive facts."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import source_projection as S

FIXTURE = S.ROOT / 'docs/specifications/smir/portable/conformance/llvm/source-projection'


class ProjectionWireSchema(unittest.TestCase):
    """Actual schema/wire regression runnable without the native LLVM toolchain."""

    @classmethod
    def setUpClass(cls):
        cls.modules = S.apis()

    @classmethod
    def budget(cls):
        return cls.modules[4].SourceQueryBudget(
            max_work=10**18, max_edges=10**10, max_copied_bytes=10**16, max_depth=128)

    def test_wire_primitive_representations_match_real_codec(self):
        definitions, _ = S.schema(self.budget())
        defs = definitions['$defs']
        rules = {'token': defs['wire_source_field_decl']['properties']['access'],
                 'hex': defs['wire_enum_value']['properties']['value']}
        codec_api = self.modules[5]
        codec = codec_api.RecordCodec({'dummy': {'fields': []}})
        for kind, valid, invalid in [
                ('token', ['a', 'a' * 63], ['', 'a' * 64, 'A', '_a', 'aé']),
                ('hex', ['', '00', 'a0ff'], ['0', '000', 'AA', 'gg'])]:
            for value in valid:
                with self.subTest(kind=kind, value=value):
                    S.shape(rules[kind], value, defs, self.budget())
                    self.assertEqual(codec.decode(kind, codec.encode(kind, value)), value)
            for value in invalid:
                with self.subTest(kind=kind, value=value):
                    with self.assertRaisesRegex(S.ProjectionError, 'SCHEMA'):
                        S.shape(rules[kind], value, defs, self.budget())
                    with self.assertRaises(codec_api.RecordError):
                        codec.encode(kind, value)


    def test_conservative_main_buffer_profile_without_native_tools(self):
        negatives = [b'#include "x"', b'/*prefix*/ #include "x"', b'%:include "x"',
                     b'??=include "x"', b'%\\\n:include "x"', b'%\\ \n:include "x"',
                     b'%\\\t\r\n:include "x"', b'const char *p="%:";', b'/* ??= */',
                     b'const char *p=R"(#)";', b'int __reserved;', b'const char *p="#";',
                     b'\\\v\n', b'\\\f\r']
        for value in negatives:
            with self.subTest(value=value), self.assertRaises(S.ProjectionError) as error:
                S._source_profile(value)
            self.assertEqual((error.exception.code, error.exception.kind),
                             ('E-SOURCE-PROJECTION-SOURCE-SCOPE', 'unavailable'))
        for value in [b'struct A { int field[4]; };', b'const char *p="ordinary";',
                      b'// ordinary\nstruct A {};', b'const char *p="line\\n";']:
            with self.subTest(value=value):
                self.assertIsNone(S._source_profile(value))


class OriginalSourceProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = Path(os.environ.get('SMIR_SOURCE_PROJECTION_TEST_DIR', tempfile.gettempdir()))
        parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='projection-tests-', dir=parent))
        cls.previous_output = os.environ.get('SMIR_SOURCE_PROJECTION_DIR')
        os.environ['SMIR_SOURCE_PROJECTION_DIR'] = str(cls.output / 'source-runs')
        if 'SMIR_SOURCE_PROJECTION_ORACLES' in os.environ:
            cls.oracles = json.loads(Path(os.environ['SMIR_SOURCE_PROJECTION_ORACLES']).read_text())
        else:
            cls.oracles = S.build_oracles(Path(os.environ.get('LLVM_REFERENCE_CHECKOUT', '/Users/int/dev/llvm-project')),
                                          cls.output / 'build')
        cls.modules = S.apis()
        cls.request = json.loads((FIXTURE / 'coordinates.json').read_text())
        cls.source = FIXTURE / 'records.cpp'
        cls.observed = S.project(cls.request, cls.source, cls.oracles['record'], cls.oracles['sidecar'],
                                 budget=cls.budget())

    @classmethod
    def tearDownClass(cls):
        if cls.previous_output is None:
            os.environ.pop('SMIR_SOURCE_PROJECTION_DIR', None)
        else:
            os.environ['SMIR_SOURCE_PROJECTION_DIR'] = cls.previous_output

    @classmethod
    def budget(cls, **changes):
        values = dict(max_work=10**18, max_edges=10**10, max_copied_bytes=10**16, max_depth=128)
        values.update(changes)
        return cls.modules[4].SourceQueryBudget(**values)

    def run_project(self, request=None, source=None, budget=None):
        return S.project(self.request if request is None else request, self.source if source is None else source,
                         self.oracles['record'], self.oracles['sidecar'],
                         budget=self.budget() if budget is None else budget)

    def source_case(self, text):
        path = self.output / ('case-' + str(len(list(self.output.glob('case-*')))) + '.cpp')
        path.write_text(text)
        raw = subprocess.run([self.oracles['sidecar'], str(path)], capture_output=True, text=True, timeout=30)
        request = deepcopy(self.request)
        if raw.returncode == 0:
            side = json.loads(raw.stdout)
            table = {x['id']: x for x in side['types']}
            request['roots'] = [dict(declaration=table[x]['data']['declaration']) for x in side['roots']]
        return path, request

    def test_nonempty_original_owner_all_layouts(self):
        report = self.observed.report()
        self.assertEqual((len(report['abi']['types']), len(report['abi']['layouts']), len(report['declarations'])),
                         (30, 28, 14))
        self.assertEqual(len(report['original_roots']), 10)
        self.assertEqual([x['section'] for x in report['original_roots']], list(range(1, 11)))
        self.assertTrue(all(x['status'] == 'equal' for x in report['native_comparisons']))
        expected = json.loads((FIXTURE / 'expected.json').read_text())['records']
        for row in report['native_comparisons']:
            name = row['declaration']['qualified_name']
            if name in expected:
                e = expected[name]; layout = row['portable']
                self.assertEqual([layout['size'], layout['align'], layout['data_size'], layout['nonvirtual_size']],
                                 e['geometry_octets'], name)
                self.assertEqual([x['offset_bits'] for x in layout['fields']], e['field_offsets_bits'], name)

    def test_bool_precision_reference_storage_and_incomplete(self):
        a = self.observed.report(); types = {x['id']: x for x in a['abi']['types']}
        execution = {x['id']: x for x in a['execution_types']}
        boolean = next(x for x in types.values() if x['identity']['entity'] == 'bool')
        self.assertEqual((boolean['bits'], execution[boolean['execution']['some']['id']]['bits']), (1, 1))
        self.assertEqual(next(l['size'] for l in a['abi']['layouts'] if l['id'] == boolean['layout']['some']), 1)
        for x in types.values():
            if x['kind'] == 'record' and 'complete' in x['flags']:
                e = execution[x['execution']['some']['id']]
                self.assertEqual((x['representation'], e['kind'], e['element']), ('storage', 'array', S.qref(0)))
        forward = next(x for x in types.values() if x['identity']['entity'] == 'Forward')
        self.assertEqual([forward[k] for k in ('execution', 'layout', 'record_input', 'flags')], [None, None, None, []])

    def test_actual_private_same_name_and_top_cv_identity(self):
        types = self.observed.report()['abi']['types']
        local = [x for x in types if x['identity']['linkage'] == 'local']
        self.assertEqual(len(local), 2)
        self.assertNotEqual(local[0]['identity']['entity'], local[1]['identity']['entity'])
        self.assertTrue(all(x['identity']['entity'].startswith('Same@decl:') for x in local))
        self.assertTrue(all(x['identity']['unit'] == S.some(self.request['private_unit']) for x in local))
        inner = [x for x in types if x['kind'] == 'record' and x['identity']['entity'] == 'Inner']
        self.assertEqual(len(inner), 2)
        self.assertEqual({tuple(x['qualifiers']) for x in inner}, {(), ('const',)})
        graph = self.modules[1].NominalGraph(self.observed.report()['abi'], 'projection')
        self.assertTrue(graph.compatible(S.qref(inner[0]['id']), S.qref(inner[1]['id']), ignore_top_cv=True))

    def test_real_lvalue_reference_and_void_pointee(self):
        report = self.observed.report()
        rows = {x['id']: x for x in report['abi']['types']}
        reference = next(x for x in rows.values() if x['kind'] == 'reference')
        self.assertIn('lvalue_ref', reference['flags'])
        self.assertNotIn('rvalue_ref', reference['flags'])
        execution = {x['id']: x for x in report['execution_types']}
        self.assertEqual(execution[reference['execution']['some']['id']]['kind'], 'data_ptr')
        void = next(x for x in rows.values() if x['kind'] == 'void')
        self.assertEqual([void[k] for k in ('flags', 'execution', 'layout', 'representation')],
                         [[], None, None, 'none'])
        self.assertTrue(any(x['kind'] == 'pointer' and x['elements'] == [S.qref(void['id'])]
                            for x in rows.values()))

    def test_all_advertised_builtin_enum_families(self):
        path, request = self.source_case((FIXTURE / 'builtin-values.cpp').read_text())
        result = self.run_project(request, path).report()
        expected = {
            'signed char': (8, True), 'unsigned char': (8, False),
            'short': (16, True), 'unsigned short': (16, False),
            'int': (32, True), 'unsigned int': (32, False),
            'long': (64, True), 'unsigned long': (64, False),
            'long long': (64, True), 'unsigned long long': (64, False),
            'float': (32, False), 'double': (64, False), 'bool': (1, False),
        }
        values = {x['identity']['entity']: (x['bits'], x['signed'])
                  for x in result['abi']['types'] if x['kind'] == 'scalar'}
        self.assertEqual(values, expected)
        self.assertTrue(all(x['status'] == 'equal' for x in result['native_comparisons']))

    def test_large_array_stays_symbolic(self):
        costs = []
        for extent in (10, 10**9):
            path, request = self.source_case('struct Big {int values[' + str(extent) + '];};')
            budget = self.budget()
            result = self.run_project(request, path, budget).report()
            big = next(x for x in result['abi']['types'] if x['identity']['entity'] == 'Big')
            layout = next(x for x in result['abi']['layouts'] if x['id'] == big['layout']['some'])
            self.assertEqual((layout['size'], layout['fields'][0]['width_bits']),
                             (4 * extent, 32 * extent))
            self.assertLess(len(result['abi']['types']), 8)
            costs.append((budget._used_work, budget._used_copied_bytes))
        self.assertLess(costs[1][0], 2 * costs[0][0])
        self.assertLess(costs[1][1], 2 * costs[0][1])

    def test_explicit_family_unit_and_library_coordinates(self):
        request = deepcopy(self.request)
        request['family']['name'] = 'another_projection'
        request['private_unit'] = self.modules[1].unit_identity('llvm_witness', 'another_projection', 1,
                                                             request['logical_unit_key'])
        request['library'] = S.some('ab' * 32)
        other = self.run_project(request).report()
        private = [x for x in other['abi']['types'] if x['identity']['linkage'] in ('internal', 'local')]
        self.assertTrue(all(x['identity']['unit'] == S.some(request['private_unit']) for x in private))
        self.assertTrue(all(x['identity']['library'] == request['library'] for x in private))
        self.assertTrue(all(x['identity']['unit'] is None and x['identity']['library'] is None
                            for x in other['abi']['types'] if x['identity']['linkage'] == 'builtin'))
        self.assertNotEqual(other['module_content_digest'], self.observed.module_content_digest)

    def test_coordinate_mismatch_is_not_inferred(self):
        for field in ('private_unit', 'abi_site'):
            request = deepcopy(self.request); request[field] = 'ff' * 32
            with self.subTest(field=field), self.assertRaisesRegex(S.ProjectionError, 'COORDINATE'):
                self.run_project(request)

    def test_actual_deleted_and_unresolved_copy_refusals(self):
        for text in ('struct Bad {int&& value;};',
                     'struct Bad {Bad(const Bad&)=delete; int value;};',
                     'struct Inner {int x;}; struct Bad {const Inner value;};'):
            source, request = self.source_case(text)
            with self.subTest(source=text), self.assertRaisesRegex(S.ProjectionError, 'TRAIT-SCOPE') as caught:
                self.run_project(request, source)
            self.assertEqual(caught.exception.kind, 'unavailable')

    def test_actual_unsupported_builtin_and_layout_scope(self):
        for text in ('struct Bad {char value;};', 'struct Bad {int value:3;};',
                     'struct Bad {virtual void method(); int value;};',
                     'struct __attribute__((packed)) Bad {int value;};'):
            source, request = self.source_case(text)
            with self.subTest(source=text), self.assertRaises(S.ProjectionError) as caught:
                self.run_project(request, source)
            self.assertEqual(caught.exception.kind, 'unavailable')

    def test_compiler_rejection_and_macro_scope_are_distinct(self):
        source, request = self.source_case('struct Bad { INVALID ??? };')
        with self.assertRaisesRegex(S.ProjectionError, 'COMPILER-REJECTED'):
            self.run_project(request, source)
        source = self.output / 'macro.cpp'; source.write_text('#define N 2\nstruct A {int value[N];};\n')
        with self.assertRaisesRegex(S.ProjectionError, 'SOURCE-SCOPE'):
            self.run_project(source=source)

    def test_closed_schema_bool_id_and_pin_domains(self):
        definitions, _ = S.schema(self.budget())
        mutations = [lambda x: x.update(extra=True), lambda x: x.update(revision=True),
                     lambda x: x.update(private_unit=S.PIN), lambda x: x['roots'][0]['declaration'].update(canonical_offset=True)]
        for mutate in mutations:
            request = deepcopy(self.request); mutate(request)
            with self.subTest(request=request), self.assertRaisesRegex(S.ProjectionError, 'SCHEMA'):
                S.shape(definitions['$defs']['request'], request, definitions['$defs'], self.budget())
        side = json.loads(subprocess.check_output([self.oracles['sidecar'], str(self.source)], text=True))
        side['llvm_pin'] += '0' * 24
        with self.assertRaisesRegex(S.ProjectionError, 'SCHEMA'):
            S.shape(definitions['$defs']['sidecar'], side, definitions['$defs'], self.budget())

    def test_input_and_output_are_not_mutable_authority(self):
        request = deepcopy(self.request); before = deepcopy(request)
        result = self.run_project(request)
        self.assertEqual(request, before)
        with self.assertRaises(FrozenInstanceError): result.runtime_authority = True
        with self.assertRaises(TypeError): result.request['private_unit'] = '00' * 32
        self.assertEqual((result.binding, result.runtime_authority, result.source_fact_authority), ('unbound', False, False))
        values = {k: getattr(result, k) for k, f in result.__dataclass_fields__.items() if f.init}
        with self.assertRaises(TypeError): S.Projection(**values, runtime_authority=True)

    def test_zero_quota_prevents_compiler_process(self):
        for dimension in ('max_work', 'max_edges', 'max_copied_bytes'):
            with self.subTest(dimension=dimension), patch.object(subprocess, 'Popen', side_effect=AssertionError('compiler started')):
                with self.assertRaises(self.modules[4].SourceDataError) as caught:
                    self.run_project(budget=self.budget(**{dimension: 0}))
                self.assertEqual(caught.exception.kind, 'resource')

    def test_actual_original_afterguard_and_source_mutation(self):
        Root = self.modules[0].RootContext; original = Root.prepare_source_data; observations = []
        def observe(owner, *, budget):
            stamp = original(owner, budget=budget)
            observations.append((owner, budget, stamp))
            return stamp
        with patch.object(Root, 'prepare_source_data', observe): self.run_project()
        self.assertGreaterEqual(len(observations), 2)
        self.assertTrue(all(x[0] is observations[0][0] and x[1] is observations[0][1] and
                            x[2] is observations[0][2] for x in observations))
        calls = []
        def mutate(owner, *, budget):
            calls.append(owner)
            if len(calls) == 2: owner.sections[10]['identity'] = '00' * 32
            return original(owner, budget=budget)
        with patch.object(Root, 'prepare_source_data', mutate), self.assertRaises(Exception) as caught:
            self.run_project()
        self.assertIn('context_snapshot_changed', str(caught.exception))

    def test_changed_schema_or_binary_is_refused(self):
        changed = self.output / 'schema.json'; changed.write_bytes(S.SCHEMA.read_bytes() + b' ')
        with patch.object(S, 'SCHEMA', changed), self.assertRaisesRegex(S.ProjectionError, 'SCHEMA'):
            self.run_project()
        with self.assertRaises((S.ProjectionError, OSError)):
            S.project(self.request, self.source, self.oracles['record'], Path('/usr/bin/true'), budget=self.budget())

    def test_conflicting_build_receipts_and_duplicate_paths_reject(self):
        record, sidecar = Path(self.oracles['record']), Path(self.oracles['sidecar'])
        original = json.loads((record.parent / 'build-receipt.json').read_text())
        side = json.loads((sidecar.parent / 'sidecar-build-receipt.json').read_text())
        shared = next(x for x in original['input_hashes'] if x['path'] in side['input_hashes'])
        directory = self.output / 'negative-receipt'
        directory.mkdir()
        binary = directory / 'record-input-witness'
        binary.symlink_to(record)
        for duplicate in (False, True):
            changed = deepcopy(original)
            if duplicate:
                changed['input_hashes'].append(deepcopy(shared))
            else:
                next(x for x in changed['input_hashes'] if x['path'] == shared['path'])['sha256'] = '00' * 32
            (directory / 'build-receipt.json').write_text(json.dumps(changed))
            with self.subTest(duplicate=duplicate), self.assertRaisesRegex(S.ProjectionError, 'E-SOURCE-PROJECTION-INPUT'):
                S.build_identity(binary, sidecar, self.budget())
        with self.assertRaisesRegex(S.ProjectionError, 'duplicate JSON key'):
            S.read_json('{"path":"first","path":"second"}')

    def test_actual_cli_normal_optimized_identical(self):
        commands = []
        for flags in ([], ['-O']):
            command = [sys.executable, '-B', *flags, str(S.TOOL / 'source_projection.py'), 'project',
                       '--request', str(FIXTURE / 'coordinates.json'), '--source', str(self.source),
                       '--record-oracle', self.oracles['record'], '--sidecar', self.oracles['sidecar']]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60,
                                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            commands.append(result.stdout)
        self.assertEqual(commands[0], commands[1])


    def test_main_buffer_header_counter_rejected_before_native(self):
        header = self.output / 'profile-input.hpp'
        source = self.output / 'profile-counter.cpp'
        original = S.run_tool
        calls = []
        def observe(*args, **kwargs):
            calls.append(args)
            return original(*args, **kwargs)
        for count in (4, 8):
            header.write_text('#define PORTABLE_N ' + str(count) + '\n')
            for prefix in ['#', '%:', '??=', '%\\\n:', '%\\ \n:', '%\\\t\r\n:']:
                source.write_text(prefix + 'include "' + str(header) + '"\n' +
                                  'struct HeaderRecord { int field[PORTABLE_N]; };\n')
                with self.subTest(count=count, prefix=prefix), patch.object(S, 'run_tool', observe):
                    with self.assertRaises(S.ProjectionError) as error:
                        self.run_project(source=source)
                    self.assertEqual((error.exception.code, error.exception.kind),
                                     ('E-SOURCE-PROJECTION-SOURCE-SCOPE', 'unavailable'))
        self.assertEqual(calls, [])

    def test_profile_precharge_uses_original_ledger_before_native(self):
        ledger = self.budget()
        budget_class = self.modules[4].SourceQueryBudget
        original_charge = budget_class.charge
        events = []
        def charge(current, **units):
            if current is ledger:
                events.append((current._used_work, current._used_copied_bytes, dict(units)))
            return original_charge(current, **units)
        with patch.object(budget_class, 'charge', charge):
            self.run_project(budget=ledger)
        size = len(self.source.read_bytes())
        matching = [event for event in events
                    if event[2] == dict(work=8 * size + 1, copied_bytes=256)]
        self.assertEqual(len(matching), 1)
        before, _, _ = matching[0]
        low = self.budget(max_work=before + 8 * size)
        original_tool = S.run_tool
        calls = []
        def observe(*args, **kwargs):
            calls.append(args)
            return original_tool(*args, **kwargs)
        with patch.object(S, 'run_tool', observe):
            with self.assertRaises(self.modules[4].SourceDataError) as error:
                self.run_project(budget=low)
        self.assertEqual(error.exception.kind, 'resource')
        self.assertEqual(low._used_work, before)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
