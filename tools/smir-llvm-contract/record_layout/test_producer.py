"""Actual AST-library witnesses; no skipped/mocked producer or native execution."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from builder import PIN, REPOSITORY, build, digest

FIXTURES = REPOSITORY / 'docs/specifications/smir/portable/conformance/llvm/record-layout'


class ActualSourceProducer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = Path(os.environ.get('SMIR_RECORD_WITNESS_DIR', '/tmp/rax-portable-smir-01/LLVM/record-layout-runs'))
        parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='ast-source-', dir=parent))
        cls.binary = build(Path(os.environ.get('LLVM_REFERENCE_CHECKOUT', '/Users/int/dev/llvm-project')),
                           cls.output / 'build')
        cls.binary_hash = digest(cls.binary)
        cls.results = []

    @classmethod
    def tearDownClass(cls):
        (cls.output / 'observations.json').write_text(json.dumps(cls.results, indent=2) + '\n')
        assert digest(cls.binary) == cls.binary_hash
        print('AST-only source producer artifacts retained:', cls.output)

    def run_source(self, path, unit, language='cpp23'):
        result = subprocess.run([str(self.binary), str(path), unit, language],
                                capture_output=True, text=True, timeout=30)
        observation = dict(path=str(path), source_sha256=digest(path), unit=unit,
                           language=language, exit=result.returncode, stderr=result.stderr)
        if result.stdout:
            observation['result'] = json.loads(result.stdout)
        self.results.append(observation)
        return result, observation.get('result')

    def records(self, report):
        types = {row['id']: row for row in report['types']}
        return {types[ref['id']]['record_name']: types[ref['id']]
                for ref in report['record_roots']}, types

    def test_function_pointer_source_production_needs_no_complete_call_signature(self):
        for suffix, complete in (('incomplete', False), ('complete', True)):
            result, report = self.run_source(
                FIXTURES / f'source-fnaddr-cross-tu-{suffix}.cpp', 'function_address_source')
            self.assertEqual(result.returncode, 0, result.stderr)
            types = {node['id']: node for node in report['types']}
            variables = {row['name']: types[row['type']['id']] for row in report['variable_type_roots']}
            pointer = variables['address']
            self.assertEqual(pointer['portable_pointer_kind'], 'code_address')
            self.assertEqual((pointer['native_size_bits'], pointer['native_align_bits']), (64, 64))
            self.assertNotIn('signature', pointer)
            prototype = types[pointer['pointee']['id']]
            self.assertEqual(prototype['kind'], 'function')
            self.assertEqual(len(prototype['params']), 1)
            self.assertEqual(types[prototype['result']['id']]['complete'], complete)
            self.assertEqual(types[prototype['params'][0]['id']]['complete'], complete)
            self.assertEqual(prototype['ref_qualifier'], 'none')
            self.assertFalse(prototype['noexcept'])
            declarations = {row['name']: row for row in report['function_declarations']}
            declaration = declarations['function']
            self.assertEqual(declaration['source_linkage'], 'cpp')
            declared_type = types[declaration['type']['id']]
            self.assertEqual(declared_type['params'], prototype['params'])
            self.assertEqual(declared_type['result'], prototype['result'])
            self.assertEqual(declared_type['exception_spec_state'], 'resolved')
            self.assertFalse(report['smir_emitted'])
            self.assertFalse(report['runtime_symbols_bound'])

    def test_source_function_noexcept_is_produced_from_actual_ast(self):
        result, report = self.run_source(FIXTURES / 'source-fnaddr-noexcept.cpp', 'noexcept_source')
        self.assertEqual(result.returncode, 0, result.stderr)
        types = {node['id']: node for node in report['types']}
        variables = {row['name']: types[row['type']['id']] for row in report['variable_type_roots']}
        weak, strong = (types[variables[name]['pointee']['id']] for name in ('weakened', 'exact'))
        self.assertFalse(weak['noexcept'])
        self.assertTrue(strong['noexcept'])
        self.assertEqual(weak['params'], strong['params'])
        self.assertEqual(weak['result'], strong['result'])
        self.assertTrue(all(value['portable_pointer_kind'] == 'code_address' for value in variables.values()))
        declarations = {row['name']: types[row['type']['id']] for row in report['function_declarations']}
        self.assertTrue(declarations['no_throw']['noexcept'])
        self.assertFalse(declarations['may_throw']['noexcept'])

    def test_actual_cpp_traits_and_numeric_member_alignment(self):
        result, report = self.run_source(FIXTURES / 'source-records.cpp', 'cpp_records')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(PIN, report['library_version'])
        self.assertFalse(report['backend_emission'])
        self.assertFalse(report['native_execution'])
        records, types = self.records(report)
        self.assertEqual(len(records), 19)
        plain = records['Plain']['record_input']['some']
        nonpod = records['NonPOD']['record_input']['some']
        self.assertTrue(plain['pod03'])
        self.assertFalse(nonpod['pod03'])
        self.assertTrue(plain['trivial'])
        self.assertFalse(nonpod['trivial'])
        field = records['AlignedMember']['record_input']['some']['fields'][1]
        self.assertEqual(field['explicit_align'], {'some': 16})
        self.assertEqual(records['NonPOD']['native_layout']['data_size'], 5)
        self.assertEqual(records['RepeatedEmpty']['native_layout']['data_size'], 1)
        self.assertEqual(records['RepeatedEmpty']['native_layout']['nonvirtual_size'], 2)
        for record in report['types']:
            if record['kind'] == 'record' and record['complete']:
                self.assertEqual(record['native_layout']['type']['id'], record['id'])

    def test_actual_owners_cv_empty_members_and_six_vptr_fields(self):
        result, report = self.run_source(FIXTURES / 'source-records.cpp', 'cpp_owner')
        self.assertEqual(result.returncode, 0, result.stderr)
        records, types = self.records(report)
        qualified = records['QualifiedEmpty']['record_input']['some']['fields']
        const_type = types[qualified[0]['type']['id']]
        mutable_type = types[qualified[1]['type']['id']]
        self.assertTrue(const_type['const'])
        self.assertFalse(mutable_type['const'])
        self.assertEqual(const_type['source_decl'], mutable_type['source_decl'])
        self.assertEqual(const_type['owner'], 'cpp_owner')
        virtual = records['VirtualOnly']['record_input']['some']
        self.assertTrue(virtual['dynamic'])
        self.assertFalse(virtual['polymorphic'])
        self.assertTrue(virtual['bases'][0]['virtual'])
        vptr = records['VirtualOnly']['native_layout']['vptrs'][0]
        self.assertTrue({'offset', 'offset_top', 'rtti', 'slots', 'vcall_offsets', 'vbase_offsets'} <= vptr.keys())
        self.assertEqual(vptr['offset'], 0)
        self.assertFalse(vptr['runtime_symbols_bound'])
        self.assertFalse(vptr['native_certificate'])
        self.assertEqual(vptr['rtti']['some']['namespace'], 'source-rtti-declaration')
        diamond = records['Diamond']['native_layout']
        self.assertEqual([base['offset'] for base in diamond['bases']], [0, 8, 0])
        self.assertEqual(len(diamond['vptrs']), 2)
        self.assertEqual([entry['offset_top'] for entry in diamond['vptrs']], [0, -8])
        self.assertTrue(all(entry['raw_components'] for entry in diamond['vptrs']))

    def test_actual_c23_anonymous_group_and_flexible_array(self):
        result, report = self.run_source(FIXTURES / 'source-records.c', 'c_records', 'c23')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report['language'], 'c23')
        records, types = self.records(report)
        anonymous = records['AnonymousC']['record_input']['some']['fields'][1]
        self.assertIsNone(anonymous['name'])
        self.assertTrue(anonymous['anonymous'])
        flexible = records['FlexibleC']
        input_field = flexible['record_input']['some']['fields'][-1]
        self.assertIsNone(types[input_field['type']['id']]['count'])
        self.assertEqual(input_field['explicit_align'], {'some': 16})
        self.assertEqual(flexible['native_layout']['fields'][-1]['width_bits'], 0)
        self.assertEqual(flexible['native_layout']['size'], 16)
        self.assertEqual(flexible['native_layout']['align'], 16)
        self.assertTrue(all(not flexible['record_input']['some'][name]
                            for name in ('pod03', 'trivial', 'standard_layout', 'polymorphic', 'dynamic', 'empty')))

    def test_full_apint_width_guard_rejects_without_bad_layout_output(self):
        source = self.output / 'wide.cpp'
        source.write_text('struct Limit { unsigned char field:4294967296ULL; };\n')
        result, report = self.run_source(source, 'wide_guard')
        self.assertEqual(result.returncode, 1)
        self.assertIn('E-SMIR-UPSTREAM-BITFIELD-WIDTH', result.stderr)
        self.assertIsNone(report)

    def test_excluded_source_layout_attributes_are_explicit_errors(self):
        source = self.output / 'packed.cpp'
        source.write_text('struct __attribute__((packed)) Packed { char c; int value; };\n')
        result, report = self.run_source(source, 'packed_guard')
        self.assertEqual(result.returncode, 1)
        self.assertIn('E-WITNESS-EXCLUDED-LAYOUT-ATTRIBUTE', result.stderr)
        self.assertIsNone(report)

    def test_logical_owner_is_explicit_and_syntax_is_not_an_identity_certificate(self):
        source = FIXTURES / 'source-records.cpp'
        first, a = self.run_source(source, 'owner_a')
        second, b = self.run_source(source, 'owner_b')
        self.assertEqual((first.returncode, second.returncode), (0, 0))
        self.assertNotEqual(a['source_owner'], b['source_owner'])
        self.assertTrue(all(node['owner'] == 'owner_a' for node in a['types']))
        self.assertTrue(all(node['owner'] == 'owner_b' for node in b['types']))
        self.assertFalse(a['runtime_symbols_bound'])
        self.assertFalse(a['portable_layout_certified'])

    def test_recursive_graph_and_distinct_qualified_declarations(self):
        source = self.output / 'recursive.cpp'
        source.write_text('struct Forward; enum class E: unsigned short;\n'
                          'namespace A { struct R { R *next; Forward *opaque; E value; }; }\n'
                          'namespace B { struct R { A::R *other; }; }\n')
        result, report = self.run_source(source, 'recursive_owner')
        self.assertEqual(result.returncode, 0, result.stderr)
        records, types = self.records(report)
        self.assertEqual(set(records), {'A::R', 'B::R'})
        a, b = records['A::R'], records['B::R']
        self.assertNotEqual(a['source_decl'], b['source_decl'])
        fields = a['record_input']['some']['fields']
        self.assertEqual(types[fields[0]['type']['id']]['pointee']['id'], a['id'])
        pointer = types[fields[1]['type']['id']]
        incomplete = types[pointer['pointee']['id']]
        self.assertFalse(incomplete['complete'])
        self.assertIsNone(incomplete['record_input'])
        enumeration = types[fields[2]['type']['id']]
        self.assertEqual(types[enumeration['underlying']['id']]['value_bits'], 16)

    def test_dependent_record_is_rejected_before_native_layout(self):
        source = self.output / 'dependent.cpp'
        source.write_text('template<class T> struct Dependent { T value; };\n')
        result, report = self.run_source(source, 'dependent_guard')
        self.assertEqual(result.returncode, 1)
        self.assertIn('E-WITNESS-DEPENDENT-RECORD', result.stderr)
        self.assertIsNone(report)

    def test_lambda_capture_field_uses_accepted_declaration_order_normalization(self):
        source = self.output / 'capture.cpp'
        source.write_text('void f() { int x = 7; auto lambda = [x] { return x; };\n'
                          'struct Holder { decltype(lambda) value; }; }\n')
        result, report = self.run_source(source, 'capture_guard')
        self.assertEqual(result.returncode, 0, result.stderr)
        closures = [node for node in report['types'] if node.get('is_lambda')]
        self.assertEqual(len(closures), 1)
        field = closures[0]['record_input']['some']['fields'][0]
        self.assertEqual(field['name'], {'some': '$capture0'})
        self.assertFalse(field['anonymous'])
        self.assertIsNone(field['bit_width'])
        self.assertEqual(field['access'], 'private')
        self.assertEqual(closures[0]['native_layout']['fields'][0]['name'], '$capture0')

    def test_actual_capture_families_preserve_types_owners_and_selected_names(self):
        result, report = self.run_source(FIXTURES / 'source-captures.cpp', 'capture_families')
        self.assertEqual(result.returncode, 0, result.stderr)
        records, types = self.records(report)
        expected = {'ValueHolder': ['scalar', 'scalar'], 'ReferenceHolder': ['reference'],
                    'ArrayHolder': ['array'], 'InitHolder': ['scalar'],
                    'EmptyHolder': [], 'ThisHolder': ['record']}
        # Local-class qualified spellings may contain their function context.
        for name, kinds in expected.items():
            holder = next(node for key, node in records.items() if key.split('::')[-1] == name)
            closure = types[holder['record_input']['some']['fields'][0]['type']['id']]
            self.assertTrue(closure['is_lambda'])
            fields = closure['record_input']['some']['fields']
            self.assertEqual([types[field['type']['id']]['kind'] for field in fields], kinds)
            self.assertEqual([field['name'] for field in fields],
                             [{'some': f'$capture{index}'} for index in range(len(fields))])
            for index, field in enumerate(fields):
                selected = closure['native_layout']['fields'][index]
                self.assertEqual(selected['declaration_index'], index)
                self.assertEqual(selected['name'], field['name']['some'])
                self.assertEqual(selected['type'], field['type'])
                self.assertEqual(types[field['type']['id']]['owner'], 'capture_families')

    def test_capture_metadata_names_do_not_depend_on_source_variable_spelling(self):
        reports = []
        for name in ('x', 'different_name'):
            source = self.output / f'capture-name-{name}.cpp'
            source.write_text(f'void f() {{ int {name}=1; auto lambda=[{name}] {{}}; '
                              'struct Holder { decltype(lambda) value; }; }\n')
            result, report = self.run_source(source, 'renamed_capture')
            self.assertEqual(result.returncode, 0, result.stderr)
            closure = next(node for node in report['types'] if node.get('is_lambda'))
            reports.append(closure['record_input'])
        self.assertEqual(reports[0], reports[1])

    def test_source_capture_prefix_identifier_collision_is_explicit_error(self):
        source = self.output / 'capture-prefix.cpp'
        source.write_text('#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"\n'
                          'struct Collision { int $capture0; };\n')
        result, report = self.run_source(source, 'capture_prefix')
        self.assertEqual(result.returncode, 1)
        self.assertIn('E-SMIR-RESERVED-METADATA-NAME', result.stderr)
        self.assertIsNone(report)

    def test_capture_reordering_changes_ordered_type_graph(self):
        observed = []
        for index, order in enumerate(('first, second', 'second, first')):
            source = self.output / f'capture-order-{index}.cpp'
            source.write_text('void f() { int first=1; long second=2; auto lambda=[' + order +
                              '] {}; struct Holder { decltype(lambda) value; }; }\n')
            result, report = self.run_source(source, 'ordered_capture')
            self.assertEqual(result.returncode, 0, result.stderr)
            types = {node['id']: node for node in report['types']}
            closure = next(node for node in report['types'] if node.get('is_lambda'))
            fields = closure['record_input']['some']['fields']
            self.assertEqual([field['name']['some'] for field in fields], ['$capture0', '$capture1'])
            observed.append([types[field['type']['id']]['value_bits'] for field in fields])
        self.assertEqual(observed, [[32, 64], [64, 32]])

    def test_draft_helper_state_source_wrappers_adjust_to_pointer_parameters(self):
        for language, suffix in (('c23', 'c'), ('cpp23', 'cpp')):
            with self.subTest(language=language):
                result, report = self.run_source(FIXTURES / f'source-helper-states.{suffix}',
                                                 'draft_helper_state', language)
                self.assertEqual(result.returncode, 0, result.stderr)
                records, types = self.records(report)
                for name in ('VaState', 'JumpState'):
                    self.assertEqual(records[name]['native_layout']['size'], 32)
                    self.assertEqual(records[name]['native_layout']['align'], 8)
                self.assertEqual([field['offset_bits'] for field in
                                  records['JumpState']['native_layout']['fields']], [0, 32, 64, 128, 192])
                wrappers = records['SourceWrappers']['record_input']['some']['fields']
                adjusted = records['AdjustedParameters']['record_input']['some']['fields']
                for wrapper_field, function_field in zip(wrappers, adjusted):
                    array = types[wrapper_field['type']['id']]
                    self.assertEqual((array['kind'], array['count']), ('array', 1))
                    function_pointer = types[function_field['type']['id']]
                    function = types[function_pointer['pointee']['id']]
                    parameter = types[function['params'][0]['id']]
                    self.assertEqual(parameter['kind'], 'pointer')
                    self.assertEqual(parameter['pointee'], array['element'])
                # Actual native C++ AST traits are not false C23 sentinels.
                self.assertEqual(records['VaState']['record_input']['some']['pod03'], language == 'cpp23')

    def test_stored_reference_extent_is_distinct_from_referent_size(self):
        result, report = self.run_source(FIXTURES / 'source-helper-states.cpp', 'reference_storage')
        self.assertEqual(result.returncode, 0, result.stderr)
        records, types = self.records(report)
        record = records['StoredReference']
        reference = types[record['record_input']['some']['fields'][0]['type']['id']]
        referent = types[reference['pointee']['id']]
        self.assertEqual(reference['kind'], 'reference')
        self.assertEqual(reference['reference_category'], 'lvalue')
        self.assertEqual(referent['value_bits'], 32)
        self.assertEqual(record['native_layout']['size'], 8)
        self.assertEqual(record['native_layout']['fields'][0]['width_bits'], 64)

    def test_c23_bitint_default_promotions_keep_declared_precision_and_signedness(self):
        result, report = self.run_source(FIXTURES / 'source-promotions.c', 'bitint_promotions', 'c23')
        self.assertEqual(result.returncode, 0, result.stderr)
        types = {node['id']: node for node in report['types']}
        call = next(call for call in report['calls'] if call['callee'] == 'sink')
        arguments = [types[ref['id']] for ref in call['arguments_after_sema']]
        self.assertEqual([node['value_bits'] for node in arguments], [32, 7, 3, 65, 7, 3, 32])
        self.assertEqual([node['signed'] for node in arguments], [True, True, False, True, True, False, True])
        self.assertEqual([node['integer_family'] for node in arguments],
                         ['builtin', 'bitint', 'bitint', 'bitint', 'bitint', 'bitint', 'builtin'])

    def test_bitint_is_diagnosed_as_extension_in_default_cpp23_witness_mode(self):
        result, report = self.run_source(FIXTURES / 'source-promotions.c', 'cpp_extension_guard', 'cpp23')
        self.assertEqual(result.returncode, 1)
        self.assertIn('extension', result.stderr)
        self.assertIsNone(report)

    def test_actual_cpp_throw_normalization_and_void_function_pointer_exceptions(self):
        result, report = self.run_source(FIXTURES / 'source-throws.cpp', 'throw_normalization')
        self.assertEqual(result.returncode, 0, result.stderr)
        types = {node['id']: node for node in report['types']}
        payloads = [types[row['normalized_payload_type']['some']['id']] for row in report['throws']]
        self.assertEqual([node['kind'] for node in payloads], ['scalar', 'pointer', 'pointer', 'pointer'])
        self.assertFalse(payloads[0]['const'])
        self.assertEqual(payloads[0]['value_bits'], 32)
        self.assertEqual(types[payloads[1]['pointee']['id']]['kind'], 'scalar')
        self.assertEqual(types[payloads[2]['pointee']['id']]['kind'], 'function')
        void = types[payloads[3]['pointee']['id']]
        self.assertEqual(void['kind'], 'void')
        self.assertTrue(void['const'])

    def test_source_throw_of_incomplete_pointee_rejects_before_witness(self):
        source = self.output / 'throw-incomplete.cpp'
        source.write_text('struct Forward; void f(Forward *pointer) { throw pointer; }\n')
        result, report = self.run_source(source, 'throw_incomplete')
        self.assertEqual(result.returncode, 1)
        self.assertIn('incomplete type', result.stderr)
        self.assertIsNone(report)

    def test_covariant_pointer_reference_and_destructor_thunks_are_distinct(self):
        result, report = self.run_source(FIXTURES / 'source-covariant-thunks.cpp', 'covariant_thunks')
        self.assertEqual(result.returncode, 0, result.stderr)
        records, _ = self.records(report)
        secondary = next(row for row in records['Derived']['native_layout']['vptrs'] if row['offset'] == 8)
        thunks = secondary['raw_thunks']
        pointer = next(row for row in thunks if row['return_policy'] == 'nullable_pointer')
        reference = next(row for row in thunks if row['return_policy'] == 'reference')
        for thunk in (pointer, reference):
            self.assertEqual(thunk['this_nonvirtual_bytes'], -8)
            self.assertEqual(thunk['return_nonvirtual_bytes'], 8)
            self.assertFalse(thunk['runtime_thunk_bound'])
            self.assertFalse(thunk['body_materialized'])
        kinds = [row['kind'] for row in secondary['raw_components']]
        self.assertIn('complete-destructor', kinds)
        self.assertIn('deleting-destructor', kinds)
        methods = {row['id']: row for row in report['method_declarations']}
        self.assertTrue(methods[pointer['source_target']['id']]['overrides'])

    def test_construction_phase_vbase_offsets_rtti_and_vtt_use_actual_group(self):
        result, report = self.run_source(FIXTURES / 'source-construction-vtt.cpp', 'construction_vtt')
        self.assertEqual(result.returncode, 0, result.stderr)
        records, types = self.records(report)
        definition = records['C']['construction']
        self.assertFalse(definition['runtime_binding'])
        self.assertFalse(definition['source_path_bound'])
        groups = definition['groups']
        self.assertEqual([row['kind'] for row in groups], ['complete', 'construction'])
        self.assertEqual([types[row['current_type']['id']]['record_name'] for row in groups], ['C', 'A'])
        self.assertEqual([row['subobject_offset'] for row in groups], [0, 16])
        self.assertEqual([row['group_index'] for row in definition['entries']], [0, 1, 1, 0, 0])
        self.assertEqual([row['storage_offset'] for row in definition['entries']], [0, 16, 40, 16, 40])
        ordinary_a = records['A']['native_layout']['vptrs'][0]['vbase_offsets']
        constructing_a = [row['value'] for row in groups[1]['raw_components'] if row['kind'] == 'vbase']
        self.assertEqual(ordinary_a, [16])
        self.assertEqual(constructing_a, [24])
        for group in groups:
            rtti = [types[row['source_type']['id']]['record_name'] for row in group['raw_components']
                    if row['kind'] == 'rtti']
            self.assertTrue(rtti)
            self.assertEqual(set(rtti), {types[group['current_type']['id']]['record_name']})

    def test_unused_null_slot_is_distinct_from_callable_secondary_entry(self):
        result, report = self.run_source(FIXTURES / 'source-unused-slot.cpp', 'unused_vtable_slot')
        self.assertEqual(result.returncode, 0, result.stderr)
        records, _ = self.records(report)
        vptrs = records['D']['native_layout']['vptrs']
        primary = next(row for row in vptrs if row['offset'] == 0)
        secondary = next(row for row in vptrs if row['offset'] == 8)
        self.assertEqual(primary['raw_components'][-1]['kind'], 'unused')
        self.assertEqual(secondary['raw_components'][-1]['kind'], 'function')
        self.assertEqual(primary['slots'][0]['variant'], 'unused')
        self.assertFalse(primary['runtime_symbols_bound'])

    def test_unissued_methods_explicit_object_and_three_ref_qualifier_states(self):
        result, report = self.run_source(FIXTURES / 'source-method-views.cpp', 'method_views')
        self.assertEqual(result.returncode, 0, result.stderr)
        methods = {row['name']: row for row in report['declared_method_observations']}
        self.assertEqual([methods[f'MethodViews::{name}']['ref_qualifier']
                          for name in ('ordinary', 'lvalue', 'rvalue')], ['none', 'lvalue', 'rvalue'])
        explicit = methods['MethodViews::explicit_object']
        self.assertTrue(explicit['explicit_object'])
        self.assertFalse(explicit['implicit_this'])
        self.assertFalse(explicit['static'])
        self.assertTrue(methods['MethodViews::static_like']['static'])
        self.assertFalse(methods['MethodViews::static_like']['implicit_this'])
        self.assertTrue(methods['MethodViews::undecided']['undeduced_return'])
        self.assertGreater(report['unissued_call_observations'], 0)

    def test_primary_shared_vtable_negative_component_kinds_interleave(self):
        result, report = self.run_source(FIXTURES / 'source-vtable-components.cpp', 'vtable_order')
        self.assertEqual(result.returncode, 0, result.stderr)
        records, _ = self.records(report)
        primary = records['C']['native_layout']['vptrs'][0]
        offsets = [row for row in primary['raw_components']
                   if row['kind'] in {'vcall_offset', 'vbase_offset'}]
        self.assertEqual([row['kind'] for row in offsets],
                         ['vbase_offset', 'vbase_offset', 'vcall_offset', 'vbase_offset', 'vcall_offset'])
        self.assertEqual([row['address_relative_bytes'] for row in offsets], [-56, -48, -40, -32, -24])
        self.assertEqual(primary['vbase_offsets'], [8, 0, 0])
        self.assertEqual(primary['vcall_offsets'], [0, 0])
        self.assertEqual(primary['component_order'], ['vbase', 'vbase', 'vcall', 'vbase', 'vcall'])
        length = len(primary['component_order'])
        self.assertEqual([row['address_relative_bytes'] for row in offsets],
                         [-8 * (2 + length - index) for index in range(length)])
        for target in primary['vbase_slot_targets']:
            self.assertEqual(target['component_value'], target['target_offset'] - target['receiver_offset'])
        targets = {(report['types'][row['receiver_source_type']['id']]['record_name'],
                    report['types'][row['target_source_type']['id']]['record_name']): row['slot_bytes']
                   for row in primary['vbase_slot_targets']}
        self.assertEqual({key: targets[key] for key in (('C', 'A'), ('C', 'V'), ('C', 'W'))},
                         {('C', 'A'): -48, ('C', 'V'): -32, ('C', 'W'): -56})

    def test_pinned_struct_extent_gap_is_separate_from_format_array_limit(self):
        for extent, accepted in ((2**60 - 1, True), (2**60, False), (2**61 - 1, False)):
            with self.subTest(extent_bytes=extent):
                source = self.output / f'extent-{extent}.c'
                source.write_text(f'struct Extent {{ char bytes[{extent}ULL]; }};\n')
                result, report = self.run_source(source, 'extent_gap', 'c23')
                self.assertEqual(result.returncode, 0 if accepted else 1)
                if accepted:
                    records, _ = self.records(report)
                    self.assertEqual(records['Extent']['native_layout']['size'], extent)
                else:
                    self.assertIn('is too large', result.stderr)
                    self.assertIsNone(report)


if __name__ == '__main__':
    unittest.main()
