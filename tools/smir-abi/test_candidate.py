"""Full ordered ABI contract, nominal/call/journal/native/fenv conformance."""

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import threading
import unittest

from candidate import verify
from candidate_codec import MAX_BYTES, MAX_COUNT, MAX_DEPTH, MAX_NODES, RECORDS, decode, encode
from candidate_fixtures import build, context, field, declared_field, plain_cpp_record, seal, slot, step, native_profile
from construction import ConstructionJournal, ExceptionLease, verify_program
from fenv_contract import ALL, DEFAULT_ENV, DEFAULT_MODE, ENV, FE, MODE, ROUND, Environment, FEnvTrap
from layout import ABIError
from native_contract import catch_relation, verify_adapter, verify_captures
from nominal import NominalGraph, option, ref, some, unit_identity
from site_config import MACROS, header, identity, site_record
from witness import TARGETS, compiler
from execution_shapes import ExecutionShapes
from namespaces import Entities
from c_interop_fixtures import build_pair
from object_lifetimes import CompletedObjects

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'docs/specifications/smir/portable/conformance/abi/candidate'


def tables(document):
    return {name: {item['id']: item for item in document[name]} for name in
            ('signatures', 'domains', 'recipes', 'personalities', 'unwind', 'catches', 'bridges', 'journals')}


def codec_oracle():
    path = ROOT / 'tools/smir-format/codec.py'
    spec = importlib.util.spec_from_file_location('smir_abi_independent_root_codec', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.RecordCodec(RECORDS, module.RecordLimits(max_bytes=MAX_BYTES, max_depth=MAX_DEPTH,
        max_nodes=MAX_NODES, max_list=MAX_COUNT, max_string=MAX_BYTES))


class CandidateCodecTests(unittest.TestCase):
    def test_selected_owner_proxy_layout_on_six_targets(self):
        clang, _ = compiler()
        for target in TARGETS:
            result = subprocess.run([clang, '-target', target, '-std=c++23', '-ffreestanding',
                '-nostdinc', '-fsyntax-only', str(FIXTURES / 'owner-proxy-layout.cpp')],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, (target, result.stderr))

    def test_pinned_source_object_extent_boundary_on_six_targets(self):
        clang, _ = compiler()
        for target in TARGETS:
            for extent, accepted in (((1 << 61) - 1, True), (1 << 61, False), ((1 << 61) + 1, False)):
                command = [clang, '-target', target, '-std=c23', '-ffreestanding', '-nostdinc',
                           '-fsyntax-only', '-DOBJECT_EXTENT=' + str(extent) + 'ULL',
                           str(FIXTURES / 'max-object.c')]
                result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode == 0, accepted, (target, extent, result.stderr))
                if not accepted:
                    self.assertIn('array is too large', result.stderr)

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='abi-candidate-', dir=os.environ.get('SMIR_ABI_TMP'))
        cls.addClassCleanup(cls.directory.cleanup)
        cls.path = Path(cls.directory.name)
        cls.cxx = os.environ.get('CXX', '/usr/bin/clang++' if sys.platform == 'darwin' else 'clang++')
        cls.probe = cls.path / 'wire-probe'
        cls.native = cls.path / 'native-witness'
        for source, output, standard, extra in [
                ('candidate_probe.cpp', cls.probe, 'c++20', []),
                ('candidate_native_witness.cpp', cls.native, 'c++23', ['-fno-elide-constructors', '-pthread'])]:
            subprocess.run([cls.cxx, '-std=' + standard, '-Wall', '-Wextra', '-Werror', *extra,
                            str(ROOT / 'tools/smir-abi' / source), '-o', str(output)], check=True,
                           capture_output=True, text=True)
        cls.oracle = codec_oracle()

    def compare(self, cases):
        source = ''.join(kind + ' ' + payload.hex() + '\n' for kind, payload in cases)
        result = subprocess.run([str(self.probe)], input=source, capture_output=True, text=True,
                                check=True, timeout=20)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(cases))
        for (kind, payload), line in zip(cases, lines):
            cpp = json.loads(line)
            try:
                value = decode(kind, payload)
                accepted = True
            except ABIError:
                accepted = False
            self.assertEqual(cpp['ok'], accepted, (kind, payload.hex()[:128]))
            try:
                independent = self.oracle.decode(kind, payload)
                other_accepted = True
            except ValueError:
                other_accepted = False
            self.assertEqual(other_accepted, accepted, (kind, payload.hex()[:128]))
            if accepted:
                expected = value.hex() if isinstance(value, bytes) else value
                self.assertEqual(json.dumps(cpp['value'], sort_keys=True), json.dumps(expected, sort_keys=True))
                self.assertEqual(independent, value)
                self.assertEqual(self.oracle.encode(kind, value), payload)
                self.assertEqual(encode(kind, value), payload)

    def test_full_candidate_and_live_journal_wire(self):
        document, evidence = build()
        self.assertEqual(json.loads((FIXTURES / 'complete.json').read_text()), document)
        self.assertEqual(json.loads((FIXTURES / 'evidence.json').read_text()), evidence)
        self.compare([('abi_contract', encode('abi_contract', document))])
        journal = {'revision': 1, 'instance': 5, 'program': ref(0), 'parent_instance': None, 'transition': 1, 'thread': 2,
                   'activation': 3, 'generation': 4, 'stage': 'unwinding', 'next_ordinal': 9,
                   'entries': [{'instance': 5, 'transition': 1, 'thread': 2, 'activation': 3, 'generation': 4,
                                'slot': 0, 'element': 2, 'ticket': 8, 'phase': 'construct_commit',
                                'ordinal': 9, 'owner': 0, 'exception_lease': some(17)}],
                   'exception_lease': some(17)}
        self.compare([('cleanup_state', encode('cleanup_state', journal))])

    def test_common_primitive_boundaries_and_some(self):
        cases = []
        for bits in (8, 16, 32, 64):
            for value in (0, 1, (1 << bits) - 1):
                cases.append(('u' + str(bits), encode('u' + str(bits), value)))
            for value in (-(1 << (bits - 1)), -1, 0, (1 << (bits - 1)) - 1):
                cases.append(('i' + str(bits), encode('i' + str(bits), value)))
        for kind, values in [('bool', [True, False]), ('opt:opt:u64', [None, some(None), some(some((1 << 64) - 1))]),
                             ('utf8', ['', 'x\0y', '\U0010ffff', '\u0080\u07ff\u0800\uffff']),
                             ('token', ['a', 'z' + '9_' * 31]), ('digest32', ['00' * 32, 'ff' * 32]),
                             ('hex', ['', '0080ff']), ('bytes', [b'', b'\0\xff'])]:
            cases += [(kind, encode(kind, value)) for value in values]
        self.compare(cases)

    def test_noncanonical_primitives_and_truncation(self):
        cases = [('bool', b'\2'), ('opt:u8', b'\2'), ('vec:u8', (MAX_COUNT + 1).to_bytes(4, 'little')),
                 ('token', b'\0'), ('token', b'\1A'), ('token', b'\x40' + b'a' * 64)]
        for raw in [b'\xc0\x80', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\x80', b'\xe0\x80\x80']:
            cases.append(('utf8', len(raw).to_bytes(4, 'little') + raw))
        for kind, value in [('qref', ref(123, 7)), ('adjustment', {'kind': 'virtual', 'vptr_offset': 8, 'slot_bytes': -24, 'addend': 3})]:
            payload = encode(kind, value)
            cases += [(kind, payload[:index]) for index in range(len(payload))]
            cases.append((kind, payload + b'\0'))
        self.compare(cases)

    def test_seeded_full_payload_corruption_acceptance_parity(self):
        document, _ = build()
        payload = encode('abi_contract', document)
        rng = random.Random(0x41424902)
        cases = [('abi_contract', payload[:end]) for end in range(0, len(payload), max(1, len(payload) // 128))]
        for _ in range(256):
            changed = bytearray(payload)
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
            cases.append(('abi_contract', bytes(changed)))
        self.compare(cases)

    def test_native_cpp_cleanup_catch_exception_ptr_and_flag(self):
        result = subprocess.run([str(self.native)], capture_output=True, text=True, timeout=15, check=True)
        self.assertEqual(result.stdout.strip(),
                         'trace=ABa catches=5 exception_ptr=3 flag_iterations=100000 flag_size=1')
        result = subprocess.run([str(self.native), 'catch_copy'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 73)
        self.assertEqual(result.stdout.strip(), 'catch-copy-terminate')
        result=subprocess.run([str(self.native),'object_lifetimes'],capture_output=True,text=True,timeout=10,check=True)
        self.assertEqual(result.stdout.strip(),'object_threads=1 placement=42 ended_member=1')

    def test_actual_pinned_library_site_header_configuration(self):
        clang, version = compiler()
        directory = self.path / 'site'
        directory.mkdir(exist_ok=True)
        (directory / '__config_site').write_text(header())
        source = directory / 'site.cpp'
        source.write_text('''#include <__configuration/abi.h>
#if !_LIBCPP_ABI_FORCE_ITANIUM || _LIBCPP_ABI_FORCE_MICROSOFT
#error wrong_abi
#endif
#if _LIBCPP_ABI_VERSION != 1 || !_LIBCPP_HAS_THREADS || !_LIBCPP_HAS_THREAD_API_EXTERNAL
#error wrong_site
#endif
#ifdef _LIBCPP_ABI_ALTERNATE_STRING_LAYOUT
#error host_layout_leak
#endif
static_assert(sizeof(long)==8 && sizeof(void*)==8);
''')
        result = subprocess.run([clang, '-target', 'x86_64-unknown-linux-gnu', '-std=c++23',
                                 '-ffreestanding', '-nostdinc', '-I', str(directory),
                                 '-I', '/Users/int/dev/llvm-project/libcxx/include',
                                 '-fsyntax-only', str(source)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_fenv_objects_layout_and_readonly_symbols_on_six_targets(self):
        clang, _ = compiler()
        for index, target in enumerate(TARGETS):
            output=self.path/f'fenv-{index}.ll'
            result=subprocess.run([clang,'-target',target,'-std=c++23','-ffreestanding','-nostdinc',
                '-S','-emit-llvm',str(FIXTURES/'env-layout.cpp'),'-o',str(output)],
                capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            ir=output.read_text()
            self.assertRegex(ir,r'@__rax_default_fenv = .*constant .*i32 1, i32 0, i32 0, i32 0, i64 0, i64 0')
            self.assertRegex(ir,r'@__rax_default_femode = .*constant .*zeroinitializer')
            self.assertIn('ret ptr @__rax_default_fenv',ir)


class CandidateVerificationTests(unittest.TestCase):
    def test_portable_unwind_descriptor_rejected_before_native_lookup(self):
        fixture = json.loads((FIXTURES / 'reject-portable-native-cfi.json').read_text())
        document, evidence = fixture['abi'], fixture['evidence']
        # A logical personality is a typed portable declaration; it does not
        # require a native-CFI table or a portable pseudo-register namespace.
        positive = deepcopy(document)
        positive['unwind'] = []
        self.assertFalse(verify(positive, context(positive, evidence))['admitted_for_execution'])

        formats = ('logical', 'dwarf_cfi_lsda', 'darwin_compact_dwarf',
                   'windows_x64_unwind', 'windows_arm64_unwind')
        for profile in ('aarch64_looking', 'x86_64_looking'):
            for source_format in formats:
                with self.subTest(profile=profile, source_format=source_format):
                    bad = deepcopy(document)
                    unwind = bad['unwind'][0]
                    unwind['source_format'] = source_format
                    unwind['code_size'] = 0
                    unwind['function'] = ref(502)  # Deliberately unavailable.
                    if profile == 'x86_64_looking':
                        row = unwind['rows'][0]
                        row['cfa'].update(reg=7)
                        row['return_rule'] = {'kind': 'register', 'reg': 16}
                        row['registers'] = [{'reg': 32, 'rule': {'kind': 'cfa_offset', 'offset': -32, 'width': 16}}]
                    checked = context(bad, evidence)
                    original_symbol = checked.symbol
                    def symbol(reference):
                        if reference['id'] == 502:
                            raise AssertionError('portable CFI reached native code-size lookup')
                        return original_symbol(reference)
                    checked.symbol = symbol
                    def forbidden_metadata(_):
                        raise AssertionError('portable CFI reached metadata lookup')
                    checked.metadata = forbidden_metadata
                    checked.native_unwind = forbidden_metadata
                    with self.assertRaisesRegex(ABIError, '^ABI_CC_CFI_PROFILE$'):
                        verify(bad, checked)

    def test_call_plan_mismatches_between_independently_valid_roots(self):
        a, evidence = build()
        verify(a, context(a, evidence))
        for change in ('this', 'vtt', 'return_noundef'):
            b, facts = deepcopy(a), deepcopy(evidence)
            identifier = 2
            if change == 'this':
                b['signatures'][2]['this_type'] = some(ref(6))
                b['signatures'][2]['lowered_params'][0].update(source_type=ref(6), value_type=ref(6))
            elif change == 'vtt':
                b['signatures'][2]['vtt'] = False
                b['signatures'][2]['lowered_params'].pop(1)
                shape = next(item for item in facts['execution_graph'] if item['id'] == 14)
                shape['params'].pop(1)
                shape['param_noundef'].pop(1)
            else:
                identifier = 0
                b['signatures'][0]['return_noundef'] = False
                next(item for item in facts['execution_graph'] if item['id'] == 12)['result_noundef'] = [False]
            verify(b, context(b, facts))
            graph = NominalGraph(a, 'a', {'b': b})
            self.assertFalse(graph.signature_compatible(ref(identifier), ref(identifier), 'a', 'b'), change)

    def test_reference_category_and_function_ref_qualification(self):
        a, evidence = build(all_kinds=True)
        verify(a, context(a, evidence))
        identifier = next(item['id'] for item in a['types'] if item['kind'] == 'reference')
        b = deepcopy(a)
        b['types'][identifier]['flags'].remove('lvalue_ref')
        b['types'][identifier]['flags'].append('rvalue_ref')
        seal(b)
        verify(b, context(b, evidence))
        self.assertFalse(NominalGraph(a, 'a', {'b': b}).compatible(ref(identifier), ref(identifier), 'a', 'b'))
        for flags in [[], ['lvalue_ref', 'rvalue_ref']]:
            bad = deepcopy(a)
            bad['types'][identifier]['flags'] = ['complete', 'trivial_copy', 'trivial_destroy'] + flags
            seal(bad)
            with self.assertRaisesRegex(ABIError, 'ABI_CC_REFERENCE_CATEGORY'):
                verify(bad, context(bad, evidence))
        b = deepcopy(a)
        b['types'][14]['flags'].append('lvalue_ref')
        seal(b)
        verify(b, context(b, evidence))
        self.assertFalse(NominalGraph(a, 'a', {'b': b}).compatible(ref(14), ref(14), 'a', 'b'))
        b = deepcopy(a)
        b['types'][12]['flags'].append('lvalue_ref')
        seal(b)
        with self.assertRaisesRegex(ABIError, 'ABI_CC_REF_QUALIFIED_THIS'):
            verify(b, context(b, evidence))

    def test_source_allocation_binding_has_no_logical_value_mask(self):
        document, evidence = build()
        binding = deepcopy(document['storage_bindings'][1])
        binding.update(kind='allocation', fragments=[{'source_path': [], 'source_offset_bits': 0,
            'execution_offset_bits': 0, 'width_bits': 64, 'role': 'object_representation'}])
        document['storage_bindings'][1] = binding
        verify(document, context(document, evidence))
        for change, code in [
            (lambda b: b.update(view_width_bits=32), 'ABI_CC_STORAGE_ALLOCATION'),
            (lambda b: b['fragments'][0].update(role='value'), 'ABI_CC_STORAGE_ALLOCATION_FRAGMENT'),
        ]:
            bad = deepcopy(document)
            change(bad['storage_bindings'][1])
            with self.assertRaisesRegex(ABIError, code):
                verify(bad, context(bad, evidence))

    def test_multiple_foreign_builds_and_exact_GNU_SEH_profiles(self):
        for isa in ('x86_64', 'aarch64'):
            for abi in ('itanium', 'microsoft'):
                document, evidence = native_profile(isa=isa, abi=abi)
                verify(document, context(document, evidence))
                other = deepcopy(document['domains'][1])
                other.update(id=2, build='a'*64)
                document['domains'].append(other)
                evidence['native_domains']['2'] = deepcopy(other)
                verify(document, context(document, evidence))
                bad = deepcopy(document)
                bad['bridges'][0].update(source=1, target=2)
                with self.assertRaisesRegex(ABIError, 'ABI_CC_FOREIGN_BRIDGE_REQUIRES_PORTABLE'):
                    verify(bad, context(bad, evidence))
                bad = deepcopy(document)
                bad['domains'][2]['isa'] = 'aarch64' if isa == 'x86_64' else 'x86_64'
                with self.assertRaisesRegex(ABIError, 'ABI_CC_FOREIGN_ISA_SELECTION'):
                    verify(bad, context(bad, evidence))
                bad = deepcopy(document)
                bad['personalities'][0]['flags'].remove('cross_domain_translation')
                changed = deepcopy(evidence)
                changed['native_personalities']['0'] = deepcopy(bad['personalities'][0])
                with self.assertRaisesRegex(ABIError, 'ABI_CC_EXCEPTION_TRANSLATION'):
                    verify(bad, context(bad, changed))

    def test_caught_RTTI_normalization_and_source_identity(self):
        a, evidence = build(all_kinds=True)
        b = deepcopy(a)
        graph = NominalGraph(a, 'a', {'b': b})
        self.assertTrue(graph.catch_compatible(ref(1), ref(1), 'a', 'b'))
        b['types'][1]['qualifiers'] = ['const']
        self.assertTrue(graph.catch_compatible(ref(1), ref(1), 'a', 'b'))
        self.assertFalse(graph.catch_compatible(ref(4), ref(6), 'a', 'b'))
        for item in a['types']:
            if item['kind'] in ('void', 'reference', 'array', 'function'):
                with self.assertRaisesRegex(ABIError, 'ABI_CC_CATCH_NORMALIZATION'):
                    graph.catch_compatible(ref(item['id']), ref(item['id']), 'a', 'a')
        self.assertTrue(graph.catch_compatible(ref(6), ref(6), 'a', 'b'))

    def test_normalized_native_CFI_registers_widths_and_rejections(self):
        a, evidence = build()
        verify(a, context(a, evidence))
        cases = [
            ('ABI_CC_CFA_REGISTER', lambda row: row['cfa'].update(reg=7)),
            ('ABI_CC_CFA_REGISTER', lambda row: row['cfa'].update(base='register', reg=16)),
            ('ABI_CC_CFI_WIDTH', lambda row: row['return_rule'].update(width=4)),
            ('ABI_CC_CFI_REGISTER', lambda row: row['registers'].append({'reg': 33, 'rule': {'kind': 'same'}})),
            ('ABI_CC_CFI_REGISTER_WIDTH', lambda row: row['registers'].append({'reg': 17, 'rule': {'kind': 'register', 'reg': 0}})),
            ('ABI_CC_CFI_EXPRESSION_UNSUPPORTED', lambda row: row.update(return_rule={'kind': 'expression', 'recipe': 0})),
        ]
        for diagnostic, change in cases:
            bad = deepcopy(a)
            change(bad['unwind'][0]['rows'][0])
            with self.assertRaisesRegex(ABIError, diagnostic):
                verify(bad, context(bad, evidence))
        a['unwind'][0]['rows'][0]['registers'] = [{'reg': 17, 'rule': {'kind': 'cfa_offset', 'offset': -24, 'width': 8}}]
        evidence['native_unwind']['100'] = deepcopy(a['unwind'][0])
        verify(a, context(a, evidence))

    def test_full_call_plan_hidden_owner_noundef_and_recipe_body_independence(self):
        a,evidence=build();b=deepcopy(a)
        graph=NominalGraph(a,'a',{'b':b})
        for identifier in (0,1,2):
            self.assertTrue(graph.signature_compatible(ref(identifier),ref(identifier),'a','b'))
        b['signatures'][2]['this_type']=some(ref(6))
        self.assertFalse(graph.signature_compatible(ref(2),ref(2),'a','b'))
        b['signatures'][2]=deepcopy(a['signatures'][2])
        b['signatures'][2]['vtt']=False
        self.assertFalse(graph.signature_compatible(ref(2),ref(2),'a','b'))
        b['signatures'][2]=deepcopy(a['signatures'][2])
        b['signatures'][0]['lowered_params'][0]['noundef']=False
        self.assertFalse(graph.signature_compatible(ref(0),ref(0),'a','b'))
        recipe={'id':1,'domain':0,'params':[{'id':7,'type':ref(4)},{'id':8,'type':ref(4)}],
            'results':[],'entry':0,'steps':[step(0,'byte_copy',[7,8],normal=1,extent=8,align=4),step(1,'return',[])]}
        a['recipes'].append(recipe);a['signatures'][1]['lowered_params'][1]['move']=some(1)
        b=deepcopy(a);b['recipes'][1]['steps'][0]['ticket']=99
        b['recipes'][1]['id']=19;b['signatures'][1]['lowered_params'][1]['move']=some(19)
        verify(a,context(a,evidence));verify(b,context(b,evidence))
        graph=NominalGraph(a,'a',{'b':b})
        self.assertTrue(graph.signature_compatible(ref(1),ref(1),'a','b'))
        b['recipes'][1]['params'][1]['type']=ref(6)
        self.assertFalse(graph.signature_compatible(ref(1),ref(1),'a','b'))

    def test_C_provider_CPP_C_linkage_complete_roots_and_rejections(self):
        c,cpp,evidence,ids=build_pair()
        verify(c,context(c,evidence));verify(cpp,context(cpp,evidence))
        graph=NominalGraph(c,'c',{'cpp':cpp})
        fn=ref(ids['function'])
        self.assertTrue(graph.boundary_compatible(fn,fn,'c','cpp'))
        self.assertFalse(graph.compatible(ref(ids['wchar']),ref(ids['wchar']),'c','cpp'))
        self.assertTrue(graph.boundary_compatible(fn,fn,'cpp','c'))
        for mutate in [
            lambda d:d['types'][ids['function']]['flags'].remove('c_linkage'),
            lambda d:d['types'][ids['record']]['flags'].remove('c_compatible'),
            lambda d:next(l for l in d['layouts'] if l['id']==ids['record']).update(size=16),
            lambda d:d['types'][ids['record']]['methods'].append({'name':'method','signature':ref(12),'virtual':False,'slot':None,'noexcept':False}),
            lambda d:d['types'][ids['wchar']].update(signed=False),
        ]:
            bad=deepcopy(cpp);mutate(bad)
            self.assertFalse(NominalGraph(c,'c',{'cpp':bad}).boundary_compatible(fn,fn,'c','cpp'))

    def test_C_data_linkage_pointer_mirror_and_address_only_incomplete_object(self):
        c,cpp,_,ids=build_pair()
        graph=NominalGraph(cpp,'cpp',{'c':c})
        self.assertTrue(graph.data_boundary_compatible(ref(ids['wide_pointer']),ref(ids['wide_pointer']),'cpp','c'))
        self.assertTrue(graph.data_boundary_compatible(ref(ids['record']),ref(ids['record']),'cpp','c'))
        self.assertFalse(graph.boundary_compatible(ref(ids['record']),ref(ids['record']),'cpp','c'))
        incomplete=deepcopy(cpp)
        incomplete['types'][ids['record']].update(layout=None,execution=None,representation='none',flags=[])
        graph=NominalGraph(incomplete,'cpp',{'c':c})
        self.assertTrue(graph.data_boundary_compatible(ref(ids['record']),ref(ids['record']),'cpp','c'))
        self.assertFalse(graph.data_boundary_compatible(ref(ids['record']),ref(ids['record']),'c','cpp'))

    def test_candidate_primary_archives_and_exact_source_identity(self):
        source=json.loads((ROOT/'docs/specifications/smir/portable/schema/abi/candidate-sources.json').read_text())
        self.assertEqual(len(source['sources']),17)
        for item in source['sources']:
            payload=(ROOT/'docs/specifications/smir/portable/references'/item['path']).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(),item['sha256'])
            self.assertEqual(item['source_revision'],'36763294ef639d8a6a4379d81da653dda1c20686')
            self.assertEqual(item['license'],'Apache-2.0 WITH LLVM-exception')

    def test_closed_namespaces_same_id_and_dependency_private_ids(self):
        a,_=build();b=deepcopy(a)
        b['signatures'][0]['id']=99
        resolver=Entities('A',a,{'B':b},{'A':{7:{'module':'B','signature':{900:99}}}})
        self.assertEqual(resolver.lookup('nominal',ref(0))['kind'],'void')
        self.assertEqual(resolver.lookup('signature',ref(0))['function_type'],ref(12))
        with self.assertRaisesRegex(ABIError,'ABI_CC_ENTITY_NAMESPACE'):
            resolver.resolve('nominal',ref(0)).as_namespace('signature')
        self.assertEqual(resolver.resolve('signature',ref(900,7)).identifier,99)
        with self.assertRaisesRegex(ABIError,'ABI_CC_UNBOUND_ENTITY_DECLARATION'):
            resolver.lookup('bridge',ref(900,7))
        with self.assertRaisesRegex(ABIError,'ABI_CC_ENTITY_REFERENCE'):
            resolver.lookup('signature',ref(12))

    def test_complete_contract_has_all_surfaces_and_no_execution_admission(self):
        doc, evidence = build()
        result = verify(doc, context(doc, evidence))
        self.assertEqual((result['types'], result['signatures'], result['layouts']), (24, 3, 17))
        self.assertFalse(result['admitted_for_execution'])
        for name in ('types', 'layouts', 'signatures', 'domains', 'recipes', 'personalities', 'unwind', 'catches', 'bridges', 'journals'):
            self.assertTrue(doc[name], name)

    def test_cleanup_formals_and_reverse_callback_native_endpoint(self):
        doc,evidence=build()
        program=doc['journals'][0]
        program['params']=[{'id':7,'type':ref(5)}]
        program['slots'][0].update(count=0,count_source=some(7))
        verify(doc,context(doc,evidence))
        bad=deepcopy(doc);bad['journals'][0]['params'][0]['type']=ref(1)
        with self.assertRaisesRegex(ABIError,'ABI_CC_JOURNAL_COUNT_SOURCE'):
            verify(bad,context(bad,evidence))
        callback=deepcopy(doc['bridges'][0]);callback.update(id=1,source=1,target=0)
        doc['bridges'].append(callback)
        verify(doc,context(doc,evidence))
        evidence['symbols']['100']['bridge_abi']='aapcs64_frame'
        with self.assertRaisesRegex(ABIError,'ABI_CC_BRIDGE_ENTRY'):
            verify(doc,context(doc,evidence))

    def test_semantic_rejection_partitions(self):
        def bad_layout(document, evidence):
            # Isolate extent alignment; changing a record also invalidates its
            # atomic wrapper first and is a different rejection partition.
            next(item for item in document['layouts'] if item['id'] == 1)['size'] = 5

        cases = [
            ('source_execution_mismatch', lambda d,e: d['types'][1].update(bits=64), 'ABI_CC_TYPE_BINDING'),
            ('layout_extent', bad_layout, 'ABI_CC_LAYOUT_EXTENT'),
            ('sret_order', lambda d,e: d['signatures'][1]['lowered_params'].reverse(), 'ABI_CC_CALL_PARAMETER'),
            ('variadic_suffix', lambda d,e: d['signatures'][2]['lowered_params'].pop(), 'ABI_CC_CALL_SHAPE'),
            ('cfi_coverage', lambda d,e: d['unwind'][0]['rows'][0].update(start=1), 'ABI_CC_CFI_COVERAGE'),
            ('cfi_width', lambda d,e: d['unwind'][0]['rows'][0]['return_rule'].update(width=3), 'ABI_CC_CFI_WIDTH'),
            ('missing_metadata', lambda d,e: d['unwind'][0].update(metadata=[]), 'ABI_CC_MISSING_NATIVE_METADATA'),
            ('wrong_metadata_hash', lambda d,e: d['unwind'][0]['metadata'][0].update(digest='f'*64), 'ABI_CC_METADATA_DIGEST'),
            ('ambiguous_alias', lambda d,e: d['bridges'][0].update(aliases='shared'), 'ABI_CC_UNREPRESENTABLE_ALIAS'),
            ('native_certificate', lambda d,e: e.update(native_types={}), 'ABI_CC_NATIVE_TYPE_EVIDENCE'),
            ('native_domain_certificate',lambda d,e:e.update(native_domains={}),'ABI_CC_NATIVE_DOMAIN_EVIDENCE'),
            ('native_layout_certificate',lambda d,e:e.update(native_layouts={}),'ABI_CC_NATIVE_LAYOUT_EVIDENCE'),
            ('unwind_certificate', lambda d,e: d['unwind'][0]['rows'][0]['cfa'].update(offset=16), 'ABI_CC_NATIVE_UNWIND_EVIDENCE'),
            ('landing_outside_code', lambda d,e: d['unwind'][0]['regions'][0].update(landing_offset=16), 'ABI_CC_LANDING_PAD'),
        ]
        for name, change, code in cases:
            with self.subTest(name=name):
                doc, evidence = build()
                change(doc, evidence)
                seal(doc)
                with self.assertRaisesRegex(ABIError, code):
                    verify(doc, context(doc, evidence))

    def test_alpha_renaming_ids_preserves_nominal_definition(self):
        doc, _ = build()
        graph = NominalGraph(doc, 'A')
        before = graph.fingerprint(ref(3))
        changed = deepcopy(doc)
        mapping = {typ['id']: typ['id'] + 200 for typ in changed['types']}

        def rename(value):
            if isinstance(value, list):
                return [rename(item) for item in value]
            if not isinstance(value, dict):
                return value
            if set(value) == {'module', 'id'} and value['module']['kind'] == 'self' and value['id'] in mapping:
                return ref(mapping[value['id']])
            return {key: rename(item) for key, item in value.items()}
        changed = rename(changed)
        for typ in changed['types']:
            old = typ['id']
            typ['id'] = mapping[old]
        # Layout IDs are independent; type->layout still uses original IDs.
        after = NominalGraph(changed, 'A').fingerprint(ref(mapping[3]))
        self.assertEqual(before, after)

    def test_nominal_sharing_and_pointee_completeness_do_not_change_definition(self):
        doc,_=build()
        # Duplicate equivalent scalar nodes must not affect source identity.
        first=deepcopy(doc)
        layout=next(item for item in first['layouts'] if item['id']==3)
        layout['fields']=[field('a',1,0,32),field('b',1,32,32)]
        second=deepcopy(first)
        duplicate=deepcopy(second['types'][1]);duplicate['id']=99
        second['types'].append(duplicate)
        next(item for item in second['layouts'] if item['id']==3)['fields'][1]['type']=ref(99)
        self.assertEqual(NominalGraph(first,'a').fingerprint(ref(3)),NominalGraph(second,'a').fingerprint(ref(3)))
        # Function/pointer declarations can name an incomplete record in one TU.
        first=deepcopy(doc);second=deepcopy(doc)
        first['types'][3].update(flags=[],layout=None,execution=None,representation='none')
        first['types'][3]['identity']['definition']='0'*64
        self.assertEqual(NominalGraph(first,'a').fingerprint(ref(4)),NominalGraph(second,'a').fingerprint(ref(4)))

    def test_boundary_requires_complete_by_value_layout_even_when_execution_matches(self):
        a,_=build();b=deepcopy(a)
        graph=NominalGraph(a,'a',{'b':b})
        self.assertTrue(graph.boundary_compatible(ref(13),ref(13),'a','b'))
        next(l for l in b['layouts'] if l['id']==3)['size']=16
        self.assertFalse(graph.boundary_compatible(ref(13),ref(13),'a','b'))
        b=deepcopy(a);b['types'][3].update(layout=None,execution=None,representation='none',flags=[])
        graph=NominalGraph(a,'a',{'b':b})
        self.assertTrue(graph.compatible(ref(13),ref(13),'a','b'))
        self.assertFalse(graph.boundary_compatible(ref(13),ref(13),'a','b'))
        self.assertTrue(graph.boundary_compatible(ref(4),ref(4),'a','b'))

    def test_cyclic_dependency_declaration_maps_and_incomplete_extern(self):
        a, _ = build()
        b = deepcopy(a)
        b['types'][3]['id'] = 203
        next(layout for layout in b['layouts'] if layout['id']==3)['type'] = ref(203)
        for typ in b['types']:
            typ['elements'] = [ref(203) if r == ref(3) else r for r in typ['elements']]
        bindings = {'A': {7: {'module':'B','types':{900:203}}},
                    'B': {8: {'module':'A','types':{901:3}}}}
        graph = NominalGraph(a, 'A', {'B':b}, bindings)
        self.assertTrue(graph.compatible(ref(3), ref(900,7)))
        self.assertEqual(graph.resolve(ref(901,8), 'B')[1]['id'], 3)
        with self.assertRaisesRegex(ABIError, 'ABI_CC_UNBOUND_DECLARATION'):
            graph.resolve(ref(203,7))
        b['types'] = [typ for typ in b['types'] if typ['id'] != 203] + [
            {**deepcopy(a['types'][3]), 'id':203, 'layout':None, 'representation':'none',
             'execution':None, 'flags':[], 'identity':{**a['types'][3]['identity'],'definition':'0'*64}}]
        graph = NominalGraph(a, 'A', {'B':b}, bindings)
        self.assertTrue(graph.compatible(ref(3), ref(900,7)))
        with self.assertRaisesRegex(ABIError, 'ABI_CC_INCOMPLETE_VALUE'):
            graph.layout(ref(900,7))

    def test_value_padding_masks_and_atomic_flag_identity(self):
        doc, _ = build()
        graph = NominalGraph(doc, 'main')
        self.assertEqual(graph.value_mask(ref(3)).hex(), 'ff000000ffffffff')
        self.assertEqual(graph.value_mask(ref(9)).hex(), '01')
        self.assertEqual(graph.value_mask(ref(10)).hex(), 'ffffffffffffffff0100000000000000')
        self.assertEqual(graph.value_mask(ref(11)).hex(), 'ff000000ffffffff')

    def test_every_nominal_kind_and_scalar_configuration(self):
        doc,evidence=build(all_kinds=True)
        from candidate import KINDS
        self.assertEqual({item['kind'] for item in doc['types']},KINDS)
        verify(doc,context(doc,evidence))
        graph=NominalGraph(doc,'main')
        vector=next(t for t in doc['types'] if t['kind']=='vector')
        self.assertEqual(graph.value_mask(ref(vector['id'])),b'\xff'*12+b'\0'*4)
        enum=next(t for t in doc['types'] if t['identity']['entity']=='example.Enum')
        enum['enumerators'][1]['name']='minus_one';seal(doc)
        with self.assertRaisesRegex(ABIError,'ABI_CC_ENUM_DECLARATION'):verify(doc,context(doc,evidence))

    def test_explicit_source_storage_correspondence_and_rejection(self):
        doc,evidence=build()
        self.assertEqual(len(doc['storage_bindings']),4)
        verify(doc,context(doc,evidence))
        for change,expected in [
            (lambda d:d['storage_bindings'][2].update(access_bytes=16),'ABI_CC_STORAGE_ACCESS'),
            (lambda d:d['storage_bindings'][1]['fragments'][0].update(execution_offset_bits=32),'ABI_CC_STORAGE_POSITION'),
            (lambda d:d['storage_bindings'][1]['fragments'][1].update(role='value'),'ABI_CC_STORAGE_VALUE_COVERAGE'),
            (lambda d:d['storage_bindings'][3]['fragments'][2].update(source_path=['missing']),'ABI_CC_STORAGE_SOURCE_PATH')]:
            bad=deepcopy(doc);change(bad)
            with self.assertRaisesRegex(ABIError,expected):verify(bad,context(bad,evidence))

    def test_storage_effect_cannot_cross_source_or_adjacent_value_bits(self):
        doc,evidence=build()
        binding=doc['storage_bindings'][3]
        binding.update(kind='fieldwise',view_offset_bits=0,view_width_bits=32,access_bytes=8)
        binding['nominal']=ref(1)
        with self.assertRaisesRegex(ABIError,'ABI_CC_STORAGE_EFFECT_RANGE'):
            verify(doc,context(doc,evidence))
        doc,evidence=build()
        layout=next(l for l in doc['layouts'] if l['id']==3)
        layout.update(size=4,data_size=4,nonvirtual_size=4)
        layout['fields']=[field('a',1,0,13,['bitfield']),dict(field('b',1,13,3,['bitfield']),declaration_index=1)]
        doc['types'][3]['record_input']=some(plain_cpp_record([
            declared_field('a',1,bit_width=13),declared_field('b',1,bit_width=3)]))
        next(t for t in evidence['execution_graph'] if t['id']==3)['bits']=32
        binding=doc['storage_bindings'][3]
        binding.update(kind='bit_container',view_offset_bits=0,view_width_bits=13,access_bytes=2)
        evidence['memory_layouts']['3'].update(size=2,access_bytes=2,alignment=1)
        seal(doc)
        # Isolate the effect predicate from unrelated call-plan copy extents.
        # Verify the new declared source record independently before the effect.
        from record_layout.checked import CheckedRecords
        from storage_binding import verify_binding
        graph=NominalGraph(doc,'main');CheckedRecords(graph).verify(ref(3))
        with self.assertRaisesRegex(ABIError,'ABI_CC_STORAGE_EFFECT_VALUE_CLOBBER'):
            verify_binding(binding,graph,context(doc,evidence).memory_layout)

    def test_capture_formal_bijection_execution_type_and_injected_brand(self):
        doc,evidence=build();graph=NominalGraph(doc,'main');ctx=context(doc,evidence)
        recipe={'params':[{'id':7,'type':ref(7)}]}
        captures=[{'parameter':7,'type':ref(7),'source':{'kind':'exception'}}]
        self.assertTrue(verify_captures(recipe,captures,graph,ctx.execution))
        for bad,expected in [([], 'ABI_CC_CAPTURE_BIJECTION'),
            ([{**captures[0],'type':ref(5)}],'ABI_CC_CAPTURE_TYPE'),
            ([{**captures[0],'source':{'kind':'journal'}}],'ABI_CC_CAPTURE_INJECTED_KIND')]:
            with self.assertRaisesRegex(ABIError,expected):verify_captures(recipe,bad,graph,ctx.execution)

    def test_shape_bisimulation_sharing_ids_and_recursive_signatures(self):
        nodes=[{'id':0,'kind':'int','bits':32},{'id':1,'kind':'int','bits':32},
            {'id':2,'kind':'struct','fields':[ref(0),ref(0)]},
            {'id':3,'kind':'struct','fields':[ref(0),ref(1)]},
            {'id':4,'kind':'code_ptr','signature':ref(5)},
            {'id':5,'kind':'function','params':[ref(4)],'results':[],'cc':'portable','variadic':False,
             'param_noundef':[True],'result_noundef':[]},
            {'id':6,'kind':'code_ptr','signature':ref(7)},
            {'id':7,'kind':'function','params':[ref(6)],'results':[],'cc':'portable','variadic':False,
             'param_noundef':[True],'result_noundef':[]}]
        shapes=ExecutionShapes(nodes)
        self.assertTrue(shapes.equal(ref(2),ref(3)));self.assertEqual(shapes.digest(ref(2)),shapes.digest(ref(3)))
        self.assertTrue(shapes.equal(ref(4),ref(6)));self.assertEqual(shapes.digest(ref(4)),shapes.digest(ref(6)))
        nodes[-1]['param_noundef']=[False];other=ExecutionShapes(nodes)
        self.assertFalse(other.equal(ref(4),ref(6)));self.assertNotEqual(other.digest(ref(4)),other.digest(ref(6)))

    def test_source_unit_keys_reject_absolute_and_preserve_unicode_identity(self):
        for path in ['/absolute.cpp','\\\\server\\file','C:\\source.cpp','D:/source.cpp']:
            with self.assertRaisesRegex(ABIError,'ABI_CC_SOURCE_UNIT'):unit_identity('n','m',1,path)
        self.assertNotEqual(unit_identity('n','m',1,'e\u0301.cpp'),unit_identity('n','m',1,'\u00e9.cpp'))

    def test_private_source_identity_across_artifacts_is_family_and_unit_qualified(self):
        a, _ = build(); b = deepcopy(a)
        uid = unit_identity('example','library',1,'src/unit.cpp')
        for document in (a,b):
            document['types'][3]['identity'].update(linkage='internal',unit=some(uid))
            seal(document)
        graph=NominalGraph(a,'artifact_debug',{'artifact_optimized':b},families={
            'artifact_debug':('example','library',1),'artifact_optimized':('example','library',1)})
        self.assertTrue(graph.compatible(ref(3),ref(3),'artifact_debug','artifact_optimized'))
        graph.families['artifact_optimized']=('example','other_library',1)
        self.assertFalse(graph.compatible(ref(3),ref(3),'artifact_debug','artifact_optimized'))
        graph.families['artifact_optimized']=('example','library',1)
        b['types'][3]['identity']['unit']=some(unit_identity('example','library',1,'src/other.cpp'))
        self.assertFalse(graph.compatible(ref(3),ref(3),'artifact_debug','artifact_optimized'))

    def test_catch_public_private_ambiguous_virtual_cv_and_member_conversions(self):
        doc,_=build()
        def record(name,bases=()):
            identifier=max(t['id'] for t in doc['types'])+1
            typ=deepcopy(doc['types'][3]);typ.update(id=identifier,layout=some(identifier))
            typ['identity']['entity']=name
            layout=deepcopy(next(l for l in doc['layouts'] if l['id']==3))
            # Pure catch source-path/access test with synthetic placements;
            # this is not a record-geometry admission witness.
            typ['record_input']=some(plain_cpp_record([]))
            typ['record_input']['some']['bases']=[{'type':b['type'],'virtual':b['virtual'],'access':b['access']} for b in bases]
            placements=[{'type':b['type'],'offset':b['offset'],'virtual':b['virtual'],
                'declaration_index':None if b['virtual'] else some(i),'origin_path':[i],
                'adjustment':{'kind':'virtual','vptr_offset':0,'slot_bytes':-24,'addend':0} if b['virtual'] else
                             {'kind':'fixed','offset':b['offset']}} for i,b in enumerate(bases)]
            layout.update(id=identifier,type=ref(identifier),fields=[],bases=placements,size=64,data_size=64,nonvirtual_size=64)
            doc['types'].append(typ);doc['layouts'].append(layout)
            return identifier
        def base(typ,path,offset=0,access='public',virtual=False):
            # Historical path spelling does not identify ABI2 declaration edges.
            return {'type':ref(typ),'access':access,'virtual':virtual,'offset':offset}
        def pointer(name,target):
            identifier=max(t['id'] for t in doc['types'])+1
            typ=deepcopy(doc['types'][4]);typ.update(id=identifier,elements=[ref(target)])
            typ['identity']['entity']=name;doc['types'].append(typ)
            return identifier
        b=record('B');d=record('D',[base(b,'B')]);private=record('Private',[base(b,'B',access='private')])
        l=record('L',[base(b,'B')]);r=record('R',[base(b,'B')])
        ambiguous=record('Ambiguous',[base(l,'L'),base(r,'R',32)])
        vl=record('VL',[base(b,'B',virtual=True)]);vr=record('VR',[base(b,'B',virtual=True)])
        vd=record('VD',[base(vl,'VL'),base(vr,'VR',32)])
        bp=pointer('B*',b);dp=pointer('D*',d)
        cv=record('B');doc['types'][cv]['qualifiers']=['const']
        cvp=pointer('B const*',cv)
        seal(doc);graph=NominalGraph(doc,'main')
        self.assertEqual(catch_relation(graph,ref(d),ref(b))['kind'],'base')
        self.assertIsNone(catch_relation(graph,ref(private),ref(b)))
        self.assertIsNone(catch_relation(graph,ref(ambiguous),ref(b)))
        self.assertEqual(catch_relation(graph,ref(vd),ref(b))['kind'],'base')
        self.assertEqual(catch_relation(graph,ref(dp),ref(bp),null_pointer=True)['kind'],'pointer')
        self.assertEqual(catch_relation(graph,ref(bp),ref(cvp))['kind'],'pointer')
        self.assertIsNone(catch_relation(graph,ref(cvp),ref(bp)))
        self.assertIsNone(catch_relation(graph,ref(1),ref(5)))

    def test_adapter_normal_unwind_dominance_and_call_signature(self):
        doc, evidence = build()
        integer, lease = 1, 7
        evidence['symbols']['110'] = {'kind':'function','domain':0,'signature':doc['signatures'][0]['function_type']}
        recipe = {'id':1,'domain':0,'params':[{'id':0,'type':ref(integer)}], 'results':[ref(integer)],'entry':0,
                  'steps':[step(0,'call',[0],[(1,integer)],normal=1,callee=some(ref(110)),unwind=some(2),
                                exception=some({'id':2,'type':ref(lease)})),
                           step(1,'return',[1]),step(2,'raise',[2])]}
        verify_adapter(recipe, NominalGraph(doc,'main'), context(doc,evidence), tables(doc))
        bad = deepcopy(recipe)
        bad['steps'][2]['inputs'] = [1]
        with self.assertRaisesRegex(ABIError, 'ABI_CC_ADAPTER_DOMINANCE'):
            verify_adapter(bad,NominalGraph(doc,'main'),context(doc,evidence),tables(doc))
        bad = deepcopy(recipe)
        bad['params'][0]['type'] = ref(5)
        with self.assertRaisesRegex(ABIError, 'ABI_CC_ADAPTER_ARGUMENT_TYPE'):
            verify_adapter(bad,NominalGraph(doc,'main'),context(doc,evidence),tables(doc))


class ConstructionTests(unittest.TestCase):
    def test_completed_constructor_does_not_invent_ended_member_lifetime(self):
        ctor=self.journal();identity=ctor.identity
        ctor.begin(0,0,1,identity)
        for slot_id in (1,2):
            ctor.begin(slot_id,0,slot_id+1,identity);ctor.commit(slot_id,0,slot_id+1,identity)
        ctor.commit(0,0,1,identity);ctor.finish_construction()
        registry=CompletedObjects(lambda identifier:{'live':True,'generation':1,'base':4096,'size':16})
        certificate=registry.publish(ctor,object_id=1,generation=1,address=4096,module='a'*64,
            module_generation=1,program=ref(1),leases=[1],lifetimes={(0,0):1,(2,0):3})
        self.assertEqual([entry['slot'] for entry in certificate['subobjects']],[0,2])
        self.assertEqual(ctor.states[1,0]['phase'],'alive') # historical initial completion

    def test_completed_object_fresh_thread_destructor_placement_and_once(self):
        program={'id':0,'signature':0,'params':[],'slots':[slot(0,3,destructor=0)],
            'normal_order':[0],'exception_order':[0]}
        ctor=self.journal(program);identity=ctor.identity
        ctor.begin(0,0,1,identity);ctor.commit(0,0,1,identity);ctor.finish_construction()
        registry=CompletedObjects(lambda object_id:{'live':True,'generation':7,'base':4096,'size':16})
        certificate=registry.publish(ctor,object_id=6,generation=7,address=4096,module='a'*64,
            module_generation=1,program=ref(0),leases=[8],lifetimes={(0,0):1})
        self.assertEqual(ctor.stage,'published')
        replaced=registry.replace(certificate['id'],0,0,2)
        with self.assertRaisesRegex(ABIError,'ABI_CC_STALE_OBJECT_CERTIFICATE'):
            registry.claim(certificate,program,identity=(9,10,11,12,13))
        dtor=registry.claim(replaced,program,identity=(9,10,11,12,13))
        self.assertNotEqual(dtor.identity[1],ctor.identity[1])
        self.assertEqual(dtor.entries,[])
        with self.assertRaisesRegex(ABIError,'ABI_CC_STALE_OBJECT_CERTIFICATE'):
            registry.claim(replaced,program,identity=(14,15,16,17,18))
        dtor.destroy_begin(0,0,1,dtor.identity)
        dtor.destroy_commit(0,0,1,dtor.identity,throws=True,exception=99)
        dtor.finish_cleanup()
        self.assertEqual(registry.finish(dtor)['phase'],'dead')
        self.assertEqual(ctor.entries[0]['thread'],2)
        self.assertEqual(dtor.entries[0]['thread'],10)
    def program(self):
        return {'id':1,'signature':0,'params':[],'slots':[
            slot(0,3,extent=16,stride=16,destructor=0,covers=[1,2]),
            slot(1,3,parent=0,extent=8,stride=8,role='member',destructor=0),
            slot(2,3,parent=0,offset=8,extent=8,stride=8,role='member',destructor=0)],
                'normal_order':[2,1,0], 'exception_order':[2,1,0]}

    def journal(self, program=None, counts=None):
        return ConstructionJournal(program or self.program(),transition=1,thread=2,activation=3,generation=4,instance=5,counts=counts)

    def test_partial_construction_reverse_cleanup_matches_native_trace(self):
        journal = self.journal()
        ident = (1,2,3,4,5)
        journal.begin(0,0,1,ident)
        journal.begin(1,0,2,ident)
        journal.commit(1,0,2,ident)
        journal.begin(2,0,3,ident)
        journal.construction_throws(2,0,3,77,ident)
        self.assertEqual(journal.cleanup_plan(),[(1,0)])
        journal.destroy_begin(1,0,4,ident)
        journal.destroy_commit(1,0,4,ident)
        self.assertEqual(journal.cleanup_plan(),[])
        self.assertEqual(journal.states[0,0]['phase'],'constructing')
        self.assertEqual(journal.states[2,0]['phase'],'failed')
        self.assertEqual([entry['phase'] for entry in journal.entries],
                         ['construct_begin','construct_begin','construct_commit','construct_begin',
                          'construct_failed','destroy_begin','destroy_commit'])

    def test_complete_destructor_coverage_not_duplicate_member_cleanup(self):
        journal=self.journal(); ident=(1,2,3,4,5)
        journal.begin(0,0,1,ident)
        for slot_id in [1,2]:
            journal.begin(slot_id,0,slot_id+1,ident); journal.commit(slot_id,0,slot_id+1,ident)
        journal.commit(0,0,1,ident);journal.finish_construction()
        self.assertEqual(journal.cleanup_plan(),[(0,0)])
        journal.destroy_begin(0,0,4,ident);journal.destroy_commit(0,0,4,ident)
        self.assertEqual([state['phase'] for state in journal.states.values()],['destroyed']*3)
        with self.assertRaisesRegex(ABIError,'ABI_CC_CLEANUP_ORDER'):
            journal.destroy_begin(1,0,5,ident)

    def test_dynamic_array_prefix_reverse_and_stale_replay(self):
        program={'id':0,'signature':0,'params':[{'id':7,'type':ref(5)}],'slots':[slot(0,3,role='array',count=0,count_source=7,extent=32,stride=8,destructor=0)],
                 'normal_order':[0],'exception_order':[0]}
        journal=self.journal(program,{7:4});ident=(1,2,3,4,5)
        with self.assertRaisesRegex(ABIError,'ABI_CC_ARRAY_PREFIX'):
            journal.begin(0,1,1,ident)
        for index in range(3):
            journal.begin(0,index,index+1,ident);journal.commit(0,index,index+1,ident)
        journal.begin(0,3,4,ident);journal.construction_throws(0,3,4,88,ident)
        self.assertEqual(journal.cleanup_plan(),[(0,2),(0,1),(0,0)])
        with self.assertRaisesRegex(ABIError,'ABI_CC_STALE_JOURNAL'):
            journal.destroy_begin(0,2,5,(1,9,3,4,5))
        journal.destroy_begin(0,2,5,ident);journal.destroy_commit(0,2,5,ident)
        with self.assertRaisesRegex(ABIError,'ABI_CC_CLEANUP_REPLAY'):
            journal.destroy_commit(0,2,5,ident)

    def test_destructor_throw_during_unwind_terminates(self):
        journal=self.journal();ident=(1,2,3,4,5)
        journal.begin(0,0,1,ident);journal.begin(1,0,2,ident);journal.commit(1,0,2,ident)
        journal.begin(2,0,3,ident);journal.construction_throws(2,0,3,77,ident)
        journal.destroy_begin(1,0,4,ident);journal.destroy_commit(1,0,4,ident,throws=True)
        self.assertEqual(journal.stage,'terminated')
        self.assertEqual(journal.states[1,0]['phase'],'destroying')

    def test_invalid_parent_cycle_coverage_and_nonlocal_exit(self):
        bad=self.program();bad['slots'][0]['parent']=some(1)
        with self.assertRaisesRegex(ABIError,'ABI_CC_SLOT_CYCLE'):verify_program(bad)
        bad=self.program();bad['slots'][1]['covers']=[2];bad['slots'][1]['destructor_kind']='complete'
        with self.assertRaisesRegex(ABIError,'ABI_CC_DESTRUCTOR_COVERAGE'):verify_program(bad)
        journal=self.journal();ident=(1,2,3,4,5);journal.begin(0,0,1,ident)
        with self.assertRaisesRegex(ABIError,'ABI_CC_LONGJMP_NONTRIVIAL'):journal.nonlocal_abandon()

    def test_exception_ptr_cross_thread_and_catch_copy_termination(self):
        lease=ExceptionLease(7,1,3,ref(90));lease.begin_catch(1);lease.retain_pointer();lease.end_catch(1)
        self.assertFalse(lease.destroyed)
        lease.rethrow_pointer(2,True);lease.begin_catch(2);lease.release_pointer();lease.end_catch(2)
        self.assertTrue(lease.destroyed)
        self.assertEqual(lease.events[-1],('destroy',1,3,ref(90)))
        other=ExceptionLease(8,1,3,ref(90));self.assertEqual(other.begin_catch(1,copy_throws=True),'terminated')

    def test_exception_rethrow_nested_catch_counts_and_no_fabricated_catch(self):
        lease=ExceptionLease(7,1,3,ref(90));lease.begin_catch(1)
        with self.assertRaisesRegex(ABIError,'ABI_CC_EXCEPTION_CATCH_REPLAY'):lease.begin_catch(1)
        lease.rethrow_current(1);lease.begin_catch(1)
        self.assertEqual(lease.active,2)
        lease.end_catch(1);self.assertFalse(lease.destroyed)
        lease.end_catch(1);self.assertTrue(lease.destroyed)
        with self.assertRaisesRegex(ABIError,'ABI_CC_EXCEPTION_LIFETIME'):lease.end_catch(1)

    def test_nested_array_instances_partial_failure_and_cross_module_program(self):
        parent_program={'id':0,'signature':0,'params':[],'slots':[
            {**slot(0,3,role='array',count=3,extent=48,stride=16,destructor=0),
             'child_program':some(ref(900,7))}], 'normal_order':[0],'exception_order':[0]}
        registry={}
        parent=ConstructionJournal(parent_program,transition=1,thread=2,activation=3,generation=4,
            instance=5,registry=registry,program_key=('array_module',0),
            resolve_program=lambda r:('class_module',1) if r==ref(900,7) else None)
        ident=(1,2,3,4,5)
        children=[]
        for element in range(2):
            parent.begin(0,element,element+1,ident)
            child=ConstructionJournal(self.program(),transition=1,thread=2,activation=6,generation=7,
                instance=10+element,registry=registry,program_key=('class_module',1),
                parent_instance={'journal':5,'slot':0,'element':element})
            ci=child.identity
            child.begin(0,0,1,ci);child.begin(1,0,2,ci);child.commit(1,0,2,ci)
            child.begin(2,0,3,ci)
            if element==0:
                child.commit(2,0,3,ci);child.commit(0,0,1,ci);child.finish_construction()
                parent.commit(0,element,element+1,ident)
            else:
                child.construction_throws(2,0,3,77,ci)
                child.destroy_begin(1,0,4,ci);child.destroy_commit(1,0,4,ci)
                child.construction_throws(0,0,1,77,ci);child.finish_cleanup()
                parent.construction_throws(0,element,element+1,77,ident)
            children.append(child)
        self.assertEqual(parent.cleanup_plan(),[(0,0)])
        parent.destroy_begin(0,0,4,ident)
        with self.assertRaisesRegex(ABIError,'ABI_CC_CHILD_CLEANUP'):
            parent.destroy_commit(0,0,4,ident)
        child=children[0];ci=child.identity
        child.destroy_begin(0,0,4,ci);child.destroy_commit(0,0,4,ci);child.finish_cleanup()
        parent.destroy_commit(0,0,4,ident);parent.finish_cleanup()
        self.assertEqual(parent.stage,'destroyed')
        self.assertEqual(children[1].states[2,0]['phase'],'failed')
        with self.assertRaisesRegex(ABIError,'ABI_CC_JOURNAL_INSTANCE_REPLAY'):
            ConstructionJournal(self.program(),transition=1,thread=2,activation=6,generation=7,
                instance=10,registry=registry)


class FEnvTests(unittest.TestCase):
    def test_exact_snapshot_layout_defaults_rounds_and_thread_copy(self):
        self.assertEqual((ENV.size,MODE.size),(32,16))
        self.assertEqual(DEFAULT_ENV.hex(),'01000000'+'00'*28)
        source=Environment();target=Environment()
        for rounding in ROUND.values():
            source.round=rounding;source.set_except(ALL)
            target.set_env(source.get_env())
            self.assertEqual((target.round,target.flags),(rounding,63))
        with self.assertRaises(ABIError):target.set_env((1<<64)-1)
        target.set_env(DEFAULT_ENV);target.set_mode(DEFAULT_MODE)
        self.assertEqual((target.round,target.flags),(0,0))

    def test_six_flags_sticky_denorm_and_no_trap_restores(self):
        env=Environment();env.diagnostic_policy=31
        env.set_except(63);self.assertEqual(env.test(63),63)
        env.set_flags(32,63);self.assertEqual(env.flags,32)
        env.arithmetic_flags([]);self.assertEqual(env.flags,32)
        env.raise_flags(32);self.assertEqual(env.flags,32)
        snapshot=env.get_env();env.clear(63);env.set_env(snapshot)
        self.assertEqual((env.flags,env.diagnostic_policy),(32,31))
        env.set_mode(MODE.pack(0x400,0,0));self.assertEqual(env.flags,32)

    def test_diagnostic_priority_flags_before_stop_and_private_policy(self):
        env=Environment();env.diagnostic_policy=31
        with self.assertRaises(FEnvTrap) as error:env.arithmetic_flags(['inexact','divide_by_zero','invalid'])
        self.assertEqual(error.exception.cause,'invalid');self.assertEqual(env.flags,7)
        before=env.get_env();saved=env.hold();self.assertEqual(saved,before)
        self.assertEqual((env.flags,env.diagnostic_policy),(0,31))
        env.set_env(DEFAULT_ENV);self.assertEqual(env.diagnostic_policy,31)
        env.set_except(FE['inexact'])
        with self.assertRaises(FEnvTrap):env.update(DEFAULT_ENV)
        self.assertEqual(env.flags,FE['inexact'])

    def test_bad_masks_modes_traps_and_reserved_are_failure_atomic(self):
        env=Environment();env.round=0x800;env.flags=32;before=env.get_env()
        for snapshot in [ENV.pack(0,0,0,0,0,0),ENV.pack(1,123,0,0,0,0),
                         ENV.pack(1,0,64,0,0,0),ENV.pack(1,0,0,1,0,0),ENV.pack(1,0,0,0,1,0)]:
            with self.assertRaises(ABIError):env.set_env(snapshot)
            self.assertEqual(env.get_env(),before)
        for operation in [env.clear,env.raise_flags,env.set_except,env.test]:
            with self.assertRaises(ABIError):operation(64)
            self.assertEqual(env.get_env(),before)

class CandidateVarArgsTests(unittest.TestCase):
    def test_host_thread_borrow_uses_owner_cookie_and_owner_revoke(self):
        arenas, Image, a, b, facts = self.model()
        arenas.pack(owner='A', recipe=a['recipes'][0], entries=[{
            'declaration': 1, 'image': Image((42).to_bytes(4, 'little'))}],
            area=4096, object_id=7, generation=9)
        owner_scope = (17, 2, 3)
        original = arenas.start(area=4096, bytes_=40, thread=owner_scope[0],
                                activation=owner_scope[1], generation=owner_scope[2])
        borrowed, revoked = original.copy(), original.copy()
        owner_host = threading.get_ident()
        def visit(cursor):
            # Actual source helper looks up this registered owner tuple; the
            # visiting host worker is independent of it, as is a guest visitor.
            value = cursor.arg(ref(301), owner='B', thread=owner_scope[0],
                activation=owner_scope[1], generation=owner_scope[2],
                decode_value=lambda typ, image, owner: image)
            return threading.get_ident(), value.data
        with ThreadPoolExecutor(max_workers=1) as executor:
            host, value = executor.submit(visit, borrowed).result(timeout=5)
            self.assertNotEqual(host, owner_host)
            self.assertEqual(value, (42).to_bytes(4, 'little'))
            self.assertEqual((original.cursor, borrowed.cursor), (0, 40))
            arenas.revoke(*owner_scope)
            with self.assertRaisesRegex(ABIError, 'ABI_CC_VARARGS_ACTIVATION'):
                executor.submit(visit, revoked).result(timeout=5)
        self.assertEqual(revoked.cursor, 0)

    def model(self):
        from candidate_varargs import Arenas,Image
        a,evidence=build();b=deepcopy(a)
        duplicate=deepcopy(b['types'][1]);duplicate['id']=301;duplicate['layout']=some(301)
        b['types'].append(duplicate)
        layout=deepcopy(next(item for item in b['layouts'] if item['id']==1))
        layout.update(id=301,type=ref(301));b['layouts'].append(layout);seal(b)
        verify(b,context(b,evidence))
        facts={7:{'live':True,'generation':9,'base':4096,'size':256},
               8:{'live':True,'generation':10,'base':8192,'size':0}}
        graph=NominalGraph(a,'A',{'B':b})
        return Arenas(graph,lambda identifier:facts[identifier]),Image,a,b,facts

    def test_cross_module_nominal_ids_copy_and_activation_revocation(self):
        arenas,Image,a,b,facts=self.model()
        arenas.pack(owner='A',recipe=a['recipes'][0],entries=[{'declaration':1,'image':Image((123).to_bytes(4,'little'))}],
            area=4096,object_id=7,generation=9)
        cursor=arenas.start(area=4096,bytes_=40,thread=1,activation=2,generation=3)
        copied=cursor.copy()
        args={'owner':'B','thread':1,'activation':2,'generation':3,'decode_value':lambda t,i,o:i}
        self.assertEqual(cursor.arg(ref(301),**args).data,(123).to_bytes(4,'little'))
        self.assertEqual(copied.cursor,0)
        self.assertEqual(copied.arg(ref(301),**args).data,(123).to_bytes(4,'little'))
        arenas.revoke(1,2,3)
        with self.assertRaisesRegex(ABIError,'ABI_CC_VARARGS_ACTIVATION'):cursor.arg(ref(301),**args)

    def test_empty_registered_pack_wrong_size_and_typed_decode_failure_atomicity(self):
        arenas,Image,a,b,facts=self.model()
        arenas.pack(owner='A',recipe={'params':[]},entries=[],area=8192,object_id=8,generation=10)
        empty=arenas.start(area=8192,bytes_=0,thread=1,activation=2,generation=3)
        with self.assertRaisesRegex(ABIError,'ABI_CC_VARARGS_BOUNDS'):
            empty.arg(ref(1),owner='A',thread=1,activation=2,generation=3,decode_value=lambda t,i,o:i)
        with self.assertRaisesRegex(ABIError,'ABI_CC_VARARGS_REGISTRATION'):
            arenas.start(area=8192,bytes_=1,thread=1,activation=2,generation=3)
        arenas.pack(owner='A',recipe=a['recipes'][0],entries=[{'declaration':1,'image':Image(b'\x01\0\0\0')}],
            area=4096,object_id=7,generation=9)
        cursor=arenas.start(area=4096,bytes_=40,thread=1,activation=2,generation=3)
        def reject(t,image,owner):
            raise ABIError('ABI_CC_TYPED_UNPACK')
        with self.assertRaisesRegex(ABIError,'ABI_CC_TYPED_UNPACK'):
            cursor.arg(ref(301),owner='B',thread=1,activation=2,generation=3,decode_value=reject)
        self.assertEqual(cursor.cursor,0)
        facts[7]['generation']=11
        with self.assertRaisesRegex(ABIError,'ABI_CC_VARARGS_BACKING'):
            cursor.arg(ref(301),owner='B',thread=1,activation=2,generation=3,decode_value=lambda t,i,o:i)

    def test_pointer_origins_preserved_and_failed_reconstruction_does_not_advance(self):
        arenas,Image,a,b,facts=self.model();token=object()
        image=Image((0x55).to_bytes(8,'little'),tuple((index,token) for index in range(8)))
        arenas.pack(owner='A',recipe={'params':[{'id':7,'type':ref(6)}]},
            entries=[{'declaration':6,'image':image}],area=4096,object_id=7,generation=9)
        cursor=arenas.start(area=4096,bytes_=40,thread=1,activation=2,generation=3)
        def recover(t,image,owner):
            if len(image.origins)!=8 or any(origin is not token for _,origin in image.origins):
                raise ABIError('ABI_CC_POINTER_ORIGIN')
            return image
        copied=cursor.copy()
        result=cursor.arg(ref(6),owner='B',thread=1,activation=2,generation=3,decode_value=recover)
        self.assertEqual(result.origins,image.origins)
        registration=arenas.registrations[4096]
        registration['image']=Image(registration['image'].data)
        with self.assertRaisesRegex(ABIError,'ABI_CC_POINTER_ORIGIN'):
            copied.arg(ref(6),owner='B',thread=1,activation=2,generation=3,decode_value=recover)
        self.assertEqual(copied.cursor,0)


class ConsumerNominalExpectationTests(unittest.TestCase):
    """Actual reference routing, separate from any selected provider or proof."""

    def test_candidate_verify_forwards_consumer_expectation_without_source_rewrite(self):
        document, evidence = build()
        document['signatures'][0]['function_type'] = ref(99, 7)
        original = deepcopy(document)
        ctx = context(document, evidence)
        with self.assertRaisesRegex(ABIError, 'ABI_CC_UNBOUND_DECLARATION'):
            verify(document, ctx)
        ctx.nominal_expectations = {'main': {(7, 99): 12}}
        result = verify(document, ctx)
        self.assertFalse(result['admitted_for_execution'])
        self.assertEqual(document, original)

    def test_strict_owner_precedes_colliding_provider_binding(self):
        document, _ = build()
        provider = deepcopy(document)
        bindings = {'main': {7: {'module': 'provider', 'types': {99: 13}}}}
        graph = NominalGraph(document, 'main', {'provider': provider}, bindings,
            nominal_expectations={'main': {(7, 99): 12}})
        owner, typ = graph.resolve(ref(99, 7))
        self.assertEqual((owner, typ['id']), ('main', 12))
        self.assertEqual(graph.resolve(ref(13))[1]['id'], 13)

    def test_empty_owner_is_strict_and_absent_owner_preserves_legacy(self):
        document, _ = build()
        provider = deepcopy(document)
        bindings = {'main': {7: {'module': 'provider', 'types': {99: 13}}}}
        for expectations in (None, {}, {'provider': {}}):
            with self.subTest(expectations=expectations):
                graph = NominalGraph(document, 'main', {'provider': provider}, bindings,
                                     nominal_expectations=expectations)
                self.assertEqual(graph.resolve(ref(99, 7))[0], 'provider')
        strict = NominalGraph(document, 'main', {'provider': provider}, bindings,
                              nominal_expectations={'main': {}})
        with self.assertRaisesRegex(ABIError, 'ABI_CC_UNBOUND_DECLARATION'):
            strict.resolve(ref(99, 7))

    def test_mapping_is_captured_and_immutable(self):
        document, _ = build()
        original = {'main': {(7, 99): 12}}
        graph = NominalGraph(document, 'main', nominal_expectations=original)
        original['main'][(7, 99)] = 13
        original.clear()
        self.assertEqual(graph.resolve(ref(99, 7))[1]['id'], 12)
        with self.assertRaises(TypeError):
            graph.nominal_expectations['main'][(7, 99)] = 13
        with self.assertRaises(TypeError):
            graph.nominal_expectations['main'] = {}
        reused = NominalGraph(document, 'main', nominal_expectations=graph.nominal_expectations)
        self.assertEqual(reused.resolve(ref(99, 7))[1]['id'], 12)

    def test_invalid_owner_keys_targets_and_reference_namespace_reject(self):
        document, _ = build()
        for mapping, code in [
            ([], 'ABI_CC_UNBOUND_DECLARATION'),
            ({'other': {}}, 'ABI_CC_TYPE_REFERENCE'),
            ({'main': []}, 'ABI_CC_UNBOUND_DECLARATION'),
            ({'main': {7: 12}}, 'ABI_CC_UNBOUND_DECLARATION'),
            ({'main': {(True, 99): 12}}, 'ABI_CC_UNBOUND_DECLARATION'),
            ({'main': {(7, 0xffffffff): 12}}, 'ABI_CC_UNBOUND_DECLARATION'),
            ({'main': {(7, 99): True}}, 'ABI_CC_TYPE_REFERENCE'),
            ({'main': {(7, 99): 0xffffffff}}, 'ABI_CC_TYPE_REFERENCE'),
            ({'main': {(7, 99): 999}}, 'ABI_CC_TYPE_REFERENCE')]:
            with self.subTest(mapping=mapping):
                with self.assertRaisesRegex(ABIError, code):
                    NominalGraph(document, 'main', nominal_expectations=mapping)
        graph = NominalGraph(document, 'main', nominal_expectations={'main': {(7, 1): 12}})
        for reference in (ref(1, 8), ref(2, 7), ref(True, 7), ref(1, True),
                          {'module': {'kind': 'recipe', 'slot': 7}, 'id': 1}):
            with self.subTest(reference=reference):
                with self.assertRaisesRegex(ABIError, 'ABI_CC_UNBOUND_DECLARATION'):
                    graph.resolve(reference)

    def test_local_graph_source_and_layout_callbacks_agree(self):
        document, _ = build()
        graph = NominalGraph(document, 'main', nominal_expectations={'main': {(7, 99): 1}})
        self.assertTrue(graph.compatible(ref(99, 7), ref(1)))
        self.assertEqual(graph.layout(ref(99, 7)), graph.layout(ref(1)))
        self.assertEqual(graph.fingerprint(ref(99, 7)), graph.fingerprint(ref(1)))
        # Nominal 1 is not Signature 1 merely because both namespaces use 1.
        self.assertEqual(graph.resolve(ref(99, 7))[1]['kind'], 'scalar')

    def test_execution_snapshot_deepcopy_keeps_aliases_and_separates_module_data(self):
        document, _ = build()
        graph = NominalGraph(document, 'main', nominal_expectations={'main': {(7, 99): 1}})
        copied = deepcopy(graph)
        self.assertIsNot(copied, graph)
        self.assertIsNot(copied.tables['main'][1], graph.tables['main'][1])
        self.assertEqual(copied.resolve(ref(99, 7))[1]['id'], 1)
        self.assertIs(copied.tables['main'][1], copied.modules['main']['types'][1])
        graph.nominal_expectations = None
        self.assertEqual(copied.resolve(ref(99, 7))[1]['id'], 1)
        with self.assertRaises(TypeError):
            copied.nominal_expectations['main'][(7, 99)] = 12

    def test_appended_context_and_keyword_preserve_existing_interfaces(self):
        from dataclasses import MISSING, fields
        import inspect
        from candidate import Context
        # Factory metering appended one optional field; the complete preceding
        # constructor remains callable in its original positional order.
        legacy_fields = (
            'module', 'execution', 'symbol', 'metadata', 'modules', 'bindings',
            'native_type', 'native_unwind', 'families', 'memory_layout',
            'native_domains', 'native_layout', 'native_personality',
            'source_data', 'source_stamp', 'source_budget', 'nominal_expectations',
        )
        expected_fields = legacy_fields + ('factory_budget',)
        self.assertEqual(tuple(field.name for field in fields(Context)), expected_fields)
        parameters = inspect.signature(Context).parameters
        self.assertEqual(tuple(parameters), expected_fields)
        for index, field in enumerate(fields(Context)):
            with self.subTest(field=field.name):
                self.assertEqual(parameters[field.name].kind,
                                 inspect.Parameter.POSITIONAL_OR_KEYWORD)
                if index < 10:
                    self.assertIs(field.default, MISSING)
                    self.assertIs(parameters[field.name].default, inspect.Parameter.empty)
                else:
                    self.assertIsNone(field.default)
                    self.assertIsNone(parameters[field.name].default)
        graph_parameters = inspect.signature(NominalGraph).parameters
        for name in ('nominal_expectations', 'budget'):
            self.assertEqual(graph_parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIsNone(graph_parameters[name].default)
        document, evidence = build()
        ctx = context(document, evidence)
        self.assertIsNone(ctx.nominal_expectations)
        self.assertIsNone(ctx.factory_budget)
        self.assertFalse(verify(document, ctx)['admitted_for_execution'])
        legacy_arguments = tuple(getattr(ctx, name) for name in legacy_fields)
        for old_call in (Context(*legacy_arguments),
                         Context(*legacy_arguments, factory_budget=None)):
            self.assertIsNone(old_call.nominal_expectations)
            self.assertIsNone(old_call.factory_budget)
            self.assertFalse(verify(document, old_call)['admitted_for_execution'])


if __name__ == '__main__':
    unittest.main()
