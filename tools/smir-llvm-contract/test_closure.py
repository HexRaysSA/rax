"""CC-L contracts: canonical identities, cycles, required families and Clang IR."""
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import subprocess
import tempfile
import unittest

import canonical
import bindings
import contracts
import deployment
import frontend_contract
from pointer_contract import gep
from fp_contract import to_integer, fpclass
from witness_ir import expanded_powi, expanded_powi64
from fractions import Fraction
from reference import ContractError
from test_contract import BIN, FIXTURES, PACKAGE, run

D = '1' * 64
N = '2' * 64


def view():
    declaration = lambda value: {'id': value, 'type': D}
    operation = lambda op, outs, payload: {'op': op, 'outs': outs, 'payload': payload}
    return {'revision': 'llvm-comparison-v1', 'signature': D,
            'params': [declaration(77)], 'entry': 40, 'block_addresses': False, 'regions': [],
            'blocks': [
                {'id': 40, 'phis': [], 'ops': [operation('add', [declaration(100)],
                    {'a': {'$ref': 'value', 'id': 77}, 'literal': 40, 'flags': []})],
                 'term': operation('jump', [], {}), 'edges': [{'role': 'jump', 'target': 90}]},
                {'id': 90, 'phis': [{'out': declaration(19), 'incoming': [{'block': 40, 'value': 100}]}],
                 'ops': [], 'term': operation('return', [], {'value': {'$ref': 'value', 'id': 19}}), 'edges': []},
            ]}


def groups(selection='any'):
    def group(ordinal, body):
        return {'key': 'inline.f', 'selection': selection, 'key_symbol': 'f', 'input_ordinal': ordinal,
                'members': [{'symbol': 'f', 'abi': D, 'kind': 'function',
                             'extent': len(body), 'body': body, 'extent_policy': 'fixed'}]}
    return [group(9, b'O0 reachable body'), group(2, b'O2')]


def cycle():
    def export(identifier, name):
        return {'id': identifier, 'namespace': 'test', 'name': name,
                'kind': 'function', 'source_linkage':'c', 'signature': D, 'nominal': N, 'abi_signature': D}
    modules = []
    for key, other, own_id, imported_id in [('a', 'b', 5, 301), ('b', 'a', 29, 12)]:
        own_name = key + '_fn'
        target_name = other + '_fn'
        modules.append({'key': key, 'artifact': hashlib.sha256(key.encode()).hexdigest(), 'abi': D,
                        'version': 3, 'exports': [export(own_id, own_name)],
                        'dependencies': [{'slot': 7, 'key': other, 'abi': D,
                            'minimum_version': 1, 'maximum_version': 4,
                            'declarations': [export(imported_id, target_name)]}]})
    manifest = {m['key']: {'artifact': m['artifact'], 'abi': m['abi'], 'generation': 23} for m in modules}
    return modules, manifest


class CanonicalWitnesses(unittest.TestCase):
    def test_alpha_ids_and_order_do_not_change_exactmatch_body(self):
        original = view()
        changed = copy.deepcopy(original)
        changed['entry'] = 8
        changed['blocks'][0]['id'] = 8
        changed['blocks'][0]['edges'][0]['target'] = 7
        changed['blocks'][1]['id'] = 7
        changed['blocks'][1]['phis'][0]['incoming'][0]['block'] = 8
        changed['params'][0]['id'] = 1
        changed['blocks'][0]['ops'][0]['outs'][0]['id'] = 2
        changed['blocks'][0]['ops'][0]['payload']['a']['id'] = 1
        changed['blocks'][1]['phis'][0]['out']['id'] = 3
        changed['blocks'][1]['phis'][0]['incoming'][0]['value'] = 2
        changed['blocks'][1]['term']['payload']['value']['id'] = 3
        changed['blocks'].reverse()
        self.assertEqual(canonical.canonical_function(original), canonical.canonical_function(changed))
        # Plain numeric40 is a constant, never a renamed block/value ID.
        self.assertIn(b'"literal":40', canonical.canonical_function(changed))

    def test_reachable_semantic_change_changes_body(self):
        changed = view()
        changed['blocks'][0]['ops'][0]['payload']['flags'] = ['nsw']
        self.assertNotEqual(canonical.canonical_function(view()), canonical.canonical_function(changed))

    def test_missing_duplicate_and_blockaddress_reject(self):
        mutations = [lambda f: f.update(block_addresses=True),
                     lambda f: f['blocks'].append(copy.deepcopy(f['blocks'][0])),
                     lambda f: f['blocks'][0]['ops'][0]['payload']['a'].update(id=999),
                     lambda f: f['params'].append(copy.deepcopy(f['params'][0]))]
        for mutate in mutations:
            value = view()
            mutate(value)
            with self.assertRaises(ContractError):
                canonical.canonical_function(value)

    def test_module_preimage_golden_and_identity_masking(self):
        sections = {identifier: bytes([identifier]) for identifier in range(1, 11)}
        own = b'Z' * 32
        sections[2] = b'ab' + own + own
        actual = canonical.module_identity(sections, own, 2)
        # Independent construction: second equal byte pattern is ordinary data,
        # and MUST remain. The preimage layout is explicit integer byte arithmetic.
        expected = b'SMIR0.2\0' + b'\x02\0\0\0'
        for identifier in range(1, 11):
            payload = b'ab' + bytes(32) + own if identifier == 2 else bytes([identifier])
            expected += identifier.to_bytes(2, 'little') + len(payload).to_bytes(8, 'little') + payload
        self.assertEqual(actual, hashlib.sha256(expected).hexdigest())
        output = subprocess.run(['/usr/bin/shasum', '-a', '256'], input=expected,
                                capture_output=True, check=True).stdout.decode().split()[0]
        self.assertEqual(actual, output)
        sections[2] = b'ab' + b'Q' * 32 + own
        self.assertEqual(actual, canonical.module_identity(sections, b'Q' * 32, 2))
        sections[2] = b'ab' + b'Q' * 32 + b'R' * 32
        self.assertNotEqual(actual, canonical.module_identity(sections, b'Q' * 32, 2))

    def test_invalid_module_hash_inputs_reject(self):
        sections = {identifier: bytes(32) for identifier in range(1, 11)}
        for wrong in [dict(sections, **{'2': bytes(32)}), {k:v for k,v in sections.items() if k != 10}]:
            with self.assertRaises(ContractError):
                canonical.module_identity(wrong, bytes(32), 0)
        with self.assertRaises(ContractError):
            canonical.module_identity(sections, b'Q' * 32, 0)

    def test_all_comdat_selection_kinds(self):
        self.assertEqual(canonical.select_comdat(groups('any')), [2])
        self.assertEqual(canonical.select_comdat(groups('largest')), [9])
        self.assertEqual(canonical.select_comdat(groups('nodeduplicate')), [2, 9])
        for kind in ('exactmatch', 'samesize', 'noduplicates'):
            with self.subTest(kind=kind), self.assertRaises(ContractError):
                canonical.select_comdat(groups(kind))
        exact = groups('exactmatch')
        exact[1]['members'] = copy.deepcopy(exact[0]['members'])
        self.assertEqual(canonical.select_comdat(exact), [2])
        same = groups('samesize')
        same[1]['members'][0].update(body=b'X' * len(same[0]['members'][0]['body']),
                                   extent=same[0]['members'][0]['extent'])
        self.assertEqual(canonical.select_comdat(same), [2])

    def test_comdat_abi_and_recomputed_extent(self):
        mismatched = groups()
        mismatched[1]['members'][0]['abi'] = N
        with self.assertRaisesRegex(ContractError, 'COMDAT_ABI_MISMATCH'):
            canonical.select_comdat(mismatched)
        wrong = groups()
        wrong[0]['members'][0]['extent'] = 1000
        with self.assertRaisesRegex(ContractError, 'COMDAT_CODE_EXTENT'):
            canonical.select_comdat(wrong)
        duplicate = groups()
        duplicate[1]['input_ordinal'] = duplicate[0]['input_ordinal']
        with self.assertRaisesRegex(ContractError, 'COMDAT_ORDINAL'):
            canonical.select_comdat(duplicate)


class DeploymentWitnesses(unittest.TestCase):
    def test_C_and_Cxx_symbol_linkage_are_explicit_even_with_same_spelling(self):
        modules, manifest=cycle()
        declaration=modules[0]['dependencies'][0]['declarations'][0]
        before=deployment.symbol_identity('b',declaration)
        modules[1]['exports'][0]['source_linkage']='cpp'
        with self.assertRaisesRegex(ContractError,'SOURCE_LINKAGE'):
            deployment.bind_deployment(modules,manifest)
        declaration['source_linkage']='cpp'
        self.assertNotEqual(before,deployment.symbol_identity('b',declaration))

    def test_cycle_binds_local_declarations_to_different_export_ids(self):
        modules, manifest = cycle()
        result = deployment.bind_deployment(modules, manifest)
        self.assertEqual(result['bindings']['a', 7, 301], ('b', 29, 23))
        self.assertEqual(result['bindings']['b', 7, 12], ('a', 5, 23))
        self.assertEqual(result['components'], [['a', 'b']])

    def test_abi_stable_body_replacement_no_recompile_peer(self):
        modules, manifest = cycle()
        old_a = copy.deepcopy(modules[0])
        modules[1]['artifact'] = hashlib.sha256(b'O2 B body').hexdigest()
        manifest['b']['artifact'] = modules[1]['artifact']
        manifest['b']['generation'] = 24
        result = deployment.bind_deployment(modules, manifest)
        self.assertEqual(old_a, modules[0])
        self.assertEqual(result['bindings']['a', 7, 301], ('b', 29, 24))

    def test_wrong_artifact_type_version_or_unbound_dependency_reject(self):
        mutations = [lambda m,d: d['b'].update(artifact='0' * 64),
                     lambda m,d: m[1]['exports'][0].update(signature='3' * 64),
                     lambda m,d: m[1]['exports'][0].update(nominal='3' * 64),
                     lambda m,d: m[1].update(version=5),
                     lambda m,d: m[1].update(exports=[]),
                     lambda m,d: d['b'].update(generation=0)]
        for mutate in mutations:
            modules, manifest = cycle()
            mutate(modules, manifest)
            with self.assertRaises(ContractError):
                deployment.bind_deployment(modules, manifest)

    def test_normalized_symbol_ignores_private_and_importer_ids(self):
        modules, _ = cycle()
        declaration = modules[0]['dependencies'][0]['declarations'][0]
        exported = modules[1]['exports'][0]
        self.assertEqual(deployment.symbol_identity('b', declaration), deployment.symbol_identity('b', exported))


class RequiredContractWitnesses(unittest.TestCase):
    def test_pinned_GNU_Windows_Itanium_EH_is_separate_from_native_calling_convention(self):
        for target in ('x86_64-w64-windows-gnu','aarch64-w64-windows-gnu'):
            output=run([BIN/'clang','-target',target,'-std=c++23','-ffreestanding',
                        '-nostdinc','-S','-emit-llvm',FIXTURES/'families.cpp','-o','-'])
            self.assertIn('personality ptr @__gxx_personality_seh0',output)
            self.assertIn('landingpad',output)
        source=(BIN.parents[1]/'libcxxabi/src/cxa_personality.cpp').read_text()
        self.assertIn('__gxx_personality_seh0(PEXCEPTION_RECORD ms_exc, void *this_frame,',source)
        self.assertIn('PCONTEXT ms_orig_context, PDISPATCHER_CONTEXT ms_disp)',source)

    def test_all_required_instruction_recipes_have_closed_semantic_parts(self):
        for name, recipe in contracts.RECIPES.items():
            with self.subTest(name=name):
                self.assertTrue(recipe['operands'] and recipe['results'] and recipe['steps'])
                self.assertTrue(recipe['poison'] and recipe['effects'])
                self.assertFalse(recipe['emitter_implemented'])
                self.assertNotIn('CONTRACT:', ' '.join(recipe['steps']))

    def test_target_independent_intrinsics_classified_without_missing_contract_default(self):
        rows = csv.DictReader(io.StringIO((PACKAGE / 'intrinsic-matrix.tsv').read_text()), delimiter='\t')
        required = set()
        for row in rows:
            disposition, diagnostic, rule = contracts.intrinsic_contract(row['record'], row['target'])
            self.assertNotEqual(rule, 'unclassified', row['record'])
            if not diagnostic:
                self.assertIn(rule, contracts.INTRINSIC_DETAILS, row['record'])
                required.add(rule)
        self.assertTrue({'fp.math', 'coroutine.presplit', 'memory.intrinsic', 'varargs.intrinsic'} <= required)

    def test_optional_counter_and_debugger_have_exact_distinct_policies(self):
        for stem in ('readcyclecounter','readsteadycounter'):
            disposition, diagnostic, family = contracts.intrinsic_contract('int_'+stem,'')
            self.assertEqual((disposition,diagnostic,family),('expansion','','counter.intrinsic'))
        self.assertEqual(contracts.intrinsic_contract('int_debugtrap','')[1], 'E-EXT-DEBUGGER')
        for stem, diagnostic in [('protected_field_ptr','E-EXT-PROTECTED-FIELD'),
                                 ('load_relative','E-EXT-RELATIVE-POINTERS'),
                                 ('type_checked_load_relative','E-EXT-RELATIVE-POINTERS')]:
            self.assertEqual(contracts.intrinsic_contract('int_'+stem,'')[1],diagnostic)
        self.assertEqual(contracts.INTRINSIC_DETAILS['counter.intrinsic']['target'],'constant_zero')
        text=(BIN.parents[1]/'llvm/docs/LangRef.md').read_text()
        for heading in ("#### '`llvm.readcyclecounter`' Intrinsic", "#### '`llvm.readsteadycounter`' Intrinsic"):
            paragraph=text.split(heading,1)[1].split('\n#### ',1)[0]
            self.assertIn('lowered to a constant 0',paragraph)

    def test_nontrivial_pinned_frontend_families(self):
        requests = [
            ('families.c', 'c23', ['-mlong-double-128'], ['thread_local', 'cmpxchg', 'load volatile', '__atomic_load', 'llvm.va_start', 'fp128', '<4 x i32>']),
            ('families.cpp', 'c++23', [], ['invoke ', 'landingpad', 'resume ', '__dynamic_cast', '__cxa_begin_catch', 'returns_twice']),
            ('strict-fp.c', 'c23', ['-ffp-model=strict'], ['constrained.fadd', 'constrained.sitofp', 'constrained.fcmps', 'round.dynamic', 'fpexcept.strict']),
            ('coroutine.cpp', 'c++23', [], ['.resume(', '.destroy(', '.cleanup(', 'comdat any']),
        ]
        for name, language, options, tokens in requests:
            with self.subTest(name=name):
                output = run([BIN / 'clang', '-target', 'x86_64-unknown-linux-gnu', '-std=' + language,
                              '-ffreestanding', '-nostdinc', *options, '-S', '-emit-llvm', FIXTURES / name, '-o', '-'])
                for token in tokens:
                    self.assertIn(token, output)

    def test_pinned_raw_byte_and_stronger_cas_failure_ir(self):
        for name, tokens in [('raw.ll', ['load b128', 'store b128', 'freeze b128']),
                             ('atomic-order.ll', ['cmpxchg', 'acquire seq_cst'])]:
            with self.subTest(name=name):
                output = run([BIN / 'clang', '-x', 'ir', '-O0', '-S', '-emit-llvm', FIXTURES / name, '-o', '-'])
                for token in tokens:
                    self.assertIn(token, output)


class PointerFlagWitnesses(unittest.TestCase):
    def test_signed_and_unsigned_wrap_promises_differ(self):
        minus_one = (1 << 64) - 1
        self.assertEqual(gep(100, [(minus_one,64,1)]), (99,False))
        self.assertEqual(gep(100, [(minus_one,64,1)], flags=['nusw']), (99,False))
        self.assertEqual(gep(100, [(minus_one,64,1)], flags=['nuw']), (99,True))

    def test_all_zero_and_deallocated_object_inbounds(self):
        self.assertEqual(gep(0, [(0,64,8)], flags=['inbounds']), (0,False))
        self.assertEqual(gep(100, [(1,64,8)], flags=['inbounds'], allocation=(100,8)), (108,False))
        self.assertEqual(gep(100, [(2,64,8)], flags=['inbounds'], allocation=(100,8)), (116,True))
        # No liveness input: pure GEP allows a tombstoned allocation.

    def test_intermediate_bounds_and_wide_index(self):
        back = (1 << 64) - 2
        self.assertEqual(gep(100, [(2,64,8),(back,64,8)], flags=['inbounds'], allocation=(100,8)), (100,True))
        self.assertEqual(gep(100, [(1 << 64,65,1)], flags=['nusw']), (100,True))


class FrontendContractWitnesses(unittest.TestCase):
    def test_pinned_source_object_limit_matches_u64_bit_extent(self):
        maximum=((1<<64)-1)//8
        self.assertEqual(maximum,(1<<61)-1)
        for target in ('x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu'):
            args=[BIN/'clang','-target',target,'-std=c23','-ffreestanding','-nostdinc',
                  '-fsyntax-only',FIXTURES/'object-size-limit.c']
            run(args)
            negative=subprocess.run([str(arg) for arg in [*args,'-DEXPECT_REJECTION']],
                                    capture_output=True,text=True,check=False)
            self.assertNotEqual(negative.returncode,0)
            self.assertIn('array is too large',negative.stderr)

    def test_pinned_C_and_Cxx_function_type_equality_gap_is_separate_from_wchar(self):
        run([BIN/'clang','-target','x86_64-unknown-linux-gnu','-std=c++23',
             '-ffreestanding','-nostdinc','-fsyntax-only',FIXTURES/'cxx-linkage-types.cpp'])

    def test_C_provider_Cxx_C_linkage_consumer_keeps_overloads_distinct(self):
        for name, standard in [('c-linkage.c','c23'),('c-linkage.cpp','c++23')]:
            output=run([BIN/'clang','-target','x86_64-unknown-linux-gnu','-std='+standard,
                        '-ffreestanding','-nostdinc','-S','-emit-llvm',FIXTURES/name,'-o','-'])
            self.assertIn('@c_api(',output)
            self.assertIn('%struct.CRecord = type { i32, i64 }',output)
            if standard=='c++23':
                self.assertIn('@_Z7cpp_apii(',output)
                self.assertIn('@_Z7cpp_apil(',output)
        with tempfile.TemporaryDirectory(prefix='smir-C-linkage-') as directory:
            root=Path(directory)
            sdk=['-isysroot',run(['/usr/bin/xcrun','--show-sdk-path']).strip()] if sys.platform=='darwin' else []
            run([BIN/'clang','-std=c23',*sdk,'-c',FIXTURES/'c-linkage.c','-o',root/'provider.o'])
            run([BIN/'clang++','-std=c++23','-nostdlib++','-fno-exceptions','-fno-rtti',*sdk,
                 FIXTURES/'c-linkage.cpp',root/'provider.o','-o',root/'caller'])
            run([root/'caller'])

    def test_comparable_predefines_and_personality_independence(self):
        output = run([BIN / 'clang', '-target','x86_64-unknown-linux-gnu',
                      '-mlong-double-128','-std=c23','-ffreestanding','-nostdinc',
                      '-dM','-E','-x','c','/dev/null'])
        observed = {}
        for line in output.splitlines():
            if line.startswith('#define '):
                name, _, value = line[len('#define '):].partition(' ')
                observed[name] = value
        compared = 0
        for name, value in frontend_contract.ABI_MACROS.items():
            if name.startswith(('__SMIR', '__GCC_ATOMIC_', '__CLANG_ATOMIC_')) or name == '__BITINT_MAXWIDTH__':
                continue
            with self.subTest(name=name):
                self.assertEqual(observed.get(name), value)
                compared += 1
        self.assertGreater(compared,90)
        config=frontend_contract.configuration()
        function_addresses = config['function_addresses']
        self.assertEqual(function_addresses['execution_kind'], 'code_address')
        self.assertEqual((function_addresses['size'], function_addresses['alignment']), (8, 8))
        self.assertFalse(function_addresses['signature_parameter'])
        self.assertEqual(function_addresses['source_hash'], 'SMIR-NOMINAL-SHAPE-V3')
        self.assertEqual(config['record_layout']['abi_payload_revision'], 3)
        self.assertEqual(bytes.fromhex(config['record_layout']['nominal_hash_domain_hex']),
                         b'SMIR-NOMINAL-SHAPE-V3\0')
        self.assertEqual(config['record_layout']['nominal_hash_domain'].encode('ascii'),
                         b'SMIR-NOMINAL-SHAPE-V3\0')
        self.assertEqual(config['storage']['bitint'].split(',')[0], 'SSA iN')
        target=json.loads((PACKAGE/'target.json').read_text())
        self.assertNotIn('blockers',target)
        self.assertIn('SMIR frontend and emitter',target['implementation_missing'])

    def test_pinned_site_choices_are_concrete_contract(self):
        root=Path(__file__).resolve().parents[2]
        site=json.loads((root/'docs/specifications/smir/portable/schema/abi/site.json').read_text())
        self.assertEqual(site['cmake']['LIBCXX_ABI_VERSION'],'1')
        self.assertEqual(site['cmake']['LIBCXX_HAS_EXTERNAL_THREAD_API'],'ON')
        self.assertEqual(site['cmake']['LIBCXX_ABI_FORCE_ITANIUM'],'ON')
        self.assertEqual(site['cmake']['LIBCXX_ABI_FORCE_MICROSOFT'],'OFF')
        self.assertFalse(site['native_host_linking'])
        self.assertIn('logical',site['unwinder_backend'])


class CandidateBindingWitnesses(unittest.TestCase):
    def test_compiler_private_opaque_and_nested_transport_keeps_logical_kind(self):
        import primitive_transport as primitive
        journal={'kind':'journal'}
        for name in ('exception','journal','stack_mark','fenv'):
            self.assertEqual(primitive.opaque_carrier('smir.'+name)['kind'],name)
        for name,params in [('smir.arbitrary',[]),('smir.journal',[1]),('spirv.Image',[])]:
            with self.assertRaises(ContractError):
                primitive.opaque_carrier(name,params)
        with self.assertRaisesRegex(ContractError,'OPAQUE-FREEZE'):
            primitive.freeze_carrier('journal')
        self.assertEqual(primitive.freeze_carrier('journal',proven_concrete_valid=True),'copy_valid_handle')
        self.assertIn('default_snapshot',primitive.freeze_carrier('fenv'))
        self.assertEqual(primitive.signature([], [journal])['result'],'target("smir.journal")')
        nested={'kind':'struct','fields':[{'kind':'int','bits':13},{'kind':'data_ptr'}]}
        one=primitive.signature([], [nested])
        two=primitive.signature([], [{'kind':'int','bits':13},{'kind':'data_ptr'}])
        self.assertEqual(one['result'],two['result'])
        self.assertNotEqual(one['logical_results'],two['logical_results'])
        self.assertEqual(primitive.llvm_type({'kind':'raw','bits':65}),'b65')
        self.assertEqual(primitive.llvm_type({'kind':'array','count':1<<32,
                         'element':{'kind':'raw','bits':8}}),'[4294967296 x b8]')
        with self.assertRaises(ContractError):
            primitive.llvm_type({'kind':'function'})
        output=run([BIN/'clang','-x','ir','-O1','-S','-emit-llvm',FIXTURES/'opaque-transport.ll','-o','-'])
        self.assertIn('target("smir.journal")',output)
        self.assertNotIn('ptrtoint',output)

    def test_primitive_multiresult_transport_is_not_source_record_sret(self):
        import primitive_transport as primitive
        plan=primitive.signature(['u64','u64','u32'],['u32','data_ptr'])
        self.assertEqual(plan['result'],'{ i32, ptr }')
        self.assertFalse(plan['indirect_sret'])
        self.assertIsNone(plan['source_abi'])
        self.assertEqual(primitive.signature([],[])['result'],'void')
        self.assertEqual(primitive.signature([],['u32'])['result'],'i32')
        poison={'state':'poison'}
        pointer={'state':'concrete','issued_object':7,'generation':13}
        pair=primitive.pack_results([poison,pointer],2)
        self.assertIs(primitive.extract_result(pair,2,0),poison)
        self.assertIs(primitive.extract_result(pair,2,1),pointer)
        self.assertEqual(primitive.signature([],['code_ptr'])['result'],'ptr')
        self.assertNotEqual(primitive.signature([],['code_ptr'])['logical_results'],
                            primitive.signature([],['data_ptr'])['logical_results'])
        with self.assertRaises(ContractError):
            primitive.pack_results([pointer],2)
        with self.assertRaises(ContractError):
            primitive.declaration('ordinary_source_C_function',[],[])

    def test_pinned_LLVM_primitive_aggregate_result_has_exact_fields(self):
        import primitive_transport as primitive
        expected=primitive.declaration('__rax_primitive_memory_map',['u64','u64','u32'],['u32','data_ptr'])
        self.assertIn(expected,(FIXTURES/'primitive-transport.ll').read_text())
        output=run([BIN/'clang','-x','ir','-O1','-S','-emit-llvm',FIXTURES/'primitive-transport.ll','-o','-'])
        self.assertIn('call { i32, ptr } @__rax_primitive_memory_map',output)
        self.assertIn('extractvalue { i32, ptr }',output)
        self.assertNotIn('sret(',output)

    def test_actual_vector_libm_instantiation_preserves_one_source_transaction_shape(self):
        _, records=bindings.catalog()
        f64={'kind':'float','format':'binary64'}
        vector={'kind':'vector','count':4,'element':f64}
        integers={'kind':'vector','count':4,'element':{'kind':'int','bits':65}}
        result=bindings.instantiate(records['fp_sin'],[vector],contract='constrained')
        self.assertEqual(result['params'],[vector])
        self.assertEqual(result['results'],[vector])
        ldexp=bindings.instantiate(records['fp_ldexp'],[vector,integers])
        self.assertEqual(ldexp['params'],[vector,integers])
        with self.assertRaisesRegex(ContractError,'EXPONENT_LANES'):
            bindings.instantiate(records['fp_ldexp'],[vector,{'kind':'int','bits':32}])
        wrong=copy.deepcopy(integers)
        wrong['count']=3
        with self.assertRaisesRegex(ContractError,'EXPONENT_LANES'):
            bindings.instantiate(records['fp_ldexp'],[vector,wrong])
        with self.assertRaises(ContractError):
            bindings.instantiate(records['fp_sin'],[integers])
        with self.assertRaisesRegex(ContractError,'SOURCE_LIBM_SCALAR'):
            bindings.instantiate(records['fp_sin'],[vector],contract='c_fenv')
        with self.assertRaises(ContractError):
            bindings.instantiate(records['fp_lrint'],[vector,{'kind':'int','bits':32}])
        self.assertEqual(bindings.instantiate(records['fp_powi'],[vector,{'kind':'int','bits':32}])['results'],[vector])

    def test_R018_draft_selects_exact_storage_binding_and_anonymous_physical_layout(self):
        # Local reference against explicitly named R018 revision3. Shared owner
        # catalog adoption is checked separately by namespace_plan/core_bindings.
        _, records=bindings.catalog()
        memory=copy.deepcopy(records['memory_load'])
        memory['abi_namespace']={c:'optional_storage_binding' for c in memory['contracts']}
        memory['target_namespace']={c:'storage_layout' for c in memory['contracts']}
        fp=copy.deepcopy(records['atomic_fetch_fadd'])
        fp['abi_namespace']={'llvm_default':'optional_storage_binding',
                             'constrained':'optional_storage_binding','c_fenv':'storage_binding'}
        fp['target_namespace']={c:'storage_layout' for c in fp['contracts']}
        reference={'module':{'kind':'self'},'id':7}
        layout={'type':{'kind':'int','bits':13},'size':2,'alignment':1,'access_bytes':2}
        binding={'execution_layout':reference,'view_offset_bits':0,'view_width_bits':16}
        tables={'storage_binding':{7:binding},'storage_layout':{7:layout},
                'signature':{7:{'wrong_table':True}}}

        def resolve(namespace, ref):
            canonical.require(ref['id'] in tables[namespace], 'WRONG_PHYSICAL_TABLE')
            return tables[namespace][ref['id']]

        anonymous=bindings.bind_context(memory,'ordinary',None,reference,resolve)
        self.assertIsNone(anonymous['abi'])
        self.assertEqual(anonymous['target']['access_bytes'],2)
        selected=bindings.bind_context(memory,'volatile',reference,reference,resolve)
        self.assertEqual(selected['abi'],binding)
        for contract in ('llvm_default','constrained'):
            self.assertIsNone(bindings.bind_context(fp,contract,None,reference,resolve)['abi'])
        with self.assertRaisesRegex(ContractError,'REQUIRED_ABI'):
            bindings.bind_context(fp,'c_fenv',None,reference,resolve)
        with self.assertRaisesRegex(ContractError,'REQUIRED_TARGET'):
            bindings.bind_context(memory,'ordinary',None,None,resolve)
        del tables['storage_layout'][7]
        with self.assertRaisesRegex(ContractError,'WRONG_PHYSICAL_TABLE'):
            bindings.bind_context(memory,'ordinary',None,reference,resolve)

    def test_helper_namespaces_never_fall_back_to_same_integer_other_table(self):
        _, records=bindings.catalog()
        ref={'module':{'kind':'self'},'id':7}
        tables={name:{7:{'admitted_namespace':name}} for name in
                ('nominal','signature','bridge','journal','recipe','tls')}

        def resolve(namespace,reference):
            canonical.require(reference['id'] in tables[namespace], 'WRONG_TABLE')
            return tables[namespace][reference['id']]

        for contract, expected in [('portable','signature'),('foreign','bridge'),('callback','bridge')]:
            result=bindings.bind_context(records['call_dispatch'],contract,ref,None,resolve)
            self.assertEqual(result['abi']['admitted_namespace'],expected)
        del tables['signature'][7]
        with self.assertRaisesRegex(ContractError,'WRONG_TABLE'):
            bindings.bind_context(records['call_dispatch'],'portable',ref,None,resolve)
        self.assertEqual(bindings.bind_context(records['call_dispatch'],'foreign',ref,None,resolve)['abi'],
                         {'admitted_namespace':'bridge'})
        tables['signature'][7]={'admitted_namespace':'signature'}
        packed=bindings.bind_context(records['varargs_pack'],'default',ref,ref,resolve)
        self.assertEqual(packed['abi']['admitted_namespace'],'signature')
        self.assertEqual(packed['target']['admitted_namespace'],'recipe')
        with self.assertRaisesRegex(ContractError,'UNUSED_ABI'):
            bindings.bind_context(records['eh_raise'],'default',ref,None,resolve)
        with self.assertRaisesRegex(ContractError,'REQUIRED_TARGET'):
            bindings.bind_context(records['tls_initialize'],'default',None,None,resolve)
        malformed=copy.deepcopy(records['call_dispatch'])
        del malformed['abi_namespace']['portable']
        with self.assertRaisesRegex(ContractError,'NAMESPACE_MAP'):
            bindings.namespace_plan(malformed,'portable')

    def test_catalog_protocol_digest_is_not_artifact_hash(self):
        value, _ = bindings.catalog()
        data = json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode('ascii')
        expected = hashlib.sha256(b'SMIR-HELPERS-V1\0' + data).hexdigest()
        self.assertEqual(bindings.catalog_digest(value),expected)
        changed=copy.deepcopy(value)
        changed['policies']['llvm_contract_probe']='semantic change'
        self.assertNotEqual(bindings.catalog_digest(changed),expected)
        for text in ('{"a":1,"a":2}','{"value":NaN}','{"value":Infinity}'):
            with self.subTest(text=text), self.assertRaises(ContractError):
                bindings.strict_json(text)
        with self.assertRaises(ContractError):
            bindings.catalog_digest({'digest':'self'})

    def test_core_record_bindings_and_explicit_helper_names(self):
        binding=bindings.core_bindings()
        self.assertEqual(set(binding['core']),set(contracts.RECIPES))
        self.assertTrue(all(not r['helper_import_required'] for r in binding['core'].values()))

    def test_instantiated_signatures_preserve_poison_and_width(self):
        _, records=bindings.catalog()
        wide={'kind':'int','bits':65535}
        signature=bindings.instantiate(records['atomic_cmpxchg'],[wide])
        self.assertEqual(signature['results'],[wide,{'builtin':'i1'}])
        self.assertFalse(signature['result_noundef'][0])
        with self.assertRaises(ContractError):
            bindings.instantiate(records['fp_add'],[wide])
        with self.assertRaises(ContractError):
            bindings.instantiate(records['atomic_cmpxchg'],[])
        f32={'kind':'float','format':'binary32'}
        f128={'kind':'float','format':'binary128'}
        converted=bindings.instantiate(records['fp_convert'],[f32,f128])
        self.assertEqual(converted['params'],[f32])
        self.assertEqual(converted['results'],[f128])

    def test_pinned_actual_atomic_flag_resource_header(self):
        llvm=BIN.parents[1]
        output=run([BIN/'clang','-target','x86_64-unknown-linux-gnu','-std=c23',
                    '-ffreestanding','-nostdinc','-isystem',llvm/'clang/lib/Headers',
                    '-S','-emit-llvm',FIXTURES/'atomic-flag.c','-o','-'])
        self.assertIn('atomicrmw xchg',output)
        self.assertIn('store atomic i8',output)
        self.assertIn('acq_rel, align 1',output)
        self.assertIn('release, align 1',output)


class FloatingLoweringWitnesses(unittest.TestCase):
    def test_target_integer_environment_words_and_FLT_ROUNDS_are_distinct(self):
        import environment_words as env
        for rounding,bits in env.ROUND.items():
            for flags in range(64):
                encoded=env.encode(rounding,flags)
                self.assertEqual(encoded,bits|flags)
                self.assertEqual(env.decode(encoded),(rounding,flags))
                self.assertEqual(env.restore(('nearest_even',flags),bits,mode=True),(rounding,flags))
            self.assertEqual(env.set_rounding(env.get_rounding(rounding)),rounding)
        self.assertEqual(env.get_rounding('toward_zero'),0)
        self.assertEqual(env.ROUND['toward_zero'],0xC00)
        state=('upward',63)
        for bad in (1 << 63,0x40,0x1000):
            with self.assertRaises(ContractError):
                env.restore(state,bad)
            self.assertEqual(state,('upward',63))
        with self.assertRaises(ContractError):
            env.decode(1,mode=True)
        with self.assertRaisesRegex(ContractError,'ENV-WIDTH'):
            env.decode(0,width=32)
        with self.assertRaisesRegex(ContractError,'AMBIENT-ROUNDING'):
            env.set_rounding(4)

    def test_pinned_environment_intrinsics_keep_explicit_integer_width(self):
        output=run([BIN/'clang','-x','ir','-O1','-S','-emit-llvm',FIXTURES/'environment.ll','-o','-'])
        for name in ('get.fpenv.i64','set.fpenv.i64','get.fpmode.i64','set.fpmode.i64','get.rounding','set.rounding'):
            self.assertIn('@llvm.'+name,output)

    def test_integer_round_intrinsics_freeze_invalid_results(self):
        self.assertEqual(to_integer(Fraction(255,2),8,operation='lround')[0].kind,'concrete')
        self.assertEqual(to_integer(Fraction(255,2),8,operation='lround')[0].bits,0)
        self.assertEqual(to_integer(Fraction(255,2),8,operation='fptosi')[0].bits,127)
        self.assertEqual(to_integer(Fraction(128),8,operation='fptosi')[0].kind,'poison')
        for operation in ('lrint','llrint','lround','llround'):
            for value in ('nan','+inf','-inf',Fraction(1000)):
                with self.subTest(operation=operation,value=value):
                    result,flags=to_integer(value,8,operation=operation)
                    self.assertEqual(result.kind,'concrete')
                    self.assertEqual(result.bits,0)
                    self.assertEqual(flags,{'invalid'})

    def test_rounding_and_saturating_boundaries(self):
        for rounding,expected in [('nearest_even',254),('nearest_away',254),('downward',254),('upward',255),('toward_zero',255)]:
            actual,_=to_integer(Fraction(-3,2),8,operation='lrint',rounding=rounding)
            self.assertEqual(actual.bits,expected)
        self.assertEqual(to_integer(Fraction(-1,2),8,signed=False,operation='fptoui')[0].bits,0)
        self.assertEqual(to_integer('nan',8,operation='saturating')[0].bits,0)
        self.assertEqual(to_integer('+inf',8,operation='saturating')[0].bits,127)
        self.assertEqual(to_integer('-inf',8,operation='saturating')[0].bits,128)

    def test_fpclass_all_ten_classes_no_host_nan_arithmetic(self):
        for bits,mask in [(0x7f800001,1),(0x7fc00001,2),(0xff800000,4),
                          (0xbf800000,8),(0x80000001,16),(0x80000000,32),
                          (0,64),(1,128),(0x3f800000,256),(0x7f800000,512)]:
            self.assertTrue(fpclass(bits,8,23,mask))
            self.assertFalse(fpclass(bits,8,23,0x3ff^mask))


class UpstreamBehaviorWitnesses(unittest.TestCase):
    def test_actual_pinned_fesetexceptflag_clears_unselected_flags(self):
        # Compile actual pinned source, replacing hardware set/clear primitives
        # by controlled exact bitmask primitives. This is NOT native libc fenv.
        llvm=BIN.parents[1]
        with tempfile.TemporaryDirectory(prefix='smir-upstream-fenv-') as directory:
            root=Path(directory)
            headers={
                'hdr/types/fexcept_t.h':'#pragma once\nusing fexcept_t=unsigned int;\n',
                'src/fenv/fesetexceptflag.h':'#include "hdr/types/fexcept_t.h"\nnamespace oracle { int fesetexceptflag(const fexcept_t*,int); }\n',
                'src/__support/common.h':'#define LLVM_LIBC_FUNCTION(R,N,A) R N A\n',
                'src/__support/macros/config.h':'#define LIBC_NAMESPACE_DECL oracle\n',
                'src/__support/FPUtil/FEnvImpl.h':
                    '#define FE_ALL_EXCEPT 63\nnamespace oracle { extern int shadow_flags; namespace fputil {\n'
                    'inline int clear_except(int bits) { shadow_flags &= ~bits; return 0; }\n'
                    'inline int set_except(int bits) { shadow_flags |= bits; return 0; }\n}}\n',
            }
            for name,contents in headers.items():
                path=root/name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(contents)
            driver=root/'main.cpp'
            driver.write_text(
                '#include "src/fenv/fesetexceptflag.h"\nnamespace oracle { int shadow_flags; }\n'
                'int main() {\n'
                'const int initial[3]={1,63,32}; const int desired[3]={4,0,4};\n'
                'const int selected[3]={4,0,4}; const int actual[3]={4,0,4};\n'
                'const int project[3]={5,63,36};\n'
                'for(int i=0;i<3;++i) { oracle::shadow_flags=initial[i];\n'
                'fexcept_t flags=desired[i]; if(oracle::fesetexceptflag(&flags,selected[i])!=0) return 1;\n'
                'if(oracle::shadow_flags!=actual[i] || oracle::shadow_flags==project[i]) return 2; }\n'
                'return 0; }\n')
            binary=root/'source-probe'
            sdk = ['-isysroot',run(['/usr/bin/xcrun','--show-sdk-path']).strip()] if sys.platform == 'darwin' else []
            run([BIN/'clang++','-std=c++23','-nostdinc','-nostdinc++','-nostdlib++',
                 '-fno-exceptions','-fno-rtti',*sdk,'-I',root,
                 llvm/'libc/src/fenv/fesetexceptflag.cpp',driver,'-o',binary])
            run([binary])


class PinnedOptimizerGapWitnesses(unittest.TestCase):
    def test_constrained_power_uses_pinned_i32_and_preserves_strict_metadata(self):
        output=run([BIN/'clang','-x','ir','-O1','-S','-emit-llvm',FIXTURES/'constrained-power.ll','-o','-'])
        self.assertIn('constrained.powi.f64',output)
        self.assertIn('i32 %exponent',output)
        self.assertIn('metadata !"round.dynamic", metadata !"fpexcept.strict"',output)

    def test_expanded_power_width_one_and_above_sixty_four(self):
        # Actual LLVM parsing, optimization and native host execution. Width1
        # avoids a shift by its own width; width65 retains its bit64 magnitude.
        function=expanded_powi(1)+expanded_powi(65)
        function+='''define i32 @main() {
  %minusone = call double @portable_powi1(double 2.0, i1 1)
  %half = fcmp oeq double %minusone, 0.5
  %zero = call double @portable_powi1(double 0.0, i1 0)
  %one = fcmp oeq double %zero, 1.0
  %wide = call double @portable_powi65(double -1.0, i65 18446744073709551615)
  %odd = fcmp oeq double %wide, -1.0
  %minimum = call double @portable_powi65(double -1.0, i65 -18446744073709551616)
  %even = fcmp oeq double %minimum, 1.0
  %a = and i1 %half, %one
  %b = and i1 %odd, %even
  %ok = and i1 %a, %b
  %status = select i1 %ok, i32 0, i32 1
  ret i32 %status
}
'''
        self.assertIn('freeze i65 %input',function)
        self.assertNotIn('lshr i1 %remaining, 1',function)
        with tempfile.TemporaryDirectory(prefix='smir-powi-width-') as directory:
            source=Path(directory)/'width.ll'
            source.write_text(function)
            binary=Path(directory)/'width'
            sdk=['-isysroot',run(['/usr/bin/xcrun','--show-sdk-path']).strip()] if sys.platform=='darwin' else []
            run([BIN/'clang','-x','ir','-O1',*sdk,source,'-o',binary])
            run([binary])

    def test_wide_powi_source_gap_and_narrow_frexp_are_observed(self):
        output=run([BIN/'clang','-x','ir','-O1','-S','-emit-llvm',FIXTURES/'overloaded-math.ll','-o','-'])
        # This deliberately records the pinned bug, not target correctness.
        self.assertRegex(output,r'define[^@]*@pow_wide\([^}]*ret double 1.000000e\+00')
        self.assertRegex(output,r'define[^@]*@frexp_narrow\([^}]*ret i8 -27')

    def test_expanded_power_preserves_wide_exponent_before_optimizer(self):
        with tempfile.TemporaryDirectory(prefix='smir-powi-witness-') as directory:
            root=Path(directory)
            source=root/'power.ll'
            source.write_text(expanded_powi64())
            optimized=run([BIN/'clang','-x','ir','-O1','-S','-emit-llvm',source,'-o','-'])
            self.assertNotIn('@llvm.powi',optimized)
            binary=root/'power'
            sdk=['-isysroot',run(['/usr/bin/xcrun','--show-sdk-path']).strip()] if sys.platform=='darwin' else []
            run([BIN/'clang','-x','ir','-O1',*sdk,source,'-o',binary])
            run([binary])

    def test_math_bindings_all_families_resolve_and_power_requires_preoptimization(self):
        plans=bindings.math_bindings()
        self.assertEqual(set(plans),contracts.MATH)
        self.assertIn('mandatory legalize before',plans['powi']['precondition'])
        self.assertEqual(plans['sincospi']['helpers'],['fp_sincospi'])
        self.assertEqual(plans['lrint']['helpers'],['fp_lrint'])
        constrained=bindings.constrained_math_bindings()
        self.assertEqual(len(constrained),49)
        self.assertTrue(constrained['fcmps']['signaling'])
        self.assertFalse(constrained['fcmp']['signaling'])
        self.assertEqual(constrained['powi']['exponent_bits'],32)
        self.assertEqual(constrained['lround']['helpers'],['fp_lround'])
        self.assertFalse(constrained['lrint']['vector'])


class TypeShapeWitnesses(unittest.TestCase):
    def test_nominal_quotient_matches_independent_pair_elimination(self):
        from shape import shape_digest
        root=Path(__file__).resolve().parents[2]
        script='''import sys,json
sys.path.insert(0,sys.argv[1])
import graph_identity
from nominal import NominalGraph,ref
document=json.load(open(sys.argv[2]))
original=graph_identity.canonical_quotient
captured=[]
def observe(labels,edges,root,*,budget=None):
    ids={node:i for i,node in enumerate(labels)}
    captured.append({'root':ids[root], 'graph':[
        {'id':ids[node], 'label':labels[node], 'children':[ids[c] for c in edges[node]]}
        for node in labels]})
    return original(labels,edges,root,budget=budget)
graph_identity.canonical_quotient=observe
graph=NominalGraph(document,'independent_witness')
digests=[graph.fingerprint(ref(identifier)) for identifier in (3,4)]
print(json.dumps({'digests':digests,'captured':captured}))
'''
        process=subprocess.run([sys.executable,'-B','-c',script,str(root/'tools/smir-abi'),
            str(root/'docs/specifications/smir/portable/conformance/abi/candidate/complete.json')],
            text=True,capture_output=True,check=True)
        output=json.loads(process.stdout)
        for digest, captured in zip(output['digests'],output['captured']):
            graph={row['id']:{'label':row['label'],'children':row['children']} for row in captured['graph']}
            self.assertEqual(digest,shape_digest(graph,captured['root'],domain=b'SMIR-NOMINAL-SHAPE-V3\0'))

    def test_independent_pair_relation_matches_partition_refinement(self):
        from shape import execution_view, shape_digest
        ref = lambda i: {'module':{'kind':'self'},'id':i}
        function = lambda i,p,r: {'kind':'function','id':i,'params':p,'results':r,
            'param_noundef':[False]*len(p),'result_noundef':[False]*len(r),'cc':'portable','variadic':False}
        samples = [
            ([{'kind':'int','id':1,'bits':8}],1),
            ([{'kind':'int','id':7,'bits':8},{'kind':'int','id':10,'bits':8},
              {'kind':'struct','id':20,'fields':[ref(7),ref(10)]}],20),
            ([{'kind':'int','id':1,'bits':8},{'kind':'struct','id':2,'fields':[ref(1),ref(1)]}],2),
            ([{'kind':'int','id':1,'bits':32},function(2,[ref(3)],[ref(1)]),
              {'kind':'code_ptr','id':3,'signature':ref(2)}],2),
        ]
        script = '''import sys,json
sys.path.insert(0,sys.argv[1])
from candidate.type_system import Types,ref
requests=json.load(sys.stdin)
print(json.dumps([Types({'payload_revision':2,'types':records}).digest(ref(root)) for records,root in requests]))
'''
        execution = Path(__file__).resolve().parents[2]/'tools/smir-format/execution'
        process = subprocess.run([sys.executable,'-B','-c',script,str(execution)],
                                 input=json.dumps(samples),text=True,capture_output=True,check=True)
        expected=json.loads(process.stdout)
        actual=[shape_digest(execution_view(records),root) for records,root in samples]
        self.assertEqual(actual,expected)
        self.assertEqual(actual[1],actual[2])

    def test_graph_sharing_recursion_order_and_attributes(self):
        from shape import shape_digest
        first={1:{'label':{'kind':'int','bits':8},'children':[]},
               2:{'label':{'kind':'struct'},'children':[1,1]}}
        shared={10:{'label':{'kind':'int','bits':8},'children':[]},
                11:{'label':{'kind':'int','bits':8},'children':[]},
                20:{'label':{'kind':'struct'},'children':[10,11]}}
        self.assertEqual(shape_digest(first,2),shape_digest(shared,20))
        cycle={1:{'label':{'kind':'code_ptr'},'children':[2]},
               2:{'label':{'kind':'function','noundef':[False]},'children':[1]}}
        alpha={90:{'label':{'kind':'code_ptr'},'children':[17]},
               17:{'label':{'kind':'function','noundef':[False]},'children':[90]}}
        self.assertEqual(shape_digest(cycle,1),shape_digest(alpha,90))
        alpha[17]['label']['noundef']=[True]
        self.assertNotEqual(shape_digest(cycle,1),shape_digest(alpha,90))
        order={1:{'label':{'kind':'int','bits':8},'children':[]},
               2:{'label':{'kind':'int','bits':32},'children':[]},
               3:{'label':{'kind':'struct'},'children':[1,2]}}
        swapped=copy.deepcopy(order)
        swapped[3]['children'].reverse()
        self.assertNotEqual(shape_digest(order,3),shape_digest(swapped,3))
