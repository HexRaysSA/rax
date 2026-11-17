"""Actual admitted candidate records, independent comparison and rejection."""
import copy
import json
import re
from pathlib import Path
import subprocess
import sys
import unittest

import canonical
import deployment
from test_closure import cycle, groups
from test_contract import BIN, FIXTURES, run

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'docs/specifications/smir/portable/conformance/llvm/candidate-comparison.json'


def witness(document, success=True):
    process = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('projection_witness.py'))],
                             input=json.dumps(document), text=True, capture_output=True)
    if success:
        if process.returncode:
            raise AssertionError(process.stderr)
        return json.loads(process.stdout)
    if process.returncode == 0:
        raise AssertionError('Unadmitted fixture accepted')
    return process.stderr


def alpha(document):
    result = copy.deepcopy(document)
    # Deliberately non-monotone renaming changes CFG record order. Constants
    # whose numerical values equal old IDs remain untouched.
    tm = {1: 51, 2: 19, 3: 70}
    bm = {10: 42, 20: 6, 30: 90, 40: 1}
    vm = {100: 900, 101: 2, 102: 8, 200: 3, 201: 999, 202: 4}
    def ref(r):
        r['id'] = tm[r['id']]
    def decl(d):
        d['id'] = vm[d['id']]
        ref(d['type'])
    for t in result['types']['types']:
        t['id'] = tm[t['id']]
        for r in t.get('params', []) + t.get('results', []):
            ref(r)
    result['types']['types'].sort(key=lambda t: t['id'])
    f = result['functions']['functions'][0]
    f['id'] = 93
    ref(f['signature'])
    for d in f['params']:
        decl(d)
    f['entry'] = bm[f['entry']]
    for b in f['blocks']:
        b['id'] = bm[b['id']]
        for phi in b['phis']:
            decl(phi['result'])
            for incoming in phi['incoming']:
                incoming['predecessor'] = bm[incoming['predecessor']]
                incoming['value'] = vm[incoming['value']]
            phi['incoming'].sort(key=lambda x:x['predecessor'])
        for o in b['ops']:
            for d in o['results']:
                decl(d)
            o['operands'] = [vm[x] for x in o['operands']]
        t = b['term']
        for k in ('target','true','false'):
            if k in t:
                t[k] = bm[t[k]]
        if 'condition' in t:
            t['condition'] = vm[t['condition']]
        if 'values' in t:
            t['values'] = [vm[x] for x in t['values']]
    f['blocks'].sort(key=lambda b:b['id'])
    eh = result['exceptions']['functions'][0]
    eh['function'] = f['id']
    eh['regions'][0]['id'] = 139
    eh['regions'][0]['blocks'] = sorted(bm[x] for x in eh['regions'][0]['blocks'])
    return result


class ActualProjectionTests(unittest.TestCase):
    def setUp(self):
        self.source = json.loads(FIXTURE.read_text())

    def test_actual_sem_admission_and_independent_runtime_normalization(self):
        output = witness(self.source)
        self.assertTrue(output['independent_equal'])
        self.assertEqual(len(json.loads(output['canonical'])['blocks']), 4)

    def test_actual_alpha_types_cfg_ssa_phi_and_region(self):
        a, b = witness(self.source), witness(alpha(self.source))
        self.assertEqual(a['canonical'], b['canonical'])

    def test_constant_and_function_semantics_are_not_renamed(self):
        original = witness(self.source)['canonical']
        changed = copy.deepcopy(self.source)
        changed['functions']['functions'][0]['blocks'][0]['ops'][1]['literal']['value'] = '0a000000'
        self.assertNotEqual(original, witness(changed)['canonical'])
        changed = copy.deepcopy(self.source)
        changed['functions']['functions'][0]['escape'] = 'terminate'
        self.assertNotEqual(original, witness(changed)['canonical'])
        changed = copy.deepcopy(self.source)
        changed['exceptions']['functions'][0]['regions'][0]['escape'] = 'terminate'
        self.assertNotEqual(original, witness(changed)['canonical'])

    def test_invalid_ssa_and_unknown_fields_reject_before_comparison(self):
        changed = copy.deepcopy(self.source)
        changed['functions']['functions'][0]['blocks'][2]['ops'][0]['operands'][0] = 123456
        self.assertIn('ssa_reference', witness(changed, False))
        changed = copy.deepcopy(self.source)
        changed['functions']['functions'][0]['invented'] = 1
        self.assertIn('shape', witness(changed, False))

    def test_public_identity_crosses_deployment_families_local_namespace_does_not(self):
        d = cycle()[0][0]['exports'][0]
        self.assertEqual(deployment.symbol_identity('familyA', d), deployment.symbol_identity('familyB', d))
        private = dict(d, namespace='smir.unit.translation_unit_A')
        other = dict(private, namespace='smir.unit.translation_unit_B')
        self.assertNotEqual(deployment.symbol_identity('familyA', private), deployment.symbol_identity('familyA', other))

    def test_comdat_optimization_may_change_member_set_without_merging(self):
        for kind in ('any', 'largest', 'samesize'):
            g = groups(kind)
            # Equal key extents for SameSize; helper belongs only to one input.
            g[1]['members'][0]['body'] = g[0]['members'][0]['body']
            g[1]['members'][0]['extent'] = g[0]['members'][0]['extent']
            helper = dict(g[0]['members'][0], symbol='private_helper')
            g[0]['members'].append(helper)
            winners = canonical.select_comdat(g)
            self.assertEqual(len(winners), 1)
            self.assertIn(winners[0], (2,9))
        g[0]['selection'] = g[1]['selection'] = 'exactmatch'
        with self.assertRaisesRegex(ValueError, 'COMDAT_MEMBERS_MISMATCH'):
            canonical.select_comdat(g)


class CompleteCallPlanTests(unittest.TestCase):
    def test_hidden_owner_mismatch_with_equal_execution_and_nominal_rejects(self):
        modules, manifest = cycle()
        modules[0]['dependencies'][0]['declarations'][0]['abi_signature'] = '3' * 64
        with self.assertRaisesRegex(ValueError, 'LINK_SOURCE_CALL_PLAN'):
            deployment.bind_deployment(modules, manifest)

    def test_source_call_plan_missing_or_fabricated_rejects(self):
        modules, manifest = cycle()
        modules[0]['exports'][0]['abi_signature'] = None
        with self.assertRaisesRegex(ValueError, 'LINK_CALL_PLAN_PRESENCE'):
            deployment.bind_deployment(modules, manifest)
        modules, manifest = cycle()
        modules[0]['exports'][0]['source_linkage'] = 'none'
        with self.assertRaisesRegex(ValueError, 'LINK_CALL_PLAN_PRESENCE'):
            deployment.bind_deployment(modules, manifest)


class ExceptionSourceWitnesses(unittest.TestCase):
    def test_actual_source_allocation_construction_abort_and_catch(self):
        output = run([BIN/'clang++', '-target', 'x86_64-unknown-linux-gnu', '-std=c++23',
                      '-O0', '-S', '-emit-llvm', FIXTURES/'exception-allocation.cpp', '-o', '-'])
        allocation = output.index('call ptr @__cxa_allocate_exception')
        constructor = output.index('invoke void @_ZN7PayloadC1Ei')
        throwing = output.index('call void @__cxa_throw')
        self.assertLess(allocation, constructor)
        self.assertLess(constructor, throwing)
        for pattern in ('call void @__cxa_free_exception', 'landingpad { ptr, i32 }',
                        'call ptr @__cxa_begin_catch', 'call void @__cxa_end_catch'):
            self.assertIn(pattern, output)

    def test_pinned_ir_verifier_accepts_opaque_landingpad_result_without_storage(self):
        output = run([BIN/'clang', '-target', 'x86_64-unknown-linux-gnu', '-x', 'ir',
                      '-O0', '-S', '-emit-llvm', FIXTURES/'opaque-landingpad.ll', '-o', '-'])
        self.assertIn('landingpad { target("smir.exception"), i32 }', output)
        self.assertIn('ret target("smir.exception")', output)
        self.assertNotIn('alloca', output)


class CatchCopySourceWitnesses(unittest.TestCase):
    def test_source_catch_destination_dominates_protected_invoke_and_copy_precedes_begin(self):
        output=run([BIN/'clang++','-target','x86_64-unknown-linux-gnu','-std=c++23',
            '-O0','-S','-emit-llvm',FIXTURES/'exception-allocation.cpp','-o','-'])
        body=re.search(r'define[^@]+@_Z10catch_copyv\(\)[^{]*\{(.*?)^}',output,re.M|re.S)
        self.assertIsNotNone(body)
        text=body.group(1)
        destination=re.search(r'(%[0-9]+) = alloca %struct.Payload',text)
        self.assertIsNotNone(destination)
        self.assertLess(destination.start(),text.index('invoke void @_Z24allocate_construct_throwi'))
        self.assertLess(text.index('call ptr @__cxa_get_exception_ptr'),
                        text.index('invoke void @_ZN7PayloadC1ERKS_'))
        self.assertLess(text.index('invoke void @_ZN7PayloadC1ERKS_'),
                        text.index('call ptr @__cxa_begin_catch'))
        self.assertRegex(text,r'PayloadC1ERKS_\(ptr[^,]*'+re.escape(destination.group(1))+r',')


class TerminationContextHostWitnesses(unittest.TestCase):
    def test_implicit_catch_current_owner_and_uncaught_count_on_host(self):
        from termination_witness import observe
        result=observe(BIN/'clang++',FIXTURES/'termination-context.cpp')
        self.assertTrue(result['inputs_stable'])
        self.assertEqual(len(result['cases']),7)
        self.assertTrue(result['headers_before'])


class DynamicRethrowSourceWitnesses(unittest.TestCase):
    def test_rethrow_outside_lexical_catch_has_no_exception_operand(self):
        output=run([BIN/'clang++','-target','x86_64-unknown-linux-gnu','-std=c++23',
            '-O0','-S','-emit-llvm',FIXTURES/'dynamic-rethrow.cpp','-o','-'])
        body=re.search(r'define[^@]+@_Z15dynamic_rethrowv\(\)[^{]*\{(.*?)^}',output,re.M|re.S)
        self.assertIsNotNone(body)
        self.assertIn('call void @__cxa_rethrow()',body.group(1))
        self.assertNotIn('landingpad',body.group(1))
        self.assertIn('invoke void @_Z15dynamic_rethrowv()',output)


class ExceptionTypeMetadataTests(unittest.TestCase):
    def test_exact_revision_namespace_qualified_ids_and_no_boolean_integer_alias(self):
        from eh_metadata import allocation_reference
        fixture=json.loads((FIXTURES/'eh-type-metadata.json').read_text())
        for case in fixture['positive']:
            self.assertEqual(allocation_reference(case['node']),case['reference'])
        for node in fixture['reject']:
            with self.assertRaisesRegex(ValueError,'E-EH-TYPE-METADATA'):
                allocation_reference(node)


class SourceFenceWitnesses(unittest.TestCase):
    def test_relaxed_source_fence_is_noop_dynamic_orders_map_to_llvm(self):
        output=run([BIN/'clang','-target','x86_64-unknown-linux-gnu','-std=c23',
            '-O0','-S','-emit-llvm',FIXTURES/'source-fence.c','-o','-'])
        body=re.search(r'define[^@]+@relaxed_fence\(\)[^{]*\{(.*?)^}',output,re.M|re.S)
        self.assertIsNotNone(body)
        self.assertNotIn('fence ',body.group(1))
        self.assertIn('ret void',body.group(1))
        for order in ('acquire','release','acq_rel','seq_cst'):
            self.assertIn('fence '+order,output)
        self.assertNotIn('fence monotonic',output)
        cases=dict(re.findall(r'i32 ([1-5]), label %([0-9]+)',output))
        self.assertEqual(cases['1'],cases['2'])
        self.assertRegex(output,r'(?m)^'+cases['1']+r':[^\n]*\n\s+fence acquire')


class FunctionTypeSelectorTests(unittest.TestCase):
    def test_function_local_repeated_aliases_catchall_and_unbound_rejection(self):
        from eh_metadata import TypeSelectors
        ref=lambda i:{'module':{'kind':'self'},'id':i}
        # Independent synthetic identity classes only; actual ABI proof belongs
        # to the separate real-graph oracle below and whole-module admission.
        classes={1:'A',2:'B',9:'A'}
        table=TypeSelectors([ref(1),None,ref(2),ref(9)],
            lambda a,b:a['id'] in classes and b['id'] in classes and classes[a['id']]==classes[b['id']])
        self.assertEqual(table.selectors,[1,2,3,1])
        self.assertEqual(table.lookup(ref(9)),1)
        with self.assertRaisesRegex(ValueError,'E-EH-TYPEID-METADATA'):
            table.lookup(ref(2)|{'id':99})

    def test_actual_abi_graph_drives_type_identity_not_table_id(self):
        script='''import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from eh_metadata import TypeSelectors
sys.path.insert(0,sys.argv[2])
from nominal import NominalGraph
from copy import deepcopy
root=json.loads(Path(sys.argv[3]).read_text())
# Valid source graph identity comparison; this is not native certificate admission.
inttype=deepcopy(next(t for t in root['types'] if t['id']==1))
inttype['id']=900
root['types'].append(inttype)
graph=NominalGraph(root,'selector_witness')
ref=lambda i:{'module':{'kind':'self'},'id':i}
table=TypeSelectors([ref(1),None,ref(900)],graph.compatible)
print(json.dumps(table.selectors))
'''
        process=subprocess.run([sys.executable,'-B','-c',script,str(Path(__file__).parent),
            str(ROOT/'tools/smir-abi'),str(ROOT/'docs/specifications/smir/portable/conformance/abi/candidate/complete.json')],
            text=True,capture_output=True,check=True)
        self.assertEqual(json.loads(process.stdout),[1,2,1])


class ObservableSelectorProjectionTests(unittest.TestCase):
    def test_handler_id_alpha_preserves_selector_but_selector_change_is_observable(self):
        source=json.loads((FIXTURES/'candidate-selector.json').read_text())
        baseline=witness(source)
        changed=copy.deepcopy(source)
        handler=changed['exceptions']['functions'][0]['regions'][0]['handlers'][0]
        handler['id']=73
        renamed=witness(changed)
        self.assertEqual([baseline['reference_result'],renamed['reference_result']],[7,7])
        self.assertEqual(baseline['canonical'],renamed['canonical'])
        handler['selector']=8
        semantic=witness(changed)
        self.assertEqual(semantic['reference_result'],8)
        self.assertNotEqual(baseline['canonical'],semantic['canonical'])

    def test_zero_caught_selector_is_rejected_by_actual_admission(self):
        source=json.loads((FIXTURES/'candidate-selector.json').read_text())
        source['exceptions']['functions'][0]['regions'][0]['handlers'][0]['selector']=0
        self.assertIn('selector',witness(source,False))
