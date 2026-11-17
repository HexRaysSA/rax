"""Independent logical-variable vs SSA exception identity and LLVM verification."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from eh_slots import eliminate, execute, llvm_ir, QUOTAS
from test_contract import BIN, FIXTURES, run


class ExceptionSlotTests(unittest.TestCase):
    def setUp(self):
        self.cases = json.loads((FIXTURES/'eh-slots.json').read_text())['cases']

    def test_nested_catch_keeps_original_outer_and_branch_selects(self):
        for case in self.cases:
            transformed = eliminate(case['source'])
            for path in case['paths']:
                original = execute(case['source'],path,{'outer':'owner-A','inner':'owner-B'})
                actual = execute(transformed,path,{'outer':'owner-A','inner':'owner-B'})
                self.assertEqual(original,actual,(case['name'],path))
                if case['name']=='nested_catch_restore':
                    self.assertEqual(actual['returned'],'owner-A')
                if case['name']=='loop_simultaneous_phi_swap':
                    n=path.count('loop')
                    self.assertEqual(actual['returned'],'owner-B' if n%2 else 'owner-A')
                    self.assertEqual(actual['observed'],['owner-A' if i%2==0 else 'owner-B' for i in range(n)])

    def test_actual_pinned_llvm_before_and_after_no_opaque_memory(self):
        for case in self.cases:
            source=case['source'];transformed=eliminate(source)
            with tempfile.TemporaryDirectory(prefix='eh-slot-witness-') as temporary:
                for kind, document in [('before',source),('after',transformed)]:
                    path=Path(temporary)/(kind+'.ll');path.write_text(llvm_ir(document))
                    output=run([BIN/'clang','-target','x86_64-unknown-linux-gnu','-x','ir',
                        '-O0','-S','-emit-llvm',path,'-o','-'])
                    for operation in ('alloca','load ','store '):
                        self.assertNotIn(operation,output)
                    if kind=='after':
                        self.assertNotIn('__smir_eh_slot_',output)
                        self.assertNotIn('!smir.eh.slots',output)
                    if kind=='after' and case['name']=='conditional_merge':
                        self.assertIn('phi target("smir.exception")',output)

    def test_uninitialized_path_rejects_without_fabricated_exception(self):
        source=copy.deepcopy(self.cases[1]['source'])
        source['blocks'][2]['ops']=[]
        with self.assertRaisesRegex(ValueError,'E-EH-SLOT-UNINITIALIZED'):
            eliminate(source)

    def test_unknown_dynamic_duplicate_and_escaped_slots_reject(self):
        mutations=[lambda x:x['blocks'][0]['ops'][0].update(slot='dynamic'),
                   lambda x:x['blocks'][0]['ops'][0].update(slot=99),
                   lambda x:x['slots'].append(0),
                   lambda x:x['blocks'][0]['ops'][0].update(op='address_of_slot'),
                   lambda x:x['blocks'][0]['ops'][0].update(escape=True)]
        for mutate in mutations:
            source=copy.deepcopy(self.cases[0]['source']);mutate(source)
            with self.assertRaises(ValueError):
                eliminate(source)

    def test_get_operand_ssa_dominance_and_duplicate_value_reject(self):
        source=copy.deepcopy(self.cases[0]['source'])
        source['blocks'][0]['ops'][0]['value']='caught_inner'
        with self.assertRaisesRegex(ValueError,'E-EH-SLOT-SSA-DOMINANCE'):
            eliminate(source)
        source=copy.deepcopy(self.cases[0]['source'])
        source['blocks'][-1]['ops'][0]['result']='caught_inner'
        with self.assertRaisesRegex(ValueError,'E-EH-SLOT-DUPLICATE-VALUE'):
            eliminate(source)

    def test_loop_has_two_simultaneous_phis_duplicate_edge_trivial_phi_disappears(self):
        loop=eliminate(self.cases[2]['source'])
        self.assertEqual(len(loop['blocks'][1]['phis']),2)
        duplicate=eliminate(self.cases[3]['source'])
        self.assertFalse(any(b['phis'] for b in duplicate['blocks']))


class SlotQuotaTests(unittest.TestCase):
    def test_exact_matrix_budget_boundary_and_preexpansion_rejection(self):
        count=QUOTAS['max_slot_block_cells']//2
        source={'revision':'llvm-eh-slots-v1','slots':list(range(count)),
            'parameters':['outer'],'entry':'entry','blocks':[
                {'id':'entry','ops':[],'successors':['exit'],'return':None},
                {'id':'exit','ops':[],'successors':[],'return':'outer'}]}
        self.assertEqual(eliminate(source)['blocks'][-1]['return'],'outer')
        source['slots'].append(count)
        with self.assertRaisesRegex(ValueError,'E-EH-SLOT-RESOURCE'):
            eliminate(source)

    def test_large_product_rejected_before_inspecting_operations(self):
        # This small encoded declaration must not allocate 33 million cells.
        source={'revision':'llvm-eh-slots-v1','slots':list(range(65536)),
            'parameters':['outer'],'entry':'entry','blocks':[
                {'id':'b'+str(i),'ops':[],'successors':[],'return':'outer'} for i in range(512)]}
        with self.assertRaisesRegex(ValueError,'E-EH-SLOT-RESOURCE'):
            eliminate(source)


class NestedLandingpadWitnessTests(unittest.TestCase):
    def test_actual_nested_unwind_edges_preserve_outer_identity_in_expected_ssa(self):
        for name in ('nested-eh-slots.ll','nested-eh-slots-ssa.ll'):
            output=run([BIN/'clang','-target','x86_64-unknown-linux-gnu','-x','ir',
                '-O0','-S','-emit-llvm',FIXTURES/name,'-o','-'])
            self.assertEqual(output.count('landingpad { target("smir.exception"), i32 }'),2)
            self.assertIn('invoke void @inner_raise()',output)
            for operation in ('alloca','load ','store '):
                self.assertNotIn(operation,output)
            if name.endswith('-ssa.ll'):
                self.assertNotIn('__smir_eh_slot_',output)
                self.assertIn('ret target("smir.exception") %outer_exception',output)
                self.assertIn('opaque_observe(target("smir.exception") %inner_exception)',output)
