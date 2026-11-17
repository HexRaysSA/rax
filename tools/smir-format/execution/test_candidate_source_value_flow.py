"""Closed static assertions and real core SSA witnesses, not source admission."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from candidate.context import RootContext
from candidate.source_data_projection import source_api
from common import Reject
from source_value_flow.contract import MAX_BYTES, check
from source_value_flow import contract as implementation
from source_value_flow.fixtures import FOLDER, FN, RAW, codec, context, core_witness, document, encoded


def budget(**overrides):
    return source_api().SourceQueryBudget(**dict(dict(max_work=10**15,max_edges=10**15,
        max_copied_bytes=10**15,max_depth=128),**overrides))


class SourceValueFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus=json.loads((FOLDER/'cases.json').read_bytes())

    def original(self,profile='loop'):
        return context(bytes.fromhex(self.corpus['modules'][profile]['encoded_hex']))

    def assertion(self,profile='loop'):
        return deepcopy(next(row['assertion']for row in self.corpus['cases']if row['id']=='accept-'+profile))

    def assert_code(self,code,owner,payload,ledger=None):
        with self.assertRaises(source_api().SourceDataError)as raised:
            check(owner,payload,budget=ledger if ledger is not None else budget())
        self.assertEqual(raised.exception.code,code)
        return raised.exception

    def test_authored_39_cases_actual_original_abi_body_and_closed_assertions(self):
        self.assertEqual(len(self.corpus['cases']),39)
        for row in self.corpus['cases']:
            with self.subTest(case=row['id']):
                owner=self.original(row['module'])
                if row['expected']=='ok':
                    result=check(owner,encoded(row['assertion']),budget=budget())
                    self.assertTrue(result['static_body_and_abi_verified'])
                    expected={'accept-loop':(8,5,3),'accept-seeds':(4,2,2),'accept-literal':(1,0,1),
                        'accept-max-id':(2,1,1),'accept-boundary4096':(4096,4095,1),
                        'accept-no-source-byte-definitions':(0,0,0)}[row['id']]
                    self.assertEqual((result['raw8_definitions'],result['flows'],result['seeds']),expected)
                    for name in ('source_facts_issued','source_category_proved','source_body_equivalence','source_admission_passed',
                                 'runtime_permission','private_core_events_issued','delegated_factory_cost_qualified'):
                        self.assertIs(result[name],False)
                else:
                    self.assert_code(row['expected'],owner,encoded(row['assertion']))
                owner.assert_snapshot()

    def test_frozen_actual_modules_have_explicit_octet_lengths_and_hashes(self):
        self.assertEqual(len(self.corpus['modules']),5)
        for row in self.corpus['modules'].values():
            wire=bytes.fromhex(row['encoded_hex'])
            self.assertEqual(len(wire),row['bytes'])
            self.assertEqual(hashlib.sha256(wire).hexdigest(),row['sha256'])

    def test_closed_json_rejects_duplicates_nan_nonbytes_and_depth_before_result(self):
        owner=self.original('literal');raw=encoded(self.assertion('literal'))
        self.assert_code('FLOW_JSON',owner,raw.replace(b'"revision":1',b'"revision":1,"revision":1'))
        self.assert_code('FLOW_JSON',owner,raw.replace(b'"revision":1',b'"revision":NaN'))
        self.assert_code('FLOW_INPUT',owner,raw.decode())
        self.assert_code('FLOW_RESOURCE',owner,b'['*65+b'0'+b']'*65)
        self.assert_code('FLOW_RESOURCE',owner,b' '*(MAX_BYTES+1))
        self.assert_code('FLOW_JSON',owner,b'\xff')

    def test_actual_canonical_budget_zero_exact_and_one_less_each_dimension(self):
        raw=encoded(self.assertion('literal'));owner=self.original('literal')
        original=RootContext.verify_execution;entered=[]
        def observe(actual):
            entered.append(actual)
            return original(actual)
        with patch.object(RootContext,'verify_execution',observe):
            zero=self.assert_code('SOURCE_DATA_RESOURCE',owner,raw,budget(max_work=0,max_edges=0,max_copied_bytes=0))
        self.assertEqual(entered,[]);self.assertEqual(zero.kind,'resource')
        measured=budget();result=check(owner,raw,budget=measured)
        limits=dict(max_work=measured._used_work,max_edges=measured._used_edges,
                    max_copied_bytes=measured._used_copied_bytes,max_depth=128)
        exact=source_api().SourceQueryBudget(**limits)
        self.assertEqual(check(self.original('literal'),raw,budget=exact),result)
        for name in ('max_work','max_edges','max_copied_bytes'):
            with self.subTest(dimension=name):
                smaller=dict(limits);smaller[name]-=1
                self.assert_code('SOURCE_DATA_RESOURCE',self.original('literal'),raw,
                                 source_api().SourceQueryBudget(**smaller))

    def test_original_budget_resource_object_is_not_translated(self):
        owner=self.original('literal');raw=encoded(self.assertion('literal'))
        measured=budget();check(owner,raw,budget=measured)
        small=budget(max_work=measured._used_work-1)
        actual_charge=source_api().SourceQueryBudget.charge;observed=[]
        def observe(actual,**amounts):
            try:return actual_charge(actual,**amounts)
            except source_api().SourceDataError as error:
                observed.append(error);raise
        with patch.object(source_api().SourceQueryBudget,'charge',observe):
            error=self.assert_code('SOURCE_DATA_RESOURCE',owner,raw,small)
        self.assertEqual(len(observed),1);self.assertIs(error,observed[0])

    def test_actual_owner_change_after_resource_wins_and_chains_same_resource(self):
        raw=encoded(self.assertion('literal'));measured=budget()
        check(self.original('literal'),raw,budget=measured)
        owner=self.original('literal');small=budget(max_work=measured._used_work-1)
        actual_charge=source_api().SourceQueryBudget.charge;observed=[]
        def observe(actual,**amounts):
            try:return actual_charge(actual,**amounts)
            except source_api().SourceDataError as error:
                observed.append((error,error.kind,error.code,error.detail))
                owner.sections[3]['functions'][0]['no_return']=True
                raise
        with patch.object(source_api().SourceQueryBudget,'charge',observe):
            error=self.assert_code('FLOW_CHANGED',owner,raw,small)
        original,kind,code,detail=observed[0]
        self.assertIs(error.__cause__,original)
        self.assertEqual((original.kind,original.code,original.detail),(kind,code,detail))

    def test_changed_owner_and_fake_context_or_budget_never_validate(self):
        owner=self.original('literal');raw=encoded(self.assertion('literal'))
        owner.sections[3]['functions'][0]['no_return']=True
        self.assert_code('FLOW_CHANGED',owner,raw)
        self.assert_code('FLOW_CONTEXT',object(),raw)
        class Copy(RootContext):pass
        self.assert_code('FLOW_CONTEXT',Copy.__new__(Copy),raw)
        self.assert_code('FLOW_BUDGET_REFERENCE',self.original('literal'),raw,object())

    def test_nonplain_original_section_never_runs_its_lookup_callback(self):
        calls=[]
        class NonPlain(dict):
            def __getitem__(self,key):
                calls.append(key)
                return super().__getitem__(key)
        owner=self.original('literal')
        owner.sections[3]=NonPlain(owner.sections[3])
        self.assert_code('FLOW_INPUT',owner,encoded(self.assertion('literal')))
        self.assertEqual(calls,[])
        class Meta(type):
            def __eq__(self,other):
                calls.append(other)
                return False
        class NonPrimitive(metaclass=Meta):pass
        owner=self.original('literal');owner.sections[3]=NonPrimitive()
        self.assert_code('FLOW_INPUT',owner,encoded(self.assertion('literal')))
        self.assertEqual(calls,[])

    def test_enlarged_actual_schema_afterguard_reads_only_reserved_original_extent(self):
        schema=implementation.SCHEMA.read_bytes();size=len(schema);reads=[];raw_extents=[]
        real_open=Path.open;real_verify=RootContext.verify_execution
        output=os.environ.get('SMIR_TEST_TMP',tempfile.gettempdir())
        with tempfile.TemporaryDirectory(prefix='source-value-flow-',dir=output)as folder:
            copied=Path(folder)/'schema.json';copied.write_bytes(schema)
            class ObservedReader:
                def __init__(self,stream):self.stream=stream
                def __enter__(self):self.stream.__enter__();return self
                def __exit__(self,*args):return self.stream.__exit__(*args)
                def read(self,extent=-1):
                    reads.append(extent)
                    before=os.lseek(self.stream.fileno(),0,os.SEEK_CUR)
                    result=self.stream.read(extent)
                    raw_extents.append(os.lseek(self.stream.fileno(),0,os.SEEK_CUR)-before)
                    return result
            def observe_open(path,*args,**kwargs):
                stream=real_open(path,*args,**kwargs)
                return ObservedReader(stream)if path==copied and args and args[0]=='rb'else stream
            def verify_then_grow(owner):
                result=real_verify(owner)
                with copied.open('ab')as target:target.write(b' '*(2*io.DEFAULT_BUFFER_SIZE))
                return result
            with patch.object(implementation,'SCHEMA',copied),patch.object(Path,'open',observe_open),\
                    patch.object(RootContext,'verify_execution',verify_then_grow):
                self.assert_code('FLOW_CHANGED',self.original('literal'),encoded(self.assertion('literal')))
            self.assertEqual(reads,[size+1,size+1])
            self.assertEqual(raw_extents,[size,size+1])
            self.assertGreater(copied.stat().st_size,size+1)

    def test_actual_core_parallel_phi_swaps_loop_births_without_equal_bits_guess(self):
        wire=bytes.fromhex(self.corpus['modules']['loop']['encoded_hex'])
        for iterations in (1,2,3):
            for condition in (0,1):
                with self.subTest(iterations=iterations,condition=condition):
                    row=core_witness(wire,iterations,condition)
                    self.assertEqual(row['outcome'],'return')
                    self.assertEqual(len(row['batches']),iterations)
                    self.assertEqual(row['batches'][0]['predecessor'],0)
                    for batch in row['batches'][1:]:
                        self.assertEqual(batch['predecessor'],1)
                        self.assertTrue(batch['swaps_previous'])
                    self.assertEqual([b['ordinal']for b in row['batches']],list(range(1,iterations+1)))
                    for event in row['selections']:
                        self.assertEqual(event['selected'],'true'if condition else'false')
                        self.assertEqual(event['steps'],1)
                        self.assertTrue(event['equal_input_bits'])
                        self.assertTrue(event['distinct_input_origins'])
                    self.assertFalse(row['private_core_events_issued'])

    def test_actual_undef_select_refines_once_and_poison_has_no_selected_operand(self):
        wire=bytes.fromhex(self.corpus['modules']['loop']['encoded_hex'])
        undef=core_witness(wire,1,state='undef')
        self.assertEqual(undef['selections'][0]['selected'],'false')
        self.assertEqual(undef['selections'][0]['steps'],1)
        poison=core_witness(wire,1,state='poison')
        self.assertIsNone(poison['selections'][0]['selected'])
        self.assertEqual(poison['selections'][0]['state'],'poison')
        self.assertEqual(poison['freezes'][0],dict(input_state='poison',output_state='concrete',actual_output_defined=True))
        self.assertFalse(poison['source_admission_passed'])
        self.assertFalse(poison['source_facts_issued'])

    def test_real_body_verifier_rejects_undefined_return_before_static_result(self):
        roots,a=document('literal');roots[3]['functions'][1]['blocks'][0]['term']['values']=[999]
        owner=context(codec().encode(roots))
        with self.assertRaises(Reject):check(owner,encoded(a),budget=budget())

    def test_undef_and_poison_literals_cannot_be_initialized_seed_assertions(self):
        for kind in ('undef','poison'):
            roots,a=document('literal')
            roots[3]['functions'][1]['blocks'][0]['ops'][0]['literal']=dict(kind=kind)
            self.assert_code('FLOW_SEED',context(codec().encode(roots)),encoded(a))

    def test_real_definition_limit_noundef_fixed_core_convention_and_wide_gap(self):
        roots,a=document('chain',4096);a['nominals'].pop()
        self.assert_code('FLOW_RESOURCE',context(codec().encode(roots)),encoded(a))
        roots,a=document('literal');signature=next(t for t in roots[1]['types']if t['id']==FN)
        signature['result_noundef']=[True]
        self.assert_code('FLOW_NOUNDEF',context(codec().encode(roots)),encoded(a))
        roots,a=document('literal');next(t for t in roots[1]['types']if t['id']==FN)['variadic']=True
        with self.assertRaises(Reject) as rejected:
            context(codec().encode(roots))
        self.assertEqual(rejected.exception.code,'calling_convention')
        roots,a=document('literal');roots[1]['types'].append(dict(id=2305,kind='raw',bits=16))
        next(t for t in roots[1]['types']if t['id']==FN)['results']=[dict(module=dict(kind='self'),id=2305)]
        op=roots[3]['functions'][1]['blocks'][0]['ops'][0]
        op['results'][0]['type']['id']=2305;op['literal']['value']='2a00'
        a['seeds']=[];a['nominals']=[]
        error=self.assert_code('FLOW_WIDE_UNAVAILABLE',context(codec().encode(roots)),encoded(a))
        self.assertEqual(error.kind,'unavailable')


if __name__=='__main__':unittest.main(verbosity=2)
