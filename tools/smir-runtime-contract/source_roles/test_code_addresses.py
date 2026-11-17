"""Actual source-backed registry tests; no synthetic activation success factory."""
from pathlib import Path
import importlib.util
import sys
import unittest
from copy import deepcopy

ROOT=Path(__file__).resolve().parents[3]
EXEC=ROOT/'tools/smir-format/execution'
for name,module in tuple(sys.modules.items()):
    location=getattr(module,'__file__',None)
    if (name=='candidate' or name.startswith('candidate.')) and location and \
            ROOT/'tools/smir-runtime-contract/candidate' in Path(location).parents:
        del sys.modules[name]
sys.path.insert(0,str(EXEC));sys.path.insert(1,str(ROOT/'tools/smir-runtime-contract'))
from candidate.context import RootContext
from generate_service_type_fixtures import complete_identity,prepare_abi2_nonrecord_source

NAME='_rax_smir_code_addresses_v1';PATH=ROOT/'tools/smir-runtime-contract/source_roles/code_addresses.py'
if NAME not in sys.modules:
    spec=importlib.util.spec_from_file_location(NAME,PATH)
    module=importlib.util.module_from_spec(spec);sys.modules[NAME]=module;spec.loader.exec_module(module)
R=sys.modules[NAME]


def budget():
    return R._base.SD.SourceQueryBudget(max_work=10**12,max_edges=10**12,max_copied_bytes=10**12,max_depth=128)


def policy(**changes):
    values=dict(max_targets=32,max_permits=32,max_roots=32,max_activations=32,max_snapshots=32)
    values.update(changes);return R.RegistryPolicy(**values)


def actual():
    context=RootContext(complete_identity());context.verify_abi();context.verify_execution()
    ledger=budget();source=context.source_registry_context(budget=ledger)
    return context,source,ledger


def call_machine(*,raw=False,two_bind=False,legacy=False,quota=None,poison_argument=False,bad_plan=False):
    from candidate.machine import Machine
    from candidate.values import Value
    roots=complete_identity()
    ref=lambda identifier:{'module':{'kind':'self'},'id':identifier}
    roots[1]['types'] += [{'id':900,'kind':'code_address'},
        {'id':901,'kind':'code_ptr','signature':ref(12)}]
    main=deepcopy(roots[3]['functions'][0]);main['id']=1
    main['blocks'][0]['ops']=[
        {'op':'address_of','results':[{'id':20,'type':ref(900)}],'operands':[],'symbol':ref(0)},
        {'op':'code_bind','results':[{'id':21,'type':ref(901)}],'operands':[20],'plan':ref(0)},
        {'op':'call','results':[{'id':22,'type':ref(17)}],'operands':[0],
            'target':{'kind':'indirect','value':21,'signature':ref(12)},
            'unwind':'propagate','source_plan':{'some':ref(0)}}]
    if legacy:
        main['blocks'][0]['ops'][0]['results'][0]['type']=ref(901)
        main['blocks'][0]['ops'].insert(1,{'op':'code_erase',
            'results':[{'id':26,'type':ref(900)}],'operands':[20]})
        main['blocks'][0]['ops'][2]['operands']=[26]
    if raw:
        main['blocks'][0]['ops'][2:2]=[
            {'op':'bitcast','results':[{'id':23,'type':ref(3)}],'operands':[21]},
            {'op':'bitcast','results':[{'id':24,'type':ref(901)}],'operands':[23]}]
        main['blocks'][0]['ops'][-1]['target']['value']=24
    if two_bind:
        main['blocks'][0]['ops'].insert(2,{'op':'code_bind',
            'results':[{'id':25,'type':ref(901)}],'operands':[20],'plan':ref(0)})
    if poison_argument:
        main['blocks'][0]['ops'].insert(0,{'op':'effect_barrier','results':[],'operands':[]})
        main['blocks'][0]['ops'].insert(1,{'op':'constant',
            'results':[{'id':27,'type':ref(17)}],'operands':[],'literal':{'kind':'poison'}})
        main['blocks'][0]['ops'][-1]['operands']=[27]
    if bad_plan:
        nominal=deepcopy(next(t for t in roots[10]['types'] if t['id']==12))
        nominal['id']=13;nominal['flags']=sorted(set(nominal['flags'])|{'noexcept'})
        roots[10]['types'].append(nominal)
        plan=deepcopy(roots[10]['signatures'][0]);plan.update(id=1,function_type=ref(13),noexcept=True)
        roots[10]['signatures'].append(plan)
        next(o for o in main['blocks'][0]['ops'] if o['op']=='code_bind')['plan']=ref(1)
    main['blocks'][0]['term']={'op':'return','values':[22]};roots[3]['functions'].append(main)
    prepare_abi2_nonrecord_source(roots)
    context=RootContext(roots);context.verify_abi();context.verify_execution();ledger=budget()
    source=context.source_registry_context(budget=ledger)
    registry=R.CodeRegistry(budget=ledger,policy=policy(**(quota or {})))
    machine=Machine(context.execution_checked);machine.attach_source_registry(registry,source,budget=ledger)
    if legacy:machine.register_function(ref(0),ref(0),ref(12))
    machine.start(1,[Value(ref(17),'concrete',42)])
    return machine,registry,ledger


class ActualRegistryTests(unittest.TestCase):
    def test_argument_effects_and_bind_precede_call_noundef(self):
        machine,registry,ledger=call_machine(poison_argument=True)
        result=machine.run()
        self.assertEqual(result['kind'],'language_ub',result)
        self.assertEqual(result['reason'],'ub_noundef_argument')
        self.assertEqual(len(machine.memory.effects),1)
        self.assertEqual(len(registry._permits),1)
        self.assertEqual(registry._entries,[])

    def test_bad_bind_plan_precedes_later_call_noundef(self):
        machine,registry,ledger=call_machine(poison_argument=True,bad_plan=True)
        result=machine.run()
        self.assertEqual(result['kind'],'trap',result)
        self.assertEqual(result['reason'],'code_address_plan')
        self.assertEqual(len(machine.memory.effects),1)
        self.assertEqual(registry._permits,[])
        self.assertEqual(registry._entries,[])

    def test_two_actual_machines_share_function_pool_and_labels_are_distinct(self):
        from candidate.machine import Machine
        context,source,ledger=actual();registry=R.CodeRegistry(budget=ledger,policy=policy())
        first=Machine(context.execution_checked);second=Machine(context.execution_checked)
        first.attach_source_registry(registry,source,budget=ledger)
        second.attach_source_registry(registry,source,budget=ledger)
        a=first._source_runtime['attachment'];b=second._source_runtime['attachment']
        reference={'module':{'kind':'self'},'id':0}
        x=registry.reserve_function(a,reference,budget=ledger)
        y=registry.reserve_function(b,reference,budget=ledger)
        label=registry.reserve_label(b,reference,0,budget=ledger)
        self.assertEqual(x.bits,y.bits);self.assertEqual(x.bits,2)
        self.assertEqual(label.bits,4);self.assertEqual(x.generation,y.generation)
        owner=registry.register_source(source,budget=ledger)
        deployment=registry.prepare_deployment((owner,),budget=ledger)
        target=registry.resolve(deployment,owner,'function',reference,budget=ledger)
        self.assertEqual(registry.address(target,budget=ledger).bits,x.bits)
        # This checks genuine attached Machine reservations. The separate
        # end-to-end producer test checks actual legacy registration publication.

    def test_actual_nonnull_bind_source_call_returns_42(self):
        machine,registry,ledger=call_machine()
        result=machine.run()
        self.assertEqual(result['kind'],'return',result)
        self.assertEqual(result['values'][0].data,42)
        self.assertEqual(sum(registry._row(owner)['active'] for owner in registry._owners),0)

    def test_actual_result_transfer_needs_only_two_live_roots(self):
        machine,registry,ledger=call_machine(quota={'max_roots':2})
        result=machine.run()
        self.assertEqual(result['kind'],'return',result)
        self.assertEqual(result['values'][0].data,42)
        self.assertEqual(len(registry._permits),1)
        self.assertEqual(registry._root_count,0)
        self.assertEqual(sum(registry._row(owner)['pins'] for owner in registry._owners),0)

    def test_actual_bound_raw_roundtrip_preserves_permit_and_calls_42(self):
        machine,registry,ledger=call_machine(raw=True)
        result=machine.run()
        self.assertEqual(result['kind'],'return',result)
        self.assertEqual(result['values'][0].data,42)
        self.assertEqual(len(registry._permits),1)
        self.assertEqual(sum(registry._row(owner)['active'] for owner in registry._owners),0)

    def test_actual_original_legacy_reservation_erases_then_binds_and_calls_42(self):
        machine,registry,ledger=call_machine(legacy=True)
        result=machine.run()
        self.assertEqual(result['kind'],'return',result)
        self.assertEqual(result['values'][0].data,42)
        self.assertEqual(sum(registry._row(owner)['active'] for owner in registry._owners),0)

    def test_actual_normal_completion_is_consumed_once(self):
        machine,registry,ledger=call_machine()
        original=registry.finish_entry;saved=[]
        def record_actual(entry,*,outcome,budget):
            saved.append((entry,outcome))
            return original(entry,outcome=outcome,budget=budget)
        registry.finish_entry=record_actual
        result=machine.run()
        self.assertEqual(result['kind'],'return',result)
        self.assertEqual(result['values'][0].data,42)
        self.assertEqual(len(saved),1)
        entry,outcome=saved[0]
        with self.assertRaises(R.CodeRegistryError) as caught:
            original(entry,outcome=outcome,budget=ledger)
        self.assertEqual(caught.exception.code,'RT_CODE_ENTRY_REPLAY')
        self.assertEqual(sum(registry._row(owner)['active'] for owner in registry._owners),0)

    def test_releasing_actual_operand_root_during_entry_preflight_refuses_publication(self):
        from unittest.mock import patch
        machine,registry,ledger=call_machine()
        original=R._base.MODEL.ordinary_address_call_compatible
        comparisons=0
        def concurrent_release(*args,**kwargs):
            nonlocal comparisons
            result=original(*args,**kwargs);comparisons+=1
            if comparisons==4:
                lane=machine.stack[-1].values[21].data.authority
                root=registry._row(lane)['root']
                registry.release(root,budget=ledger)
            return result
        with patch.object(R._base.MODEL,'ordinary_address_call_compatible',concurrent_release):
            with self.assertRaises(R.CodeRegistryError) as caught:machine.run()
        self.assertEqual(caught.exception.code,'RT_CODE_REFERENCE')
        self.assertEqual(registry._entries,[])
        self.assertEqual(sum(registry._row(owner)['active'] for owner in registry._owners),0)

    def test_another_genuine_samebits_samefn_lane_cannot_replace_call_operand(self):
        machine,registry,ledger=call_machine(two_bind=True)
        original=registry.entry
        def substituted(code,call,*,activation,budget):
            other=machine.stack[-1].values[25].data.authority
            self.assertEqual(code.bits,other.bits)
            self.assertIsNot(code.permit,other.permit)
            return original(other,call,activation=activation,budget=budget)
        registry.entry=substituted
        error=sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError
        with self.assertRaises(error):machine.run()
        self.assertEqual(registry._entries,[])
        self.assertEqual(sum(registry._row(owner)['active'] for owner in registry._owners),0)

    def test_actual_source_private_selection_and_shared_even_address(self):
        context,source,ledger=actual();registry=R.CodeRegistry(budget=ledger,policy=policy())
        owner=registry.register_source(source,budget=ledger)
        self.assertIs(registry.register_source(source,budget=ledger),owner)
        deployment=registry.prepare_deployment((owner,),budget=ledger)
        reference={'module':{'kind':'self'},'id':0}
        first=registry.resolve(deployment,owner,'function',reference,budget=ledger)
        second=registry.resolve(deployment,owner,'symbol',reference,budget=ledger)
        self.assertIs(first,second)
        address=registry.address(first,budget=ledger);alias=registry.address(second,budget=ledger)
        self.assertEqual(address.bits,2);self.assertEqual(alias.bits,address.bits)
        self.assertEqual(registry.originless(address.bits,budget=ledger).bits,2)
        self.assertEqual(registry.poison(budget=ledger).state,'poison')
        self.assertEqual(registry.undef(budget=ledger).state,'undef')
        registry.drop_lane(address,budget=ledger)
        with self.assertRaises(R.CodeRegistryError):registry.drop_lane(address,budget=ledger)
        self.assertEqual(alias.bits,2)

    def test_unissued_context_owner_and_other_ledger_reject(self):
        context,source,ledger=actual();registry=R.CodeRegistry(budget=ledger,policy=policy())
        error=sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError
        with self.assertRaises(error) as caught:registry.register_source({},budget=ledger)
        self.assertEqual(caught.exception.code,'SOURCE_REGISTRY_CONTEXT')
        with self.assertRaises(R.CodeRegistryError):registry.originless(True,budget=ledger)
        with self.assertRaises(R.CodeRegistryError):registry.originless(0,budget=budget())
        for cls in (R.OwnerRef,R.AddressLane,R.BindingPermit,R.EntryRef,R.MachineAttachment):
            with self.assertRaises(R.CodeRegistryError):cls()
            fake=object.__new__(cls)
            with self.assertRaises(R.CodeRegistryError):registry._row(fake)
        context.sections[2]['symbols'][0]['name']='mutated'
        with self.assertRaises((error,R._base.SD.SourceDataError)):
            registry.register_source(source,budget=ledger)

    def test_token_exhaustion_publishes_no_address(self):
        context,source,ledger=actual();registry=R.CodeRegistry(budget=ledger,policy=policy(max_targets=0))
        owner=registry.register_source(source,budget=ledger)
        deployment=registry.prepare_deployment((owner,),budget=ledger)
        with self.assertRaises(R.CodeRegistryError) as caught:
            registry.resolve(deployment,owner,'function',{'module':{'kind':'self'},'id':0},budget=ledger)
        self.assertEqual((caught.exception.kind,caught.exception.code),('resource','RT_CODE_RESOURCE'))
        self.assertEqual(registry._pool._keys,{})


if __name__=='__main__':unittest.main()
