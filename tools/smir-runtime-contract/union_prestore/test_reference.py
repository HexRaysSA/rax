"""Boundary/rejection witnesses for a single whole-storage union model."""
from dataclasses import replace
import random,unittest
from .model import World,SourceValue,mask,_api
from candidate.raw import Raw
from candidate.memory import GuestFault
from candidate.type_system import ref
from candidate.values import from_raw, Value


def budget(**kw):
    limits=dict(max_work=10**7,max_edges=10**6,max_copied_bytes=10**7,max_depth=64)
    limits.update(kw);return _api().SourceQueryBudget(**limits)

def assignment(w,arm,offset,value,b=None):
    b=budget() if b is None else b
    p=w.preflight(arm,offset,value,budget=b);t=w.commit(p,budget=b)
    w.execute_store(t,budget=b);w.complete(t,budget=b);return b,p,t

class ProtocolTests(unittest.TestCase):
    def test_actual_verified_core_store_and_single_completion(self):
        w=World();b,p,t=assignment(w,'a',1,SourceValue(Raw.integer(8,42)))
        self.assertEqual(w.machine.memory.raw_load(w.pointer(1),1),Raw.integer(8,42))
        self.assertEqual(w.machine.memory.effects,[('store','none','none',False)])
        self.assertEqual(w.cursor,2);self.assertEqual(w.cells['a'].generation,1)
        for action in [lambda:w.commit(p,budget=b),lambda:w.execute_store(t,budget=b),lambda:w.complete(t,budget=b)]:
            with self.assertRaises(ValueError):action()
        self.assertEqual(len(w.machine.memory.effects),1)

    def test_readonly_guard_fails_before_lifetime_frontier_or_effect(self):
        w=World();w.machine.memory.objects[w.base.origin]['mutable']=False
        with self.assertRaises(GuestFault) as error:w.preflight('a',0,SourceValue(Raw.integer(8,1)),budget=budget())
        self.assertEqual(error.exception.code,'memory_permission')
        self.assertEqual((w.cells,w.cursor,w.machine.memory.effects,w.prepared),({},0,[],{}))

    def test_bounds_guard_fails_before_lifetime_frontier_or_effect(self):
        w=World()
        with self.assertRaises(GuestFault) as error:w.preflight('a',8,SourceValue(Raw.integer(8,1)),budget=budget())
        self.assertEqual(error.exception.code,'memory_bounds');self.assertEqual(w.cells,{})

    def test_real_budget_exact_and_each_dimension_one_less(self):
        trial=budget();w=World();w.preflight('a',0,SourceValue(Raw.integer(8,1)),budget=trial)
        limits=dict(max_work=trial._used_work,max_edges=trial._used_edges,max_copied_bytes=trial._used_copied_bytes)
        w=World();b=budget(**limits);p=w.preflight('a',0,SourceValue(Raw.integer(8,1)),budget=b)
        t=w.commit(p,budget=b);w.execute_store(t,budget=b);w.complete(t,budget=b)
        for dimension in limits:
            low=dict(limits);low[dimension]-=1;w=World()
            with self.assertRaisesRegex(_api().SourceDataError,'SOURCE_DATA_RESOURCE'):
                w.preflight('a',0,SourceValue(Raw.integer(8,1)),budget=budget(**low))
            self.assertEqual((w.cells,w.cursor,w.prepared,w.machine.memory.effects),({},0,{},[]))

    def test_same_budget_required_at_every_frontier(self):
        w=World();b=budget();p=w.preflight('a',0,SourceValue(Raw.integer(8,1)),budget=b)
        with self.assertRaisesRegex(ValueError,'budget_changed'):w.commit(p,budget=budget())
        t=w.commit(p,budget=b)
        for f in [w.execute_store,w.park,w.complete,w.cancel]:
            with self.assertRaisesRegex(ValueError,'budget_changed'):f(t,budget=budget())
        self.assertEqual(w.machine.memory.effects,[])

    def test_cloned_and_foreign_tokens_rejected(self):
        w=World();other=World();b=budget();p=w.preflight('a',0,SourceValue(Raw.integer(8,1)),budget=b)
        for target,token in [(w,replace(p)),(other,p)]:
            with self.assertRaisesRegex(ValueError,'foreign_or_cloned_reference'):target.commit(token,budget=b)
        t=w.commit(p,budget=b)
        with self.assertRaisesRegex(ValueError,'foreign_or_cloned_reference'):w.execute_store(replace(t),budget=b)
        with self.assertRaisesRegex(ValueError,'foreign_or_cloned_reference'):other.execute_store(t,budget=b)

    def test_same_live_arm_preserves_initialized_sibling(self):
        w=World();assignment(w,'a',1,SourceValue(Raw.integer(8,17)))
        generation=w.cells['a'].generation
        assignment(w,'a',0,SourceValue(Raw.integer(8,19)))
        self.assertEqual(w.cells['a'].generation,generation)
        self.assertEqual(w.load(w.pointer(1),1).numeric(types=w.machine.types,reference=ref(1)),Value(ref(1),'concrete',17))

    def test_switch_arm_preserves_physical_sibling_but_marks_indeterminate(self):
        w=World();assignment(w,'a',1,SourceValue(Raw.integer(8,17)))
        assignment(w,'b',0,SourceValue(Raw.integer(8,19)))
        self.assertFalse(w.cells['a'].live);self.assertEqual(w.machine.memory.raw_load(w.pointer(1),1).bits,17)
        self.assertEqual(w.load(w.pointer(1),1).indeterminate,255)
        with self.assertRaisesRegex(ValueError,'source_indeterminate_numeric_use'):w.load(w.pointer(1),1).numeric(types=w.machine.types,reference=ref(1))

    def test_same_ended_arm_has_new_generation_and_initialization(self):
        w=World();assignment(w,'a',1,SourceValue(Raw.integer(8,17)));w.end('a')
        assignment(w,'a',0,SourceValue(Raw.integer(8,19)))
        self.assertEqual(w.cells['a'].generation,2);self.assertEqual(w.load(w.pointer(1),1).indeterminate,255)

    def test_prospective_first_birth_does_not_launder_to_later_birth(self):
        w=World();h=w.prospective('a');assignment(w,'a',0,SourceValue(Raw.integer(8,1)))
        self.assertEqual(w.resolve(h),('a',1));w.end('a')
        assignment(w,'a',0,SourceValue(Raw.integer(8,2)))
        with self.assertRaisesRegex(ValueError,'stale_or_unborn_handle'):w.resolve(h)
        self.assertEqual(w.resolve(w.prospective('a')),('a',2))

    def test_unused_first_birth_handle_is_stale_after_reactivation(self):
        w=World();h=w.prospective('a');assignment(w,'a',0,SourceValue(Raw.integer(8,1)))
        assignment(w,'b',0,SourceValue(Raw.integer(8,2)));assignment(w,'a',0,SourceValue(Raw.integer(8,3)))
        with self.assertRaisesRegex(ValueError,'stale_or_unborn_handle'):w.resolve(h)

    def test_physical_pointer_shadow_stays_but_source_observation_strips_origin(self):
        w=World();raw=Raw.pointer(w.base);w.machine.memory.raw_store(w.base,raw)
        observed=w.load(w.base,8)
        self.assertEqual(w.machine.memory.raw_load(w.base,8),raw)
        self.assertEqual(observed.indeterminate,mask(64));self.assertEqual(observed.raw.origins,())
        self.assertIsNone(observed.raw.as_pointer()['identity'])

    def test_freeze_then_store_retains_indeterminate_source_state(self):
        w=World();w.machine.memory.raw_store(w.base,Raw.integer(8,0x91))
        frozen=w.load(w.base,1).freeze()
        self.assertEqual(frozen.raw,Raw.integer(8,0));self.assertEqual(frozen.indeterminate,255)
        w.init[w.base.origin]=0
        w.store(w.base,frozen)
        self.assertEqual(w.machine.memory.raw_load(w.base,1),Raw.integer(8,0))
        self.assertEqual(w.load(w.base,1).indeterminate,255)
        with self.assertRaisesRegex(ValueError,'source_indeterminate_numeric_use'):frozen.numeric(types=w.machine.types,reference=ref(1))

    def test_known_initialized_store_clears_only_its_source_bits(self):
        w=World();w.store(w.pointer(2),SourceValue(Raw.integer(8,42)))
        self.assertEqual(w.load(w.pointer(2),1).numeric(types=w.machine.types,reference=ref(1)),Value(ref(1),'concrete',42))
        self.assertEqual(w.load(w.pointer(1),1).indeterminate,255)

    def test_copy_uses_actual_physical_raw_not_projected_source_raw(self):
        w=World(16);raw=Raw.pointer(w.base);w.machine.memory.raw_store(w.base,raw)
        w.copy(w.pointer(8),w.base,8)
        self.assertEqual(w.machine.memory.raw_load(w.pointer(8),8),raw)
        self.assertEqual(w.load(w.pointer(8),8).raw.origins,())
        self.assertEqual(w.load(w.pointer(8),8).indeterminate,mask(64))

    def test_memmove_snapshots_both_planes_before_overlap(self):
        w=World(8)
        for i in range(8):w.machine.memory.raw_store(w.pointer(i),Raw.integer(8,i+1))
        w.init[w.base.origin]=0x00ff0000ff00ff00
        original=w.init[w.base.origin];w.copy(w.pointer(2),w.base,6,overlap=True)
        self.assertEqual([w.machine.memory.raw_load(w.pointer(i),1).bits for i in range(8)],[1,2,1,2,3,4,5,6])
        self.assertEqual(w.init[w.base.origin],(original&0xffff)|((original&mask(48))<<16))
        self.assertEqual(w.machine.memory.effects,[('memmove',6,False)])

    def test_memcpy_overlap_fault_changes_neither_plane(self):
        w=World();before=w.machine.memory.raw_load(w.base,8);i=w.init[w.base.origin]
        with self.assertRaises(GuestFault) as error:w.copy(w.pointer(1),w.base,7)
        self.assertEqual(error.exception.code,'ub_memcpy_overlap')
        self.assertEqual(w.machine.memory.raw_load(w.base,8),before);self.assertEqual(w.init[w.base.origin],i)

    def test_park_after_prepare_resumes_same_generation_once(self):
        w=World();b=budget();p=w.preflight('a',0,SourceValue(Raw.integer(8,42)),budget=b);t=w.commit(p,budget=b)
        w.park(t,budget=b)
        with self.assertRaisesRegex(ValueError,'effect_replay_or_stage'):w.execute_store(t,budget=b)
        w.resume(t,budget=b);w.execute_store(t,budget=b);w.complete(t,budget=b)
        self.assertEqual(w.cells['a'].generation,1);self.assertEqual(len(w.machine.memory.effects),1)

    def test_park_after_store_never_repeats_core_store(self):
        w=World();b=budget();p=w.preflight('a',0,SourceValue(Raw.integer(8,42)),budget=b);t=w.commit(p,budget=b)
        w.execute_store(t,budget=b);w.park(t,budget=b);w.resume(t,budget=b)
        with self.assertRaisesRegex(ValueError,'effect_replay_or_stage'):w.execute_store(t,budget=b)
        w.complete(t,budget=b);self.assertEqual(len(w.machine.memory.effects),1)

    def test_real_fault_after_prepare_keeps_generation_and_cannot_replay(self):
        w=World();b=budget();p=w.preflight('a',0,SourceValue(Raw.integer(8,42)),budget=b);t=w.commit(p,budget=b)
        w.machine.memory.objects[w.base.origin]['mutable']=False
        with self.assertRaises(GuestFault):w.execute_store(t,budget=b)
        self.assertEqual(w.cells['a'].generation,1);self.assertEqual(w.cursor,1);self.assertEqual(w.machine.memory.effects,[])
        w.machine.memory.objects[w.base.origin]['mutable']=True
        with self.assertRaisesRegex(ValueError,'effect_replay_or_stage'):w.execute_store(t,budget=b)
        w.cancel(t,budget=b);self.assertTrue(w.cells['a'].live)

    def test_cancellation_after_store_retains_committed_bytes_and_init(self):
        w=World();b=budget();p=w.preflight('a',0,SourceValue(Raw.integer(8,42)),budget=b);t=w.commit(p,budget=b)
        w.execute_store(t,budget=b);w.cancel(t,budget=b)
        self.assertEqual(w.load(w.base,1).numeric(types=w.machine.types,reference=ref(1)),Value(ref(1),'concrete',42));self.assertTrue(w.cells['a'].live)
        self.assertEqual(len(w.machine.memory.effects),1)

    def test_random_overlapping_moves_match_independent_byte_and_mask_oracle(self):
        rng=random.Random(0x554e494f4e)
        for _ in range(100):
            w=World(16);values=[rng.randrange(256) for i in range(16)];init=[rng.randrange(256) for i in range(16)]
            for i,x in enumerate(values):w.machine.memory.raw_store(w.pointer(i),Raw.integer(8,x))
            w.init[w.base.origin]=sum(x<<(8*i) for i,x in enumerate(init))
            count=rng.randrange(1,17);src=rng.randrange(17-count);dst=rng.randrange(17-count)
            expected=values[:];expected_i=init[:];expected[dst:dst+count]=values[src:src+count];expected_i[dst:dst+count]=init[src:src+count]
            w.copy(w.pointer(dst),w.pointer(src),count,overlap=True)
            self.assertEqual([w.machine.memory.raw_load(w.pointer(i),1).bits for i in range(16)],expected)
            self.assertEqual(w.init[w.base.origin],sum(x<<(8*i) for i,x in enumerate(expected_i)))

    def test_no_source_fact_or_runtime_authority_is_claimed(self):
        w=World();v=SourceValue(Raw.integer(8,42))
        self.assertFalse(w.source_fact_authority);self.assertFalse(w.runtime_authority)
        self.assertFalse(w.semantic_admission);self.assertFalse(w.cost_profile_qualified)
        self.assertFalse(v.source_fact_authority);self.assertFalse(v.runtime_authority)


    def test_untracked_allocation_load_rejects_before_physical_read(self):
        w=World();extra=w.machine.memory.allocate(1,1)
        self.assertNotIn(extra.origin,w.init)
        observed=[];original=w.machine.memory.raw_load
        def spy(*args):observed.append(args);return original(*args)
        w.machine.memory.raw_load=spy
        with self.assertRaisesRegex(ValueError,'unmodeled_allocation'):w.load(extra,1)
        self.assertEqual(observed,[]);self.assertNotIn(extra.origin,w.init)

    def test_untracked_allocation_store_rejects_before_physical_write(self):
        w=World();extra=w.machine.memory.allocate(1,1)
        before=w.machine.memory.raw_load(extra,1);init=dict(w.init)
        with self.assertRaisesRegex(ValueError,'unmodeled_allocation'):w.store(extra,SourceValue(Raw.integer(8,42)))
        self.assertEqual(w.machine.memory.raw_load(extra,1),before)
        self.assertEqual(w.init,init);self.assertEqual(w.machine.memory.effects,[])

    def test_untracked_copy_source_and_destination_reject_before_access(self):
        for source_outside in [False,True]:
            w=World();extra=w.machine.memory.allocate(1,1)
            before=w.machine.memory.raw_load(w.base,8);outside=w.machine.memory.raw_load(extra,1);init=dict(w.init)
            source,destination=(extra,w.base) if source_outside else (w.base,extra)
            calls=[];guard=w.machine.memory.guard
            def spy(*args,**kwargs):calls.append(args);return guard(*args,**kwargs)
            w.machine.memory.guard=spy
            with self.assertRaisesRegex(ValueError,'unmodeled_allocation'):w.copy(destination,source,1)
            self.assertEqual(calls,[])
            w.machine.memory.guard=guard
            self.assertEqual(w.machine.memory.raw_load(w.base,8),before);self.assertEqual(w.machine.memory.raw_load(extra,1),outside)
            self.assertEqual(w.init,init);self.assertEqual(w.machine.memory.effects,[])

    def test_untracked_preflight_pointer_rejects_before_budget_or_frontier(self):
        w=World();extra=w.machine.memory.allocate(1,1);w.pointer=lambda offset:extra;b=budget()
        with self.assertRaisesRegex(ValueError,'unmodeled_allocation'):w.preflight('a',0,SourceValue(Raw.integer(8,42)),budget=b)
        self.assertEqual((b._used_work,b._used_edges,b._used_copied_bytes),(0,0,0))
        self.assertEqual((w.cells,w.prepared,w.cursor,w.machine.memory.effects),({},{},0,[]))

    def test_missing_modeled_init_entry_never_defaults_to_initialized(self):
        w=World();del w.init[w.base.origin]
        for action in [lambda:w.load(w.base,1),lambda:w.store(w.base,SourceValue(Raw.integer(8,42))),
                       lambda:w.copy(w.pointer(1),w.base,1),lambda:w.preflight('a',0,SourceValue(Raw.integer(8,42)),budget=budget())]:
            with self.assertRaisesRegex(ValueError,'unmodeled_allocation'):action()
        self.assertEqual((w.cells,w.prepared,w.cursor,w.machine.memory.effects),({},{},0,[]))

    def test_manually_added_init_entry_does_not_register_an_allocation(self):
        w=World();extra=w.machine.memory.allocate(1,1);w.init[extra.origin]=0
        with self.assertRaisesRegex(ValueError,'unmodeled_allocation'):w.load(extra,1)
        with self.assertRaisesRegex(ValueError,'unmodeled_allocation'):w.store(extra,SourceValue(Raw.integer(8,42)))
        self.assertEqual(w.machine.memory.effects,[])

    def test_lost_init_after_preflight_rejects_commit_before_lifetime_change(self):
        w=World();b=budget();p=w.preflight('a',0,SourceValue(Raw.integer(8,42)),budget=b)
        del w.init[w.base.origin]
        with self.assertRaisesRegex(ValueError,'unmodeled_allocation'):w.commit(p,budget=b)
        self.assertEqual((w.cells,w.cursor,w.machine.memory.effects),({},0,[]))


    def test_numeric_inrange_fragment_matches_actual_core_rejection(self):
        w=World();extra=w.machine.memory.allocate(8,1)
        derived=w.machine.memory.offset(extra,0,False,False,False,inrange={'lower':0,'upper':8})
        raw=Raw.pointer(derived).slice(0,8)
        for convert in [lambda:from_raw(w.machine.types,ref(1),raw),
                        lambda:SourceValue(raw,0).numeric(types=w.machine.types,reference=ref(1))]:
            with self.assertRaises(GuestFault) as error:convert()
            self.assertEqual(error.exception.code,'ub_inrange_address_conversion');self.assertTrue(error.exception.language_ub)

    def test_numeric_ordinary_origin_is_stripped_by_actual_core(self):
        w=World();raw=Raw.pointer(w.base).slice(0,8)
        self.assertTrue(raw.origins)
        actual=SourceValue(raw,0).numeric(types=w.machine.types,reference=ref(1))
        self.assertEqual(actual,from_raw(w.machine.types,ref(1),raw))
        self.assertEqual(actual,Value(ref(1),'concrete',raw.bits))
        self.assertEqual(raw.origins[0].pointer,w.base)

    def test_numeric_preserves_actual_core_poison_and_undef_conversion(self):
        w=World()
        for raw in [Raw.integer(8,0xa5,poison=1),Raw.integer(8,0xa5,undef=0xf0),Raw.integer(8,42)]:
            self.assertEqual(SourceValue(raw,0).numeric(types=w.machine.types,reference=ref(1)),from_raw(w.machine.types,ref(1),raw))
        self.assertEqual(SourceValue(Raw.integer(8,0xa5,poison=1),0).numeric(types=w.machine.types,reference=ref(1)),Value(ref(1),'poison'))
        self.assertEqual(SourceValue(Raw.integer(8,0xa5,undef=0xf0),0).numeric(types=w.machine.types,reference=ref(1)),Value(ref(1),'concrete',5))

    def test_numeric_poison_range_precedence_is_actual_core(self):
        w=World();derived=w.machine.memory.offset(w.base,0,False,False,False,inrange={'lower':0,'upper':8})
        original=Raw.pointer(derived);part=original.slice(8,56)
        from candidate.raw import Span
        raw=Raw(64,original.bits,255,(Span(8,56,derived,8),))
        actual=SourceValue(raw,0).numeric(types=w.machine.types,reference=ref(3))
        self.assertEqual(actual,from_raw(w.machine.types,ref(3),raw));self.assertEqual(actual,Value(ref(3),'poison'))

    def test_numeric_source_init_guard_precedes_core_poison_or_range(self):
        w=World();derived=w.machine.memory.offset(w.base,0,False,False,False,inrange={'lower':0,'upper':8})
        raw=Raw.pointer(derived).slice(0,8)
        for value in [SourceValue(raw,1),SourceValue(Raw.integer(8,1,poison=1),1)]:
            with self.assertRaisesRegex(ValueError,'source_indeterminate_numeric_use'):value.numeric(types=w.machine.types,reference=ref(1))

    def test_numeric_requires_explicit_exact_integer_destination(self):
        w=World();value=SourceValue(Raw.integer(8,42))
        with self.assertRaises(TypeError):value.numeric()
        for typeref in [ref(2),ref(17),ref(7)]:
            with self.assertRaisesRegex(ValueError,'numeric_destination'):value.numeric(types=w.machine.types,reference=typeref)

class FixtureTests(unittest.TestCase):
    def test_closed_schema_and_actual_scenario_observations(self):
        from . import fixtures,reference
        self.assertEqual(reference.run_cases(fixtures.document()),14)

    def test_schema_rejects_unknown_authority_and_exact_integer_mutations(self):
        from copy import deepcopy
        from . import fixtures,reference
        for modify in [lambda d:d.update(source_fact_authority=True),lambda d:d.update(runtime_authority=True),
                       lambda d:d.update(extra=0),lambda d:d['cases'][0]['expected'].update(physical=True),
                       lambda d:d['cases'][0].update(scenario='unknown'),lambda d:d['cases'].append(d['cases'][0])]:
            d=deepcopy(fixtures.document());modify(d)
            with self.assertRaises(ValueError):reference.validate(d)

    def test_wrong_authored_expectation_fails_actual_observation(self):
        from . import fixtures,reference
        d=fixtures.document();d['cases'][0]['expected']=dict(d['cases'][0]['expected'],physical=43)
        with self.assertRaisesRegex(ValueError,'UNION_REFERENCE_OBSERVATION_MISMATCH'):reference.run_cases(d)

    def test_original_fixture_products_reproduce_without_writing(self):
        from . import fixtures
        before={p.name:p.read_bytes() for p in fixtures.FOLDER.iterdir() if p.is_file()}
        fixtures.check()
        self.assertEqual({p.name:p.read_bytes() for p in fixtures.FOLDER.iterdir() if p.is_file()},before)

    def test_exact_test_inventory_is_complete_and_unique(self):
        from . import fixtures
        import sys
        tests=fixtures.document()['tests']
        names=sorted('union_prestore.test_reference.'+cls.__name__+'.'+name
            for cls in [ProtocolTests,FixtureTests] for name in unittest.defaultTestLoader.getTestCaseNames(cls))
        self.assertEqual(tests,names);self.assertEqual(len(tests),len(set(tests)))

    def test_verified_execution_fixture_has_no_execution_test_module_dependency(self):
        import sys
        from candidate.values import Value
        from candidate.type_system import ref
        self.assertNotIn('test_candidate',sys.modules);self.assertNotIn('test_candidate_memory',sys.modules)
        w=World();w.machine.start(0,[])
        self.assertEqual(w.machine.run()['values'],[Value(ref(2),'concrete',42)])

if __name__=='__main__':unittest.main(verbosity=2)

