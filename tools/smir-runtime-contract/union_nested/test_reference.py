from dataclasses import replace
import random,unittest
from .model import (NestedWorld,Refusal,Index,Candidate,SourceValue,Raw,Pointer,Value,ref,GuestFault,mask,arm,_api)

def budget(**kw):
    limits=dict(max_work=10**8,max_edges=10**7,max_copied_bytes=10**8,max_depth=64);limits.update(kw)
    return _api().SourceQueryBudget(**limits)

def make(**kw):
    b=budget();w=NestedWorld(budget=b,**kw);r=w.register(budget=b);return w,r,b

def path(w,r,outer='aggregate',inner='left',**kw):
    window=w._lookup(w.windows,r)
    return (Candidate('outer',outer,Index(window.logical_index,128,False,window.bound)),)+( (Candidate('inner',inner,Index(0),**kw),) if inner is not None else ())

def value(n=42,i=0):return SourceValue(Raw.integer(8,n),i)
def assign(w,r,b,outer='aggregate',inner='left',byte=0,v=None,designation=None):
    p=w.preflight(r,path(w,r,outer,inner),value() if v is None else v,byte=byte,designation=designation,budget=b)
    t=w.commit(p,budget=b);w.execute_store(t,budget=b);w.complete(t,budget=b);return p,t

def snapshot(w):return (dict(w.states),w.cursor,w.ref_serial,w.active,list(w.machine.memory.effects),len(w.plans),len(w.tickets))

class NestedTests(unittest.TestCase):
    def test_actual_verified_store_creates_both_generations_once(self):
        w,r,b=make();p,t=assign(w,r,b)
        s=w._state(r);self.assertEqual((arm(s,'aggregate').generation,s.container_generation,arm(s,'left',True).generation),(1,1,1))
        self.assertEqual(w.load(r,0,1,budget=b).numeric(types=w.machine.types,reference=ref(1)),Value(ref(1),'concrete',42))
        self.assertEqual(w.machine.memory.effects,[('store','none','none',False)]);self.assertEqual(w.cursor,2)
        for f in [lambda:w.commit(p,budget=b),lambda:w.execute_store(t,budget=b),lambda:w.complete(t,budget=b)]:
            with self.assertRaises(Refusal):f()
        self.assertEqual(len(w.machine.memory.effects),1)

    def test_inner_readonly_after_valid_readonly_outer_guard_publishes_nothing(self):
        w,r,b=make();base=w._lookup(w.windows,r).pointer
        w.machine.memory.objects[base.origin]['mutable']=False;before=snapshot(w);calls=[];original=w.machine.memory.guard
        def spy(*args,**kw):calls.append(kw.get('write',False));return original(*args,**kw)
        w.machine.memory.guard=spy
        with self.assertRaises(GuestFault) as e:w.preflight(r,path(w,r),value(),budget=b)
        self.assertEqual(e.exception.code,'memory_permission');self.assertEqual(calls,[False,True]);self.assertEqual(snapshot(w),before)

    def test_inner_bounds_failure_has_no_outer_publication(self):
        w,r,b=make();before=snapshot(w);p=w.pointer(r,16)
        with self.assertRaises(GuestFault) as e:w.preflight(r,path(w,r,pointer=p),value(),budget=b)
        self.assertEqual(e.exception.code,'memory_bounds');self.assertEqual(snapshot(w),before)

    def test_inner_unmodeled_allocation_rejects_before_outer_publication(self):
        w,r,b=make();extra=w.machine.memory.allocate(8,1);before=snapshot(w)
        with self.assertRaisesRegex(Refusal,'unmodeled_allocation'):w.preflight(r,path(w,r,pointer=extra),value(),budget=b)
        self.assertEqual(snapshot(w),before)

    def test_inner_phase_assumption_is_explicit_unavailable_before_guards(self):
        for phase in ['initializing','unknown',True]:
            w,r,b=make();before=snapshot(w);calls=[];original=w.machine.memory.guard
            def spy(*args,**kw):calls.append(1);return original(*args,**kw)
            w.machine.memory.guard=spy
            with self.assertRaises(Refusal) as e:w.preflight(r,path(w,r,phase=phase),value(),budget=b)
            self.assertEqual(e.exception.kind,'unavailable');self.assertEqual(calls,[]);self.assertEqual(snapshot(w),before)

    def test_quota_exact_and_one_less_all_dimensions_no_partial_batch(self):
        trial=budget();w=NestedWorld(budget=trial);r=w.register(budget=trial);w.preflight(r,path(w,r),value(),budget=trial)
        limits=dict(max_work=trial._used_work,max_edges=trial._used_edges,max_copied_bytes=trial._used_copied_bytes)
        b=budget(**limits);w=NestedWorld(budget=b);r=w.register(budget=b);assign(w,r,b)
        for dimension in limits:
            low=dict(limits);low[dimension]-=1;b=budget(**low);w=NestedWorld(budget=b);r=w.register(budget=b);before=snapshot(w)
            with self.assertRaises(_api().SourceDataError) as e:w.preflight(r,path(w,r),value(),budget=b)
            self.assertEqual(e.exception.kind,'resource');self.assertEqual(snapshot(w),before)

    def test_commit_revalidates_inner_guard_before_any_batch_publication(self):
        w,r,b=make();p=w.preflight(r,path(w,r),value(),budget=b);before=snapshot(w)
        w.machine.memory.objects[w.pointer(r).origin]['mutable']=False
        with self.assertRaises(GuestFault):w.commit(p,budget=b)
        self.assertEqual(snapshot(w),before)

    def test_real_fault_after_commit_retains_all_births_no_repeat(self):
        w,r,b=make();p=w.preflight(r,path(w,r),value(),budget=b);t=w.commit(p,budget=b);s=w._state(r)
        w.machine.memory.objects[w.pointer(r).origin]['mutable']=False
        with self.assertRaises(GuestFault):w.execute_store(t,budget=b)
        self.assertIs(w._state(r),s);self.assertEqual(w.cursor,1);self.assertEqual(w.machine.memory.effects,[])
        w.machine.memory.objects[w.pointer(r).origin]['mutable']=True
        with self.assertRaises(Refusal):w.execute_store(t,budget=b)
        w.cancel(t,budget=b);self.assertIs(w._state(r),s)

    def test_park_before_and_after_store_no_repeated_lifetime_or_effect(self):
        w,r,b=make();p=w.preflight(r,path(w,r),value(),budget=b);t=w.commit(p,budget=b)
        w.park(t,budget=b)
        with self.assertRaises(Refusal):w.execute_store(t,budget=b)
        w.resume(t,budget=b);w.execute_store(t,budget=b);w.park(t,budget=b);w.resume(t,budget=b)
        with self.assertRaises(Refusal):w.resume(t,budget=b)
        with self.assertRaises(Refusal):w.execute_store(t,budget=b)
        w.complete(t,budget=b);self.assertEqual(w.cursor,2);self.assertEqual(len(w.machine.memory.effects),1)
        self.assertEqual(arm(w._state(r),'left',True).generation,1)

    def test_cancel_after_store_keeps_both_generation_and_initialized_byte(self):
        w,r,b=make();p=w.preflight(r,path(w,r),value(),budget=b);t=w.commit(p,budget=b);w.execute_store(t,budget=b);w.cancel(t,budget=b)
        self.assertEqual(w.load(r,0,1,budget=b).indeterminate,0);self.assertEqual(w.cursor,1);self.assertEqual(len(w.machine.memory.effects),1)
        self.assertTrue(arm(w._state(r),'left',True).live)

    def test_same_parent_switch_child_preserves_sibling_and_parent_generation(self):
        w,r,b=make();assign(w,r,b);w.store_value(r,8,value(17),budget=b);parent=arm(w._state(r),'aggregate').generation
        assign(w,r,b,inner='right');s=w._state(r)
        self.assertEqual(arm(s,'aggregate').generation,parent);self.assertFalse(arm(s,'left',True).live)
        self.assertEqual(w.load(r,8,1,budget=b).numeric(types=w.machine.types,reference=ref(1)).data,17)
        self.assertEqual(w.load(r,1,1,budget=b).indeterminate,255)

    def test_parent_replacement_invalidates_descendants_and_preserves_physical(self):
        w,r,b=make();assign(w,r,b,byte=1,v=value(17));h=w.prospective(r,inner='left',budget=b)
        assign(w,r,b,outer='alternate',inner=None,byte=0);s=w._state(r)
        self.assertFalse(s.container_live);self.assertTrue(all(not a.live for a in s.inner))
        self.assertEqual(w.machine.memory.raw_load(w.pointer(r,1),1).bits,17)
        self.assertEqual(w.load(r,1,1,budget=b).indeterminate,255)
        with self.assertRaisesRegex(Refusal,'stale_or_unborn'):w.resolve(h)

    def test_prospective_unborn_ancestor_and_leaf_bind_first_birth(self):
        w,r,b=make();h=w.prospective(r,inner='left',budget=b)
        with self.assertRaises(Refusal):w.resolve(h)
        assign(w,r,b,designation=h);target=w.resolve(h)
        self.assertEqual((target.outer_generation,target.container_generation,target.inner_generation),(1,1,1))

    def test_unused_first_ancestor_birth_never_retargets_later_parent(self):
        w,r,b=make();h=w.prospective(r,inner='left',budget=b)
        assign(w,r,b,inner=None,byte=8);assign(w,r,b,outer='alternate',inner=None);assign(w,r,b)
        with self.assertRaisesRegex(Refusal,'stale_or_unborn'):w.resolve(h)
        before=snapshot(w)
        with self.assertRaisesRegex(Refusal,'stale_or_wrong'):w.preflight(r,path(w,r),value(),designation=h,budget=b)
        self.assertEqual(snapshot(w),before)

    def test_unused_first_child_birth_never_retargets_later_child(self):
        w,r,b=make();h=w.prospective(r,inner='left',budget=b)
        assign(w,r,b);assign(w,r,b,inner='right');assign(w,r,b,inner='left')
        with self.assertRaisesRegex(Refusal,'stale_or_unborn'):w.resolve(h)
        self.assertEqual(w.resolve(w.prospective(r,inner='left',budget=b)).inner_generation,2)

    def test_equal_bits_distinct_real_origins_never_select_by_address(self):
        w,r,b=make();other=w.register(budget=b);p=w.pointer(other)
        derived=w.machine.memory.offset(w.pointer(r),p.address-w.pointer(r).address,False,False,False)
        self.assertEqual(Raw.pointer(derived).bits,Raw.pointer(p).bits)
        self.assertNotEqual(derived.origin,p.origin)
        before=snapshot(w)
        with self.assertRaisesRegex(Refusal,'unmodeled_allocation'):w.preflight(other,path(w,other,pointer=derived),value(),budget=b)
        self.assertEqual(snapshot(w),before)

    def test_unknown_initialization_state_rejects_not_default_initialized(self):
        w,r,b=make();assign(w,r,b);w.expire_model_state(r);before=snapshot(w)
        for f in [lambda:w.preflight(r,path(w,r),value(),budget=b),lambda:w.load(r,0,1,budget=b),lambda:w.store_value(r,0,value(),budget=b)]:
            with self.assertRaisesRegex(Refusal,'model_state_unknown'):f()
        self.assertEqual(snapshot(w),before)

    def test_foreign_cloned_window_plan_ticket_and_budget_reject(self):
        w,r,b=make();other,foreign,fb=make()
        for token in [foreign,replace(r)]:
            with self.assertRaisesRegex(Refusal,'foreign_or_cloned'):w.preflight(token,path(w,r),value(),budget=b)
        p=w.preflight(r,path(w,r),value(),budget=b)
        with self.assertRaises(Refusal):w.commit(replace(p),budget=b)
        with self.assertRaisesRegex(Refusal,'budget_changed'):w.commit(p,budget=budget())
        t=w.commit(p,budget=b)
        with self.assertRaises(Refusal):w.execute_store(replace(t),budget=b)
        with self.assertRaisesRegex(Refusal,'budget_changed'):w.execute_store(t,budget=fb)

    def test_actual_generation_exhaustion_rolls_back_entire_nested_plan(self):
        w,r,b=make(max_generation=1);assign(w,r,b);assign(w,r,b,outer='alternate',inner=None)
        before=snapshot(w)
        with self.assertRaisesRegex(Refusal,'generation_exhaustion'):w.preflight(r,path(w,r),value(),budget=b)
        self.assertEqual(snapshot(w),before)

    def test_original_128_bit_invalid_index_never_reaches_physical_guard(self):
        for index in [Index(-1,128,True,8),Index((1<<64)+5,128,False,10),Index(10,128,False,10)]:
            w,r,b=make();cs=path(w,r);cs=(cs[0],replace(cs[1],index=index));calls=[];original=w.machine.memory.guard
            def spy(*args,**kw):calls.append(1);return original(*args,**kw)
            w.machine.memory.guard=spy;before=snapshot(w)
            with self.assertRaises(Refusal):w.preflight(r,cs,value(),budget=b)
            self.assertEqual(calls,[]);self.assertEqual(snapshot(w),before)

    def test_symbolic_huge_extent_allocates_only_selected_window(self):
        b=budget();w=NestedWorld(budget=b);n=1<<40;r=w.register(logical_index=n-1,bound=n,budget=b);assign(w,r,b)
        self.assertEqual(len(w.machine.memory.objects),1);self.assertEqual(sum(o['size']for o in w.machine.memory.objects.values()),16)
        self.assertEqual(len(w._state(r).outer)+len(w._state(r).inner),4);self.assertLess(b._used_work,1000)

    def test_core_numeric_inrange_and_sticky_init_behavior_is_preserved(self):
        w,r,b=make();assign(w,r,b)
        raw=w.load(r,1,1,budget=b).freeze();self.assertEqual(raw.indeterminate,255)
        w.store_value(r,0,raw,budget=b)
        with self.assertRaisesRegex(ValueError,'source_indeterminate_numeric_use'):w.load(r,0,1,budget=b).numeric(types=w.machine.types,reference=ref(1))
        p=w.machine.memory.offset(w.pointer(r),0,False,False,False,inrange={'lower':0,'upper':8})
        with self.assertRaises(GuestFault) as e:SourceValue(Raw.pointer(p).slice(0,8),0).numeric(types=w.machine.types,reference=ref(1))
        self.assertEqual(e.exception.code,'ub_inrange_address_conversion')

    def test_full_copy_transfers_physical_origin_not_projected_init_raw(self):
        w,r,b=make();other=w.register(budget=b);assign(w,r,b);assign(w,other,b)
        raw=Raw.pointer(w.pointer(r));w.machine.memory.raw_store(w.pointer(r),raw)
        w.copy(other,0,r,0,8,budget=b)
        self.assertEqual(w.machine.memory.raw_load(w.pointer(other),8),raw)
        self.assertEqual(w.load(other,0,8,budget=b).indeterminate,mask(64)^255)
        self.assertEqual([(s.offset,s.length)for s in w.load(other,0,8,budget=b).raw.origins],[(0,8)])

    def test_overlap_snapshots_both_planes_across_inner_sibling_boundary(self):
        rng=random.Random(0x4e455354)
        for _ in range(100):
            w,r,b=make();assign(w,r,b);values=[];init=[]
            for i in range(16):
                x=rng.randrange(256);im=rng.randrange(256);values.append(x);init.append(im);w.store_value(r,i,value(x,im),budget=b)
            count=rng.randrange(1,17);src=rng.randrange(17-count);dst=rng.randrange(17-count)
            expected=values[:];expected_i=init[:];expected[dst:dst+count]=values[src:src+count];expected_i[dst:dst+count]=init[src:src+count]
            w.copy(r,dst,r,src,count,overlap=True,budget=b)
            self.assertEqual([w.machine.memory.raw_load(w.pointer(r,i),1).bits for i in range(16)],expected)
            self.assertEqual(arm(w._state(r),'aggregate').init,sum(v<<(8*i)for i,v in enumerate(expected_i)))
            self.assertEqual(arm(w._state(r),'left',True).init,sum(v<<(8*i)for i,v in enumerate(expected_i[:8])))

    def test_zero_and_wrapping_data_offsets_are_rejected_before_effect(self):
        w,r,b=make();assign(w,r,b);before=snapshot(w)
        for offset,count in [(1<<64,1),(-1,1),(16,1),(0,0)]:
            with self.assertRaises(Refusal):w.load(r,offset,count,budget=b)
        self.assertEqual(snapshot(w),before)

    def test_no_authority_or_source_event_is_created(self):
        w,r,b=make();assign(w,r,b)
        self.assertFalse(w.source_fact_authority);self.assertFalse(w.runtime_authority)
        self.assertFalse(w.semantic_admission);self.assertFalse(w.cost_profile_qualified)
        self.assertFalse(w.load(r,0,1,budget=b).source_fact_authority)


    def test_actual_store_then_host_failure_marks_unknown_without_replay(self):
        w,r,b=make();p=w.preflight(r,path(w,r),value(),budget=b);t=w.commit(p,budget=b)
        original=w.machine.memory_operation;calls=[]
        def observed(*args):
            calls.append(1);result=original(*args);raise MemoryError('after actual store')
        w.machine.memory_operation=observed
        with self.assertRaises(MemoryError):w.execute_store(t,budget=b)
        self.assertEqual(w.machine.memory.raw_load(w.pointer(r),1).bits,42)
        self.assertEqual(len(w.machine.memory.effects),1)
        with self.assertRaisesRegex(Refusal,'model_state_unknown'):w.load(r,0,1,budget=b)
        with self.assertRaises(Refusal):w.execute_store(t,budget=b)
        self.assertEqual(calls,[1]);w.cancel(t,budget=b)
        self.assertFalse(w.states[id(r)].known);self.assertEqual(arm(w.states[id(r)],'aggregate').generation,1)

    def test_prepared_state_version_changes_require_new_plan(self):
        w,r,b=make();assign(w,r,b);p=w.preflight(r,path(w,r),value(),budget=b)
        w.store_value(r,8,value(17),budget=b);before=snapshot(w)
        with self.assertRaisesRegex(Refusal,'stale_prepare'):w.commit(p,budget=b)
        self.assertEqual(snapshot(w),before);assign(w,r,b,inner='right')
        self.assertEqual(w.load(r,8,1,budget=b).numeric(types=w.machine.types,reference=ref(1)).data,17)

    def test_authored_fixtures_execute_actual_model_and_compare(self):
        from . import reference as union_nested_witness
        self.assertEqual(union_nested_witness.check(),9)


    def test_fixture_schema_rejects_authority_unknown_and_boolean_integer_alias(self):
        import copy,json
        from . import reference as union_nested_witness
        d=json.loads((union_nested_witness.FOLDER/'cases.json').read_bytes())
        for mutate in [lambda x:x.update(source_fact_authority=True),lambda x:x.update(extra=0),
                       lambda x:x['cases'][0]['expected'].update(stores=True)]:
            candidate=copy.deepcopy(d);mutate(candidate)
            with self.assertRaises(ValueError):union_nested_witness.check(candidate)


