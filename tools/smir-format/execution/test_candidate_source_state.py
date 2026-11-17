"""Authored conditional source-state cases and independent finite AP oracle."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from candidate.source_data_projection import source_api
from candidate.source_state import SourceStateError, _Model, _Range, _intersects, verify

FIXTURES = Path(__file__).resolve().parents[3] / 'docs/specifications/smir/portable/conformance/execution/source-state'


def ledger(**changes):
    limits = dict(max_work=10**9, max_edges=10**9, max_copied_bytes=10**9, max_depth=128)
    limits.update(changes)
    return source_api().SourceQueryBudget(**limits)


def base(count=3):
    pattern = dict(id='member', source_anchor='anchor', object_generation=1, canonical_cell='member_path',
                   initialization_schedule='init', cleanup_schedule='cleanup', count=count, required_prefix=count)
    history = dict(source_anchor='anchor', object_generation=1, initialization_schedule='init',
                   pattern='member', initialized_prefix=count)
    current = dict(source_anchor='anchor', object_generation=1, cleanup_schedule='cleanup', pattern='member',
                   first=0, count=count, lifetime_generation=1, ordinal_first=1,
                   ordinal_step=1 if count > 1 else 0)
    return dict(format='conditional-source-state', revision=1, binding='unbound', original_source_binding='unresolved',
        runtime_authority=False, source_fact_authority=False,
        anchors=[dict(id='anchor', object_generation=1, complete_owner='anchor', stage='constructing')],
        schedules=[dict(id=name, source_anchor='anchor', object_generation=1, kind=kind, patterns=['member'])
                   for name, kind in [('init', 'initialization'), ('cleanup', 'cleanup')]],
        patterns=[pattern], initialization=[history], current=[current] if count else [], ended=[], actions=[])


def effect(kind, first=1, count=1, generation=1):
    return dict(kind=kind, source_anchor='anchor', object_generation=1, cleanup_schedule='cleanup',
                pattern='member', first=first, count=count, lifetime_generation=generation)


def publish():
    return dict(kind='publish', source_anchor='anchor', object_generation=1, initialization_schedule='init')


def replacement(first=1, count=1, old=1, new=2):
    return dict(kind='replace', source_anchor='anchor', object_generation=1, cleanup_schedule='cleanup',
                pattern='member', first=first, count=count, old_lifetime_generation=old, new_lifetime_generation=new)


def observe(index, generation):
    return dict(kind='observe', source_anchor='anchor', object_generation=1, pattern='member',
                index=index, lifetime_generation=generation)


def cases():
    result = []
    def add(name, document, code=None):
        result.append(dict(name=name, expected={'kind':'static'} if code is None else {'kind':'semantic','code':code}, document=document))
    d=base();d['actions']=[effect('end'),publish()]
    add('history_complete_current_middle_hole_can_publish',d)
    d=base();d['actions']=[effect('end'),replacement(),publish(),observe(1,2)]
    add('reconstruction_fresh_generation_history_unchanged',d)
    d=deepcopy(d);d['actions'].append(observe(1,1))
    add('old_lifetime_alias_stays_stale',d,'SS_STALE_LIFETIME')
    d=base();d['initialization'][0]['initialized_prefix']=0;d['actions']=[publish()]
    add('current_full_cannot_invent_missing_original_history',d,'SS_INITIALIZATION_INCOMPLETE')
    d=base();d['initialization'][0]['initialized_prefix']=0
    d['actions']=[dict(kind='initialize',source_anchor='anchor',object_generation=1,initialization_schedule='init',pattern='member',next_prefix=3),publish()]
    add('explicit_original_schedule_completion_then_publication',d)
    d=deepcopy(d);d['actions'].insert(1,deepcopy(d['actions'][0]))
    add('initialization_effect_cannot_replay',d,'SS_HISTORY_PROGRESS')
    d=base();d['actions']=[effect('end'),effect('cleanup',2),effect('cleanup',0),publish()]
    add('cleanup_skips_ended_middle_cell_without_losing_history',d)
    d=base();d['actions']=[effect('cleanup',0)]
    add('cleanup_requires_reverse_current_source_order',d,'SS_CLEANUP_ORDER')
    d=base();d['actions']=[effect('end'),replacement(),effect('cleanup',2),effect('cleanup',1,generation=2),effect('cleanup',0)]
    add('replaced_middle_cell_uses_fresh_current_lifetime_in_cleanup',d)
    d=base(10**12);d['actions']=[effect('end',10**6,10**6),publish()]
    add('huge_extent_middle_hole_stays_three_symbolic_ranges',d)
    d=base(10**12);d['actions']=[effect('cleanup',0,10**12),publish()]
    add('huge_uniform_cleanup_has_no_extent_loop',d)
    add('empty_selected_pattern_no_current_cells',base(0))
    d=base();d['patterns'][0]['required_prefix']=0;d['initialization'][0]['initialized_prefix']=0;d['current']=[];d['actions']=[publish()]
    add('unselected_original_implicit_or_union_pattern_stays_absent',d)
    d=deepcopy(d);d['initialization'][0]['initialized_prefix']=1
    add('current_selection_cannot_rewrite_original_init_history',d,'SS_HISTORY_SELECTION')
    d=base();d['actions']=[publish(),publish()]
    add('publication_once',d,'SS_PUBLICATION_REPLAY')
    d=base();d['actions']=[publish(),dict(kind='initialize',source_anchor='anchor',object_generation=1,initialization_schedule='init',pattern='member',next_prefix=3)]
    add('history_cannot_change_after_publication',d,'SS_HISTORY_AFTER_PUBLICATION')
    for field,value,code in [('count',0,'SS_RANGE_BOUNDS'),('first',3,'SS_RANGE_BOUNDS'),
        ('ordinal_step',0,'SS_ORDINAL'),('ordinal_first',0,'SS_ORDINAL'),
        ('ordinal_first',2**64-1,'SS_ORDINAL'),('lifetime_generation',0,'SS_ORDINAL')]:
        d=base();d['current'][0][field]=value;add('invalid_range_'+field+'_'+str(value),d,code)
    d=base(1);d['current'][0]['ordinal_step']=1
    add('singleton_step_is_canonical_zero',d,'SS_ORDINAL')
    d=base();d['current'].append(deepcopy(d['current'][0]))
    add('same_source_cell_cannot_have_two_current_ranges',d,'SS_CELL_OVERLAP')
    d=base();d['ended'].append(deepcopy(d['current'][0]))
    add('source_cell_cannot_be_current_and_ended',d,'SS_CELL_OVERLAP')
    d=base();d['actions']=[effect('end',generation=2)]
    add('end_wrong_current_lifetime_generation',d,'SS_STALE_LIFETIME')
    d=base();d['actions']=[replacement()]
    add('replacement_needs_original_ended_cell',d,'SS_CURRENT_HOLE')
    d=base();d['actions']=[effect('end'),replacement(new=3)]
    add('replacement_generation_must_advance_exactly_once',d,'SS_LIFETIME_GENERATION')
    d=base();d['actions']=[effect('end'),effect('end')]
    add('end_does_not_replay_over_hole',d,'SS_CURRENT_HOLE')
    d=base();d['actions']=[effect('end')];d['actions'][0]['object_generation']=2
    add('stale_source_anchor_object_generation',d,'SS_OBJECT_GENERATION')
    d=base();d['actions']=[effect('end')];d['actions'][0]['cleanup_schedule']='invented'
    add('forged_schedule_label_cannot_change_cell_membership',d,'SS_SCHEDULE_MEMBERSHIP')
    d=base();d['patterns'].append({**d['patterns'][0],'id':'duplicate'})
    for s in d['schedules']:s['patterns'].append('duplicate')
    d['initialization'].append({**d['initialization'][0],'pattern':'duplicate'})
    add('renamed_pattern_cannot_duplicate_canonical_source_cell',d,'SS_CANONICAL_CELL_DUPLICATE')
    d=base();d['schedules'][0]['patterns']=[]
    add('schedule_membership_must_be_bidirectional',d,'SS_SCHEDULE_MEMBERSHIP')
    d=base();d['schedules'].append({**d['schedules'][0],'id':'other_init','patterns':[]})
    add('one_selected_original_initialization_schedule_per_anchor',d,'SS_INITIALIZATION_SCHEDULE')
    d=base();d['anchors'][0]['complete_owner']='missing'
    add('missing_original_complete_owner',d,'SS_REFERENCE')
    d=base();d['current'][0]['count']=True
    add('bool_is_not_source_count',d,'SS_SHAPE')
    d=base();d['runtime_authority']=True
    add('conditional_document_cannot_request_runtime_authority',d,'SS_SHAPE')
    d=base();d['patterns'][0]['required_prefix']=2
    add('required_original_pattern_is_selected_whole_or_absent',d,'SS_HISTORY_SELECTION')
    d=base();d['anchors'][0]['stage']='published';d['initialization'][0]['initialized_prefix']=2
    add('claimed_published_input_still_needs_original_history',d,'SS_INITIALIZATION_INCOMPLETE')
    d=base(1)
    d['ended']=d['current'];d['current']=[]
    d['patterns'].append({**d['patterns'][0],'id':'alternative','canonical_cell':'alternative_path','required_prefix':0})
    for schedule in d['schedules']:schedule['patterns'].append('alternative')
    d['initialization'].append({**d['initialization'][0],'pattern':'alternative','initialized_prefix':0})
    d['current'].append({**d['ended'][0],'pattern':'alternative'})
    d['actions']=[publish()]
    add('historical_ended_ordinal_does_not_block_current_alternative',d)
    d=deepcopy(d);d['actions']=[replacement(first=0)]
    add('restoring_ended_cell_cannot_duplicate_live_ordinal',d,'SS_ORDINAL_COLLISION')
    return result


class SourceStateTests(unittest.TestCase):
    def test_authored_cases(self):
        stored=json.loads((FIXTURES/'cases.json').read_text())
        self.assertEqual(stored['cases'],cases())
        for case in stored['cases']:
            with self.subTest(case=case['name']):
                before=deepcopy(case['document'])
                if case['expected']['kind']=='static':
                    report=verify(case['document'],budget=ledger())
                    self.assertEqual(report.binding,'unbound')
                    self.assertFalse(report.runtime_authority)
                    self.assertFalse(report.source_fact_authority)
                else:
                    with self.assertRaises(SourceStateError) as error:verify(case['document'],budget=ledger())
                    self.assertEqual(error.exception.code,case['expected']['code'])
                self.assertEqual(case['document'],before)

    def test_history_holes_replacement_and_huge_symbolic_state(self):
        d=base(10**12);d['actions']=[effect('end',10**6,10**6),replacement(10**6,10**6),publish()]
        report=verify(d,budget=ledger())
        self.assertEqual(report.initialization,(('member',10**12),))
        self.assertEqual(len(report.current),3)
        middle=next(row for row in report.current if row[4]==10**6)
        self.assertEqual(middle[6],2)
        self.assertEqual(middle[7],10**6+1)
        with self.assertRaises(FrozenInstanceError):report.runtime_authority=True

    def test_independent_finite_arithmetic_oracle_and_large_progressions(self):
        budget=ledger()
        aps=[(a,n,s) for a in range(1,11) for n in range(1,6) for s in ([0] if n==1 else range(1,6))]
        def r(ap):return _Range('a',1,'s','p',0,ap[1],1,ap[0],ap[2])
        for left in aps:
            explicit={left[0]+i*left[2] for i in range(left[1])}
            for right in aps:
                expected=bool(explicit & {right[0]+i*right[2] for i in range(right[1])})
                self.assertEqual(_intersects(r(left),r(right),budget),expected)
        for left,right,expected in [((1,10**12,2),(2,10**12,2),False),
            ((1,10**12,2),(3,10**12-1,2),True),
            ((2**64-3,2,1),(2**64-2,1,0),True),((2**64-3,2,1),(2**64-1,1,0),False)]:
            self.assertEqual(_intersects(r(left),r(right),budget),expected)

    def test_nested_domains_and_same_domain_collision(self):
        d=base(1)
        d['anchors'].append(dict(id='nested',object_generation=1,complete_owner='anchor',stage='constructing'))
        for s in list(d['schedules']):d['schedules'].append({**s,'id':'nested_'+s['id'],'source_anchor':'nested','patterns':['nested_member']})
        d['patterns'].append({**d['patterns'][0],'id':'nested_member','source_anchor':'nested',
            'initialization_schedule':'nested_init','cleanup_schedule':'nested_cleanup'})
        d['initialization'].append({**d['initialization'][0],'pattern':'nested_member','source_anchor':'nested','initialization_schedule':'nested_init'})
        d['current'].append({**d['current'][0],'pattern':'nested_member','source_anchor':'nested','cleanup_schedule':'nested_cleanup'})
        self.assertEqual(len(verify(d,budget=ledger()).current),2)
        collision=base(1)
        collision['patterns'].append({**collision['patterns'][0],'id':'second','canonical_cell':'another_path'})
        for s in collision['schedules']:s['patterns'].append('second')
        collision['initialization'].append({**collision['initialization'][0],'pattern':'second'})
        collision['current'].append({**collision['current'][0],'pattern':'second'})
        with self.assertRaisesRegex(SourceStateError,'SS_ORDINAL_COLLISION'):verify(collision,budget=ledger())

    def test_interleaved_domains_cleanup_must_not_skip_live_ordinal(self):
        d=base()
        d['current'][0]['ordinal_step']=2
        d['patterns'].append({**d['patterns'][0],'id':'even','canonical_cell':'even_path'})
        for schedule in d['schedules']:schedule['patterns'].append('even')
        d['initialization'].append({**d['initialization'][0],'pattern':'even'})
        d['current'].append({**d['current'][0],'pattern':'even','ordinal_first':2})
        bad=effect('cleanup',0,3);bad['pattern']='even'
        d['actions']=[bad]
        with self.assertRaisesRegex(SourceStateError,'SS_CLEANUP_ORDER'):verify(d,budget=ledger())
        d['actions']=[]
        for index in [2,1,0]:
            even=effect('cleanup',index);even['pattern']='even'
            d['actions'] += [even,effect('cleanup',index)]
        result=verify(d,budget=ledger())
        self.assertEqual(result.current,())
        self.assertEqual(len(result.ended),6)

    def test_bounded_depth_and_cycle_rejection(self):
        with self.assertRaises(SourceStateError) as error:verify(base(),budget=ledger(max_depth=1))
        self.assertEqual((error.exception.kind,error.exception.code),('resource','SS_RESOURCE'))
        cyclic=base();cyclic['actions'].append(cyclic)
        with self.assertRaisesRegex(SourceStateError,'SS_INPUT_CYCLE'):verify(cyclic,budget=ledger())

    def test_real_quota_refusal_preserves_action_state(self):
        d=base();step=effect('end')
        baseline_budget=ledger();baseline=_Model(d,baseline_budget)
        baseline.apply(step);measured=baseline_budget._used_work
        budget=ledger(max_work=measured-1);model=_Model(d,budget);before=model.state
        with self.assertRaises(source_api().SourceDataError) as error:model.apply(step)
        self.assertEqual(error.exception.code,'SOURCE_DATA_RESOURCE')
        self.assertIs(model.state,before)
        self.assertEqual(model.steps,0)
        with self.assertRaises(source_api().SourceDataError):model.apply(step)
        self.assertIs(model.state,before)
        for limit in ['max_work','max_edges','max_copied_bytes']:
            with self.assertRaises(source_api().SourceDataError):verify(base(),budget=ledger(**{limit:0}))
        with self.assertRaisesRegex(SourceStateError,'SS_BUDGET_IDENTITY'):verify(base(),budget=object())


if __name__=='__main__':unittest.main()
