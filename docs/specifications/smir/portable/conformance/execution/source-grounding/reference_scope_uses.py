"""Represented enclosing-scope operands and call reservation boundaries."""
from copy import deepcopy
import unittest
from reference_retained import retained
from candidate.source_grounding import ground,prove_paths,GroundingError
import source_contracts

def enclosing(mode='live'):
    owner,request,budget=retained('stale'if mode=='stale'else'live')
    c=request['carrier']['contract'];c['exits'][0]['outcome']=dict(kind='normal_no_journal')
    value=999 if mode in('undefined','undefined_declared')else 100 if mode=='self'else 101
    scope=c['scopes'][0];scope['within']=dict(kind='scope',value=value)
    enter=next(p for p in c['phase_sites']if p['event']['kind']=='object_begin_root')
    if mode not in('mismatch','undefined_declared'):enter['within']=deepcopy(scope['within'])
    if mode in('earlier_alias','later_alias'):
        site=deepcopy(enter['site']);scope['within']=dict(kind='scope',value=102);enter['within']=deepcopy(scope['within'])
        c['scope_values'].append(dict(id=102,function=0,origin=dict(kind='copy',source=101,site=site)))
        phase=dict(id=12,function=0,site=site,selector=dict(kind='always'),within=dict(kind='scope',value=101),event=dict(kind='scope_value',value=102))
        position=c['phase_sites'].index(enter)+(1 if mode=='later_alias'else 0)
        c['phase_sites'].insert(position,phase)
    return owner,request,budget

class EnclosingUseTests(unittest.TestCase):
    def test_live_declared_and_actual_parent_conditional_positive(self):
        o,d,b=enclosing();r=ground(o,d,budget=b);self.assertEqual(r.path_functions,((0,1),));self.assertFalse(r.runtime_authority)
    def test_matching_stale_parent_refuses_after_actual_public_static(self):
        o,d,b=enclosing('stale');source_contracts.verify(o,d['carrier'],budget=b)
        with self.assertRaisesRegex(GroundingError,'CG_S_STALE'):ground(o,d,budget=b)
    def test_earlier_alias_at_same_actual_site_is_valid(self):
        o,d,b=enclosing('earlier_alias');r=ground(o,d,budget=b);self.assertFalse(r.source_fact_authority)
    def test_later_alias_at_same_actual_site_public_dominance_rejects(self):
        o,d,b=enclosing('later_alias')
        with self.assertRaises(Exception)as caught:ground(o,d,budget=b)
        self.assertEqual(caught.exception.code,'ASC_SCOPE_VALUE_DOMINANCE')
    def test_public_undefined_actual_parent_refuses(self):
        o,d,b=enclosing('undefined')
        with self.assertRaises(Exception)as caught:ground(o,d,budget=b)
        self.assertEqual(caught.exception.code,'ASC_REFERENCE')
    def test_abstract_declared_parent_mismatch_refuses(self):
        o,d,b=enclosing('mismatch')
        with self.assertRaisesRegex(GroundingError,'CG_SCOPE_ENTER_WITHIN'):
            prove_paths(o.sections[3]['functions'][0],d['carrier']['contract'],b)
    def test_abstract_undefined_declared_parent_refuses(self):
        o,d,b=enclosing('undefined_declared')
        with self.assertRaisesRegex(GroundingError,'CG_S_UNDEFINED'):
            prove_paths(o.sections[3]['functions'][0],d['carrier']['contract'],b)
    def test_abstract_not_yet_created_own_parent_refuses(self):
        o,d,b=enclosing('self')
        with self.assertRaisesRegex(GroundingError,'CG_S_UNDEFINED'):
            prove_paths(o.sections[3]['functions'][0],d['carrier']['contract'],b)

class AdoptionBoundaryTests(unittest.TestCase):
    def request(self,kind):
        o,d,b=retained('stale'if kind=='stale'else'live');c=d['carrier']['contract'];c['exits'][0]['outcome']=dict(kind='normal_no_journal')
        # Deliberately direct abstract boundary only: no matching real source call
        # in this sret factory, so these rows are NOT public R-positive fixtures.
        c['adoptions']=[dict(id=9,function=0,receiver=dict(kind='existing',value=101))]
        point=dict(kind='pre_terminator',block=0)
        phase=dict(id=99,function=0,site=point,selector=dict(kind='always'),within=dict(kind='outside'),event=dict(kind='call',return_adoptions=[9]))
        c['phase_sites'].insert(-1,phase)
        return o,d,b
    def test_existing_stale_receiver_not_ignored(self):
        o,d,b=self.request('stale')
        with self.assertRaisesRegex(GroundingError,'CG_S_STALE'):prove_paths(o.sections[3]['functions'][0],d['carrier']['contract'],b)
    def test_existing_live_receiver_protocol_explicitly_unavailable(self):
        o,d,b=self.request('live')
        with self.assertRaisesRegex(GroundingError,'CG_ADOPTION_EXISTING_PROTOCOL_UNAVAILABLE'):prove_paths(o.sections[3]['functions'][0],d['carrier']['contract'],b)
    def test_future_reserved_create_receiver_need_not_be_live_yet(self):
        o,d,b=self.request('live');d['carrier']['contract']['adoptions'][0]['receiver']=dict(kind='create',scope=99,value=999)
        self.assertEqual(prove_paths(o.sections[3]['functions'][0],d['carrier']['contract'],b),1)



class PublicProducerRejectionTests(unittest.TestCase):
    """Grounding must propagate actual repaired R errors on original raw inputs."""
    def require_public_error(self, owner, request, budget, code):
        from source_contracts.checker import ConstraintError
        with self.assertRaises(ConstraintError) as caught:
            ground(owner, request, budget=budget)
        self.assertEqual(caught.exception.code, code)

    def test_declared_parent_mismatch_propagates_actual_R(self):
        self.require_public_error(*enclosing('mismatch'), 'ASC_SCOPE_ENTER_WITHIN')

    def test_undefined_declared_parent_propagates_actual_R(self):
        self.require_public_error(*enclosing('undefined_declared'), 'ASC_REFERENCE')

    def test_self_parent_propagates_actual_strict_R_frontier(self):
        self.require_public_error(*enclosing('self'), 'ASC_SCOPE_VALUE_DOMINANCE')

    def retained_call(self, mode):
        from reference_grounding import fixture
        owner, request, budget = fixture()
        contract = request['carrier']['contract']
        outcome = dict(kind='normal_retained_call', journal=20)
        outcome['return'] = 999 if mode != 'terminal' else 0
        contract['exits'][0]['outcome'] = outcome
        if mode == 'early':
            site = dict(kind='pre_terminator', block=0)
            contract['exits'][0]['site'] = site
            contract['returns'] = []
            for phase in contract['phase_sites']:
                if phase['event'] == dict(kind='scope_exit', exit=0):
                    phase['site'] = deepcopy(site)
        return owner, request, budget

    def test_missing_retained_call_return_propagates_actual_R(self):
        self.require_public_error(*self.retained_call('missing'), 'ASC_REFERENCE')

    def test_terminal_return_cannot_retain_call_propagates_actual_R(self):
        self.require_public_error(*self.retained_call('terminal'), 'ASC_RETURN_RETAINED_OUTCOME')

    def test_nonreturn_retained_call_propagates_actual_R(self):
        self.require_public_error(*self.retained_call('early'), 'ASC_RETURN_BOUNDARY')


if __name__=='__main__':unittest.main(verbosity=2)
