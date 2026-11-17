"""Actual raw API retained-scope use sites, independent from final live-set check."""
from copy import deepcopy
import unittest
from reference_grounding import fixture
from candidate.source_grounding import ground,prove_paths,GroundingError
import source_contracts

def retained(mode='live'):
    owner,request,budget=fixture();c=request['carrier']['contract']
    entry=dict(kind='entry',block=0);out=dict(kind='pre_terminator',block=0)
    c['scopes'].append(dict(id=1,function=0,enter=entry,enter_value=101,subject='existing_object',binding=0,program=None,view=None,within=dict(kind='outside'),lifecycle=None))
    c['scope_values'].append(dict(id=101,function=0,origin=dict(kind='enter',scope=1,phase=10)))
    close=dict(kind='return_exit',block=0)
    if mode=='stale':close=dict(kind='pre_op',block=0,index=0)
    elif mode in ('same_site','saved_alias'):close=deepcopy(out)
    c['exits'].append(dict(id=1,function=0,scope_value=101,site=close,outcome=dict(kind='normal_no_journal')))
    c['phase_sites'].insert(0,dict(id=10,function=0,site=entry,within=dict(kind='outside'),selector=dict(kind='always'),event=dict(kind='object_attach_incoming',scope=1,binding=0)))
    close_phase=dict(id=11,function=0,site=close,within=dict(kind='scope',value=101),selector=dict(kind='always'),event=dict(kind='scope_exit',exit=1))
    c['exits'][0]['site']=out;c['exits'][0]['outcome']=dict(kind='normal_retained_scope',journal=20,retained_scope_value=101)
    for phase in c['phase_sites']:
        if phase['event']==dict(kind='scope_exit',exit=0):phase['site']=deepcopy(out)
    # Preserve authoritative vector order: close first at same site, source exit after.
    if mode in ('stale','same_site','saved_alias'):
        position=next(i for i,p in enumerate(c['phase_sites'])if p['event']==dict(kind='scope_exit',exit=0))
        c['phase_sites'].insert(position,close_phase)
    else:c['phase_sites'].append(close_phase)
    c['returns']=[];request['scopes'].append(dict(function=0,scope=1,program=None,journal_cells=[]))
    if mode in ('saved_alias','self_alias'):
        source=100 if mode=='self_alias'else 101;site=dict(kind='normal_post',block=0,index=7)
        c['scope_values'].append(dict(id=102,function=0,origin=dict(kind='copy',source=source,site=site)))
        position=next(i for i,p in enumerate(c['phase_sites'])if p['event']['kind']=='publish')+1
        c['phase_sites'].insert(position,dict(id=12,function=0,site=site,selector=dict(kind='always'),within=dict(kind='scope',value=source),event=dict(kind='scope_value',value=102)))
        c['exits'][0]['outcome']['retained_scope_value']=102
    elif mode=='undefined':c['exits'][0]['outcome']['retained_scope_value']=999
    return owner,request,budget

class RetainedUseTests(unittest.TestCase):
    def test_live_distinct_receiver_is_conditional_positive(self):
        o,d,b=retained();r=ground(o,d,budget=b)
        self.assertEqual(r.path_functions,((0,1),))
        self.assertIn('ASC_EXIT_NORMAL_RETAINED_SCOPE_ACTUAL_OUTCOME_REQUIRED',r.deferred)
        self.assertFalse(r.runtime_authority)
    def reject_after_public_static(self,mode,code):
        o,d,b=retained(mode);source_contracts.verify(o,d['carrier'],budget=b)
        with self.assertRaisesRegex(GroundingError,code):ground(o,d,budget=b)
    def test_actual_R_stale_retained_counter(self):self.reject_after_public_static('stale','CG_S_STALE')
    def test_receiver_closed_earlier_at_same_site(self):self.reject_after_public_static('same_site','CG_S_STALE')
    def test_saved_receiver_alias_stays_stale(self):self.reject_after_public_static('saved_alias','CG_S_STALE')
    def test_self_retention_through_different_S_id_rejects(self):self.reject_after_public_static('self_alias','CG_RETAINED_SELF')
    def test_undefined_receiver_public_input_rejected(self):
        o,d,b=retained('undefined')
        with self.assertRaises(Exception)as caught:ground(o,d,budget=b)
        self.assertEqual(caught.exception.code,'ASC_REFERENCE')
    def test_undefined_receiver_abstract_boundary_rejected(self):
        # Deliberately malformed metadata, direct abstract checker only; public case above.
        o,d,b=retained('undefined')
        with self.assertRaisesRegex(GroundingError,'CG_S_UNDEFINED'):
            prove_paths(o.sections[3]['functions'][0],d['carrier']['contract'],b)

if __name__=='__main__':unittest.main(verbosity=2)
