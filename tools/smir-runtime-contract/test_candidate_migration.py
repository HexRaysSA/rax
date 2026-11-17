"""Current call-plan, no-normal frontier, EH matcher and launcher contracts."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from test_candidate_contract import HERE, ref, roots
from test_candidate_closure import Types, live_example
from runtime_candidate import launch, linking, live
from runtime_candidate.errors import Reject, some
from runtime_candidate.helpers import DEFAULT_OPTIONS, digest, instantiate
from runtime_candidate.wire import decode, encode


class MigrationTests(unittest.TestCase):
    def error(self,code,function,*args,**kwargs):
        with self.assertRaises(Reject) as caught:function(*args,**kwargs)
        self.assertEqual(caught.exception.code,code)

    def test_candidate_conformance_corpus(self):
        from check_candidate import check
        counts=check()
        self.assertGreater(sum(counts.values()),0)

    def test_actual_abi_call_interface_independent_hidden_owner_negative(self):
        script='''import copy,json,sys\nfrom candidate_fixtures import build\nfrom nominal import NominalGraph,ref\ndoc,e=build()\na=copy.deepcopy(doc);b=copy.deepcopy(doc)\ng=NominalGraph(a,'a',{'b':b})\nassert g.signature_compatible(ref(2),ref(2),'a','b')\nb['signatures'][2]['vtt']=False\ng=NominalGraph(a,'a',{'b':b})\nassert not g.signature_compatible(ref(2),ref(2),'a','b')\nprint('actual_call_interface: positive and VTT-negative passed')\n'''
        result=subprocess.run([sys.executable,'-B','-c',script],cwd=HERE.parents[1]/'tools/smir-abi',
                              text=True,capture_output=True,check=True)
        self.assertIn('VTT-negative passed',result.stdout)

    def test_boundary_full_plan_callback_required_and_mismatch(self):
        def nominal(reference):return {'kind':'function','domain':0}
        def abi_entity(namespace, reference):
            if namespace == 'nominal_domain':
                return {'id': 0, 'isa': 'portable', 'abi': 'portable', 'personality': 'portable'}
            if namespace == 'signature':
                return {'function_type': ref(0)}
            raise Reject('TEST_UNEXPECTED_ABI_NAMESPACE', namespace)
        context=linking.Context('a'*64,None,nominal,None,None,None,lambda *a:True,None,None,None,
            abi_entity=abi_entity,signature_compatible=lambda *a:False)
        record={'kind':'function','source_linkage':'cpp','nominal':some(ref(0)),'abi_signature':some(ref(2))}
        self.assertEqual(linking.source_plan(record,context),ref(2))
        self.error('RT_FUNCTION_SOURCE_PLAN',linking.same_plan,ref(2),ref(3),context,'RT_FUNCTION_SOURCE_PLAN')
        self.error('RT_SOURCE_PLAN_PRESENCE',linking.source_plan,{**record,'abi_signature':None},context)
        context.signature_compatible=None
        self.error('RT_SOURCE_PLAN_COMPARATOR',linking.same_plan,ref(2),ref(2),context,'RT_FUNCTION_SOURCE_PLAN')

    def test_new_eh_helpers_actual_types_and_exact_terminate_codeptr(self):
        definitions=[{'id':0,'kind':'exception'}, {'id':1,'kind':'data_ptr','space':'guest_data'},
            {'id':2,'kind':'function','params':[],'results':[],'param_noundef':[],'result_noundef':[],
             'variadic':False,'cc':'portable'}, {'id':3,'kind':'code_ptr','signature':ref(2)},
            {'id':4,'kind':'int','bits':32}]
        types=Types({'payload_revision':2,'types':definitions,'memory_layouts':[]})
        shapes={'eh_object_address':([0],[1]),'eh_catch_object':([0],[1]),'eh_current_owner':([],[1]),
            'eh_owner_retain':([1],[]),'eh_owner_release':([1],[]),'eh_owner_rethrow':([1],[]),
            'eh_uncaught_exceptions':([],[4]),'eh_set_terminate':([3],[3]),'eh_get_terminate':([],[3]),
            'eh_terminate':([],[]),'eh_rethrow_current':([],[])}
        for index,(name,(params,results)) in enumerate(shapes.items(),10):
            signature={'id':index,'kind':'function','params':[ref(i) for i in params],
                'results':[ref(i) for i in results],'param_noundef':[False]*len(params),
                'result_noundef':[False]*len(results),'variadic':False,'cc':'portable'}
            root={'payload_revision':2,'types':definitions+[signature],'memory_layouts':[]}
            actual=Types(root)
            record={'id':0,'kind':'internal','namespace':'smir.internal.v1','name':name,'version':1,
                'catalog':digest(),'signature':ref(index),'abi':None,'types':[],'contract':'default',
                'options':copy.deepcopy(DEFAULT_OPTIONS)}
            spec=instantiate(record,actual.resolve)
            self.assertEqual(spec['completion'],'terminal' if name=='eh_terminate' else
                'raises' if name in {'eh_owner_rethrow','eh_rethrow_current'} else 'returns')
        bad=copy.deepcopy(definitions);bad[2]['params']=[ref(4)];bad[2]['param_noundef']=[False]
        actual=Types({'payload_revision':2,'types':bad+[{'id':10,'kind':'function','params':[],
            'results':[ref(3)],'param_noundef':[],'result_noundef':[False],'variadic':False,'cc':'portable'}],
            'memory_layouts':[]})
        record.update(name='eh_get_terminate',signature=ref(10))
        self.error('RT_HELPER_TERMINATE_SIGNATURE',instantiate,record,actual.resolve)

    def launch_example(self):
        module=roots()[2];module['manifest'].update(kind='image',identity='a'*64,entry=some(ref(0)))
        selection={'abi_major':0,'minimum_minor':1,'minimum_revision':1,'implementation':None,
            'profile':2,'helpers':digest(),'services':'b'*64,'baseline':'c'*64}
        document={'revision':1,'launch':'explicit','carrier':'raw','bootstrap_arch':'none',
            'personality':'linux','foreign_isa':'none','artifact':'a'*64,'entry':ref(0),'locator':None,
            'runtime':selection,'required_capabilities':[],'modules':[]}
        actual={'os':'linux','arch':'x86_64','abi_major':0,'abi_minor':1,'revision':1,'identity':'d'*64,
            'profile':2,'helpers':digest(),'services':'b'*64,'baseline':'c'*64,'personalities':['linux'],
            'foreign_isas':['none'],'capabilities':[]}
        return module,document,actual

    def test_launch_exact_actual_identity_profile_and_first_candidate(self):
        module,document,actual=self.launch_example()
        self.assertEqual(decode('runtime_launch',encode('runtime_launch',document)),document)
        launch.validate(document,module,grants=set(),deployment=[])
        options={'host_os':'linux','host_arch':'x86_64','baseline':'c'*64,'helpers':digest(),
                 'services':'b'*64,'grants':set()}
        self.assertIs(launch.select(document,[actual],**options),actual)
        wrong={**actual,'profile':1}
        self.error('RT_LAUNCH_PROFILE',launch.select,document,[wrong,actual],**options)
        self.error('RT_LAUNCH_ENTRY',launch.validate,{**document,'entry':ref(1)},module,grants=set(),deployment=[])
        self.error('RT_LAUNCH_RUNTIME_BASELINE',launch.select,document,[{**actual,'baseline':'d'*64}],**options)

    def test_private_ticket_normal_option_and_admitted_completion(self):
        document,registry=live_example();frame=document['thread']['frames'][0]
        ticket={'id':1,'state':'prepared','helper':None,'before':frame['position'],
            'normal':some({**frame['position'],'operation':1}),'unwind':None,'committed_bytes':0,
            'direction':'none','results':[],'exception':None,'cancellation':'none'}
        frame['ticket']=some(ticket)
        live.validate(document,registry)
        ticket['normal']=None
        self.error('RT_TICKET_CONTINUATION',live.validate,document,registry)

    def test_nonreturning_helper_ticket_has_no_normal_or_completed_publication(self):
        from test_candidate_closure import verify
        from candidate.operations import Dependencies
        from candidate.live import Registry as ValueRegistry, validate as value_validate
        root={'payload_revision':2,'types':[{'id':0,'kind':'function','params':[],'results':[],
            'param_noundef':[],'result_noundef':[],'variadic':False,'cc':'portable'}],'memory_layouts':[]}
        binding={'id':0,'kind':'internal','namespace':'smir.internal.v1','name':'eh_rethrow_current','version':1,
            'catalog':digest(),'signature':ref(0),'abi':None,'types':[],'contract':'default',
            'options':copy.deepcopy(DEFAULT_OPTIONS)}
        function={'id':0,'signature':ref(0),'abi_signature':None,'params':[],'entry':0,'escape':'propagate',
            'no_return':False,'blocks':[{'id':0,'phis':[],'ops':[{'op':'call','results':[],'operands':[],
                'target':{'kind':'import','import':ref(0),'signature':ref(0)},'unwind':'propagate','source_plan':None}],
                'term':{'op':'return','values':[]}}]}
        actual=verify(root,{'payload_revision':2,'functions':[function]},
                      {'payload_revision':1,'functions':[]},Dependencies(imports={('self',0):binding}))
        document,registry=live_example()
        registry.modules['a'*64]['verified']=actual
        frame=document['thread']['frames'][0];frame['position']={'block':0,'operation':0,'predecessor':None}
        frame['locals']=[]
        frame['ticket']=some({'id':1,'state':'running','helper':some(ref(0)),'before':frame['position'],
            'normal':None,'unwind':None,'committed_bytes':0,'direction':'none','results':[],
            'exception':None,'cancellation':'none'})
        live.validate(document,registry)
        frame['ticket']['some']['state']='completed'
        self.error('RT_TICKET_NONRETURNING_COMPLETED',live.validate,document,registry)


if __name__=='__main__':unittest.main()
