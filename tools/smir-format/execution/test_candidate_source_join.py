"""Genuine original-source join witnesses; no fabricated fact/producer callback."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from candidate.context import RootContext
from candidate import source_join as J

ROOT=Path(__file__).resolve().parents[3]
sys.path.append(str(ROOT/'tools/smir-abi'))
from function_address.fixtures import ordinary,seal
from record_layout.test_source_programs import document,q


def ledger(**kw):
    p=dict(max_work=10**9,max_edges=10**8,max_copied_bytes=10**9,max_depth=128);p.update(kw)
    return J.source_api().SourceQueryBudget(**p)

def fixture(missing=False,bad=False,budget=None):
    roots=ordinary(complete_record=True)
    roots[10]['journals'].append(dict(id=700,signature=201,params=[],slots=[],normal_order=[],exception_order=[]))
    if missing:next(t for t in roots[10]['types'] if t['id']==100)['record_input']=None
    abi=document();abi['records'][0]['name']='example.R'
    if bad:
        plan=deepcopy(next(p for p in roots[10]['signatures'] if p['id']==201));plan['id']=202;roots[10]['signatures'].append(plan);abi['cleanups'][0]['signature']=q(202)
    seal(roots);owner=RootContext(roots);b=budget if budget is not None else ledger();stamp=owner.prepare_source_data(budget=b)
    family={n:roots[2]['manifest']['key'][n] for n in ('namespace','name','abi_major')}
    abi['contexts'][0].update(family=family,abi_site=roots[10]['identity'],abi_root=dict(stamp.root_digests)[10].hex(),module_root=dict(stamp.root_digests)[2].hex())
    ctx=dict(id='original',abi_context=0,family=deepcopy(family),abi_site=roots[10]['identity'],schema_digest=stamp.schema_digest.hex(),roots=[dict(section=n,digest=h.hex()) for n,h in stamp.root_digests])
    program=dict(id='cleanup',context='original',abi_cleanup=0,original_journal=q(700),source_class=q(100),view='complete',cleanup_signature=deepcopy(abi['cleanups'][0]['signature']))
    cell=dict(id='value',program='cleanup',declared_nominal=q(1),selector=dict(kind='path',record=0,steps=[dict(slot=0,indices=None)],expected_layout=dict(offset_bits=0,width_bits=32,alignment=4)))
    d=dict(format='conditional-source-join',revision=1,binding='unbound',runtime_authority=False,source_fact_authority=False,contexts=[ctx],programs=[program],cells=[cell])
    return d,abi,owner,b


def run(d,a,o,b,**kw):return J.verify(d,a,original_owners=(J.OriginalOwnerInput('original',o),),budget=b,**kw)

class SourceJoinTests(unittest.TestCase):
    def test_actual_original_direct_join(self):
        d,a,o,b=fixture();before=deepcopy((d,a));r=run(d,a,o,b)
        self.assertEqual(r.cells,('value',));self.assertEqual(r.programs,('cleanup',));self.assertIs(r.bindings[0].owner,o)
        self.assertFalse(r.runtime_authority);self.assertFalse(r.source_fact_authority);self.assertEqual(before,(d,a))
        with self.assertRaises(FrozenInstanceError):r.runtime_authority=True

    def test_same_bytes_fresh_owners_shared_ledger_and_prior_reuse(self):
        b=ledger();d,a,o,_=fixture(budget=b);first=run(d,a,o,b)
        d2,a2,o2,_=fixture(budget=b);second=run(d2,a2,o2,b)
        self.assertIsNot(first.bindings[0].stamp,second.bindings[0].stamp)
        self.assertIsNot(o,o2)
        with self.assertRaisesRegex(J.JoinError,'SJ_PRIOR_BINDING'):run(d2,a2,o2,b,expected_bindings=first.bindings)
        self.assertIs(run(d,a,o,b,expected_bindings=first.bindings).bindings[0].stamp,first.bindings[0].stamp)

    def test_deferred_path_does_not_hide_later_original_or_join_error(self):
        d,a,o,b=fixture(missing=True)
        with self.assertRaises(J.JoinError) as e:run(d,a,o,b)
        self.assertEqual((e.exception.kind,e.exception.code),('unavailable','SJ_SOURCE_EVIDENCE_UNAVAILABLE'))
        d['cells'][0]['selector']['expected_layout']['width_bits']=64
        with self.assertRaisesRegex(J.JoinError,'SJ_CELL_LAYOUT'):run(d,a,o,b)
        d,a,o,b=fixture(missing=True,bad=True)
        with self.assertRaises(J.source_api().SourceDataError) as e:run(d,a,o,b)
        self.assertEqual(e.exception.code,'ABI_SP_ORIGINAL_JOURNAL_SIGNATURE')

    def test_context_digest_domains_and_old_fields(self):
        for mutation,code in [(lambda x:x['contexts'][0].update(schema_digest='00'*32),'SJ_SOURCE_SCHEMA'),
            (lambda x:x['contexts'][0]['roots'].reverse(),'SJ_ROOT_DIGESTS'),
            (lambda x:x['contexts'][0].update(abi_site='00'*32),'SJ_CONTEXT_IDENTITY'),
            (lambda x:x['contexts'][0].update(source_unit='00'*32),'SJ_SHAPE')]:
            d,a,o,b=fixture();mutation(d)
            with self.subTest(code=code),self.assertRaisesRegex(J.JoinError,code):run(d,a,o,b)

    def test_direct_coverage_and_unsupported_root(self):
        d,a,o,b=fixture();root=dict(id='root',program='cleanup',declared_nominal=q(100),selector=dict(kind='root',record=0))
        d['cells'].append(root)
        with self.assertRaises(J.JoinError) as e:run(d,a,o,b)
        self.assertEqual(e.exception.kind,'unavailable')
        d['cells']=[root]
        with self.assertRaisesRegex(J.JoinError,'SJ_COVERAGE_EXHAUSTION'):run(d,a,o,b)
        d,a,o,b=fixture();d['cells'].append({**deepcopy(d['cells'][0]),'id':'duplicate'})
        with self.assertRaisesRegex(J.JoinError,'SJ_CELL_DUPLICATE'):run(d,a,o,b)

    def test_original_nonvirtual_base_geometry_not_descriptor_agreement(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location("source_join_original_codec",ROOT/"tools/smir-format/codec.py")
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        CandidateCodec=module.CandidateCodec
        from record_layout.test_source_programs import record,slot,cleanup,program
        schemas={n:json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_text()) for n in ('abi','execution','runtime')}
        folder=ROOT/'docs/specifications/smir/portable/conformance/abi/source-paths'
        roots=CandidateCodec(schemas).decode((folder/'source.smo').read_bytes()).roots
        names=json.loads((folder/'records.json').read_text());types={x['id']:x for x in roots[10]['types']};layouts={x['id']:x for x in roots[10]['layouts']}
        ids=[names[x] for x in ('NVD','NVL','NVR','V')];local={n:i for i,n in enumerate(ids)}
        abi=document();abi['records']=[]
        for n in ids:
            t=types[n];layout=layouts[t['layout']['some']];rows=[];input=t['record_input']['some']
            for i,base in enumerate(input['bases']):
                placed=next(x for x in layout['bases'] if x['declaration_index']=={'some':i} and not x['virtual']);child=layouts[types[base['type']['id']]['layout']['some']]
                rows.append(slot(len(rows),'nonvirtual_base',i,base['type']['id'],local[base['type']['id']],8*placed['offset'],8*child['nonvirtual_size'],alignment=child['nonvirtual_align']))
            for f in layout['fields']:rows.append(slot(len(rows),index=f['declaration_index'],nominal=f['type']['id'],offset=f['offset_bits'],width=f['width_bits'],name=f['name']))
            abi['records'].append(record(local[n],t['identity']['entity'],layout['size'],layout['nonvirtual_size'],layout['align'],source=dict(context=0,nominal=q(n)),slots=rows))
        abi['cleanups']=[cleanup(0,0,[x['id'] for x in abi['records'][0]['slots']])];abi['programs']=[program(0,steps=abi['cleanups'][0]['slots'])]
        signature=roots[10]['signatures'][0]['id'];abi['cleanups'][0]['signature']=q(signature)
        roots[10]['journals'].append(dict(id=700,signature=signature,params=[],slots=[],normal_order=[],exception_order=[]));seal(roots)
        o=RootContext(roots);b=ledger();stamp=o.prepare_source_data(budget=b);family={n:roots[2]['manifest']['key'][n] for n in ('namespace','name','abi_major')}
        abi['contexts'][0].update(family=family,abi_site=roots[10]['identity'],abi_root=dict(stamp.root_digests)[10].hex(),module_root=dict(stamp.root_digests)[2].hex())
        d=fixture()[0];d['contexts'][0].update(family=family,abi_site=roots[10]['identity'],schema_digest=stamp.schema_digest.hex(),roots=[dict(section=n,digest=h.hex()) for n,h in stamp.root_digests]);d['programs'][0].update(source_class=q(ids[0]),cleanup_signature=q(signature));d['cells']=[]
        for row in abi['records'][0]['slots']:
            d['cells'].append(dict(id='slot'+str(row['id']),program='cleanup',declared_nominal=deepcopy(row['source']['nominal']),selector=dict(kind='path',record=0,steps=[dict(slot=row['id'],indices=None)],expected_layout={k:row[k] for k in ('offset_bits','width_bits','alignment')})))
        self.assertEqual(len(run(d,abi,o,b).cells),len(d['cells']))
        abi['records'][0]['slots'][0]['offset_bits']+=8;d['cells'][0]['selector']['expected_layout']['offset_bits']+=8
        with self.assertRaisesRegex(J.JoinError,'SJ_ORIGINAL_BASE_LAYOUT'):run(d,abi,o,b)

    def test_duplicate_unsupported_cell_is_known_before_unknown(self):
        d,a,o,b=fixture();root=dict(id='root',program='cleanup',declared_nominal=q(100),selector=dict(kind='root',record=0))
        d['cells'] += [root,{**deepcopy(root),'id':'same_root'}]
        with self.assertRaisesRegex(J.JoinError,'SJ_CELL_DUPLICATE'):run(d,a,o,b)

    def test_real_afterguard_quota_refuses_without_result(self):
        from unittest.mock import patch
        d,a,o,b=fixture();calls=[];original=RootContext.prepare_source_data
        def measured(owner,*,budget):
            calls.append(budget._used_work)
            return original(owner,budget=budget)
        with patch.object(RootContext,'prepare_source_data',measured):run(d,a,o,b)
        self.assertGreaterEqual(len(calls),3)
        limited=ledger(max_work=calls[-1]);d,a,o,b=fixture(budget=limited)
        with self.assertRaises(J.source_api().SourceDataError) as e:run(d,a,o,b)
        self.assertEqual(e.exception.code,'SOURCE_DATA_RESOURCE')

    def test_reviewed_schema_identity_and_precharged_read(self):
        from unittest.mock import patch
        import tempfile
        with tempfile.TemporaryDirectory(prefix='smir-join-schema-') as directory:
            changed=Path(directory)/'schema.json';changed.write_bytes(J.SCHEMA.read_bytes()+b' ')
            d,a,o,b=fixture()
            with patch.object(J,'SCHEMA',changed),self.assertRaisesRegex(J.JoinError,'SJ_SCHEMA_IDENTITY'):run(d,a,o,b)
            limited=ledger(max_work=1);d,a,o,b=fixture()
            with patch.object(J,'SCHEMA',changed),patch.object(Path,'open',side_effect=AssertionError('unbudgeted read')):
                with self.assertRaises(J.source_api().SourceDataError):run(d,a,o,limited)

    def test_prior_binding_bound_and_schema_depth_resource(self):
        d,a,o,b=fixture();result=run(d,a,o,b)
        with self.assertRaisesRegex(J.JoinError,'SJ_PRIOR_BINDING'):run(d,a,o,b,expected_bindings=result.bindings*257)
        d,a,o,b=fixture()
        with self.assertRaises(J.JoinError) as caught:run(d,a,o,ledger(max_depth=8))
        self.assertEqual((caught.exception.code,caught.exception.kind),('SJ_RESOURCE','resource'))

    def test_authored_cases(self):
        folder=ROOT/'docs/specifications/smir/portable/conformance/execution/source-join'
        for case in json.loads((folder/'cases.json').read_text())['cases']:
            with self.subTest(case=case['id']):
                d,a,o,b=fixture(missing=case.get('missing',False),bad=case.get('bad',False))
                for edit in case.get('edits',[]):
                    parent=d
                    for key in edit['path'][:-1]:parent=parent[key]
                    parent[edit['path'][-1]]=deepcopy(edit['value'])
                if case.get('duplicate'):
                    row=deepcopy(d['cells'][0]);row['id']='duplicate';d['cells'].append(row)
                if case['expect']=='checked':self.assertEqual(run(d,a,o,b).cells,('value',))
                else:
                    with self.assertRaises(Exception) as caught:run(d,a,o,b)
                    self.assertEqual(caught.exception.code,case['expect'])

    def test_cached_function_index_is_not_original_evidence(self):
        d,a,o,b=fixture();o.functions={}
        self.assertEqual(run(d,a,o,b).cells,('value',))

    def test_source_mutation_and_real_quota(self):
        d,a,o,b=fixture();o.sections[10]['identity']='00'*32
        with self.assertRaises(Exception) as e:run(d,a,o,b)
        self.assertIn('context_snapshot_changed',str(e.exception))
        for key in ['max_work','max_edges','max_copied_bytes']:
            d,a,o,b=fixture()
            with self.assertRaises(J.source_api().SourceDataError):run(d,a,o,ledger(**{key:0}))
        d,a,o,b=fixture()
        with self.assertRaisesRegex(J.JoinError,'SJ_BUDGET_IDENTITY'):run(d,a,o,object())

if __name__=='__main__':unittest.main()
