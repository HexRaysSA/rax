"""Isolated original-root3 executable witnesses; explicit finite reference scope."""
from pathlib import Path
from copy import deepcopy
import hashlib,json,sys
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[6]
sys.path[:0]=[str(ROOT/p) for p in ('tools/smir-format','tools/smir-format/execution',
                                  'tools/smir-runtime-contract','tools/smir-abi')]
from candidate.context import RootContext,records
from candidate import root3_context as D,factory_meter as M
from candidate.source_data_projection import source_api
from candidate.type_system import Types,ref
from candidate.layouts import Layouts


def need(value,message):
    if not value:raise AssertionError(message)


def budget(work=10**24):
    return source_api().SourceQueryBudget(max_work=work,max_edges=10**24,
                                         max_copied_bytes=10**24,max_depth=128)


def owner():
    b=budget();return RootContext.from_module((HERE/'published-sret.smo').read_bytes(),budget=b),b


def reject(callback,code):
    try:callback()
    except Exception as error:
        need(code in str(error),(code,str(error)));return
    raise AssertionError('accepted: '+code)


def resealed(roots,b):
    return D.codec().decode_module(D.codec().encode_module(roots,budget=b),budget=b).roots


def check(case):
    if case=='fixture-integrity':
        manifest=json.loads((HERE/'manifest.json').read_bytes())
        for item in manifest['files']:
            data=(HERE/item['path']).read_bytes()
            need(len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256'],'fixture drift')
        o,b=owner();stamp=o.prepare_source_data(budget=b)
        need(dict(stamp.root_digests)[3].hex()==manifest['root3_sha256'],'original root3 hash')
        need(stamp.schema_digest.hex()==manifest['source_schema_sha256'],'version-specific source grammar')
    elif case=='complete-pipeline':
        o,b=owner();stamp=o.prepare_source_data(budget=b);o.verify_abi()
        body=o.verify_candidate_body(budget=b);result=o.verify_source_constraints(budget=b)
        need(body.owner is o and body.stamp is stamp and result.owner is o and result.stamp is stamp,'original custody')
        need(body.verified.functions_root==o.sections[3],'full unchanged root3')
        need(not body.executable and not body.semantic_admission and not body.active_v3_verified,'body authority')
        need(not result.source_fact_authority and not result.runtime_authority and not result.active_v3_verified,'source authority')
        need(o.execution_checked is None,'no execution receipt')
    elif case=='source-call-custody':
        o,b=owner();stamp=o.prepare_source_data(budget=b);o.verify_abi();view=o.source_call_context(budget=b)
        need(view._roots[3].field('payload_revision')==3 and view._roots[3].field('source_contract') is not None,'not projected')
        need(view._stamp.schema_digest==stamp.schema_digest and view._stamp.root_digests==stamp.root_digests,'original stamp')
        view.site(budget=b)
    elif case=='observer-unavailable':
        from codec import CandidateCodec
        schemas={n:json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())for n in ('abi','execution','runtime')}
        folder=ROOT/'docs/specifications/smir/portable/conformance/runtime/source-contracts'
        roots=CandidateCodec(schemas).decode((folder/'pointer-partial-factory-and-caller.smo').read_bytes()).roots
        raw=json.loads((folder/'pointer-partial-return-adoption.source-contract.json').read_bytes())['contract'];b=budget()
        adoption=raw['adoptions'][0];fid=adoption['function']
        scope=next(x for x in raw['scope_values']if x['function']==fid)
        typ=next(x['id']for x in roots[1]['types']if x['kind']=='journal')
        function=next(x for x in roots[3]['functions']if x['id']==fid)
        function['blocks'][0]['ops'].append(dict(op='source_journal_observe',results=[dict(id=50000,type=ref(typ))],operands=[],scope_value=scope['id'],adoption=adoption['id']))
        roots[3].update(payload_revision=3,source_contract=D.codec().wire_contract(raw,budget=b))
        o=RootContext(resealed(roots,b),budget=b);o.verify_abi()
        body=o.verify_candidate_body(budget=b)
        need(len(body.observers)==1 and body.verified.functions_root==o.sections[3], 'typed observer full root')
        need(not body.executable and not body.semantic_admission and o.execution_checked is None, 'observer admission')
        reject(lambda:o.source_registry_context(budget=b),'V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE')
        reject(o.verify_execution,'V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE')
    elif case=='version2-schema':
        from codec import CandidateCodec
        schemas={n:json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())for n in ('abi','execution','runtime')}
        path=ROOT/'docs/specifications/smir/portable/conformance/runtime/source-contracts/sret-published-factory.smo'
        o=RootContext(CandidateCodec(schemas).decode(path.read_bytes()).roots);b=budget()
        stamp=o.prepare_source_data(budget=b)
        expected=hashlib.sha256(json.dumps(records(),sort_keys=True,ensure_ascii=True,separators=(',',':')).encode('ascii')).digest()
        need(stamp.schema_digest==expected,'version2 schema changed')
    elif case=='different-ledger':
        o,b=owner();o.prepare_source_data(budget=b)
        reject(lambda:o.prepare_source_data(budget=budget()),'SOURCE_DATA')
        reject(lambda:o.verify_candidate_body(budget=budget()),'V3_CONSTRUCTION_BUDGET')
    elif case=='editable-abi-flag':
        o,b=owner();o.abi_checked=True
        reject(lambda:o.source_call_context(budget=b),'V3_GENUINE_ABI_REQUIRED')
        reject(lambda:o.verify_candidate_body(budget=b),'V3_GENUINE_ABI_REQUIRED')
    elif case=='embedded-mutation':
        o,b=owner();o.prepare_source_data(budget=b);o.sections[3]['source_contract']['revision']=2
        reject(lambda:o.prepare_source_data(budget=b),'context_snapshot_changed')
    elif case=='external-replacement':
        o,b=owner();d=json.loads((HERE/'published-sret.source.json').read_bytes());d['contract']['phase_sites']=[]
        reject(lambda:D.source_contracts().verify(o,d,budget=b),'ASC_V3_EMBEDDED_CONTRACT_MISMATCH')
    elif case=='no-execution-admission':
        o,b=owner();o.verify_abi();o.verify_candidate_body(budget=b)
        reject(lambda:o.source_registry_context(budget=b),'V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE')
        reject(o.verify_execution,'V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE')
    elif case in ('text-256-boundary','text-257-refusal','text-utf8-refusal'):
        o,b=owner();roots=deepcopy(o.sections)
        roots[2]['manifest']['key']['name']=('a'*256 if case=='text-256-boundary' else
                                           'a'*257 if case=='text-257-refusal' else 'é'*129)
        roots=resealed(roots,b)
        if case=='text-256-boundary':RootContext(roots,budget=b)
        else:reject(lambda:RootContext(roots,budget=b),'V3_RESOURCE')
    elif case=='unknown-float-format':
        o,b=owner();roots=deepcopy(o.sections)
        roots[1]['types'].append(dict(id=50001,kind='float',format='unknown'))
        reject(lambda:RootContext(roots,budget=b),'V3_TYPE_FORMAT')
    elif case in ('nominal-pointer-width','function-params','raw-width','array-count',
                  'dynamic-record','exception-profile','list-cardinality'):
        o,b=owner();roots=deepcopy(o.sections)
        if case=='nominal-pointer-width':next(x for x in roots[10]['types']if x['kind']=='pointer')['bits']=32
        elif case=='function-params':
            typ=roots[1]['types'][0]['id']
            roots[3]['functions'][0]['params']=[dict(id=10000+i,type=ref(typ))for i in range(17)]
        elif case=='raw-width':next(x for x in roots[1]['types']if x['kind']=='raw')['bits']=32769
        elif case=='array-count':next(x for x in roots[1]['types']if x['kind']=='array')['count']=1025
        elif case=='dynamic-record':next(x for x in roots[10]['types']if x['kind']=='record')['record_input']['some']['dynamic']=True
        elif case=='exception-profile':roots[8]['functions']=[dict(function=0,regions=[],actions=[])]
        elif case=='list-cardinality':roots[3]['functions'][0]['blocks'][0]['ops']*=257
        # Deliberately malformed semantic variants: constructor must refuse the
        # finite resource profile before any inherited ABI/body factory.
        reject(lambda:RootContext(roots,budget=b),'V3_COUNT' if case=='list-cardinality' else 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    elif case in ('zero-before-copy','low-before-abi','low-before-body'):
        import candidate.context as C
        import candidate.verify as V
        o,b=owner();roots=deepcopy(o.sections);calls=[]
        if case=='zero-before-copy':
            actual=C.deepcopy
            def observed(*args,**kw):calls.append(1);return actual(*args,**kw)
            with patch.object(C,'deepcopy',observed):reject(lambda:RootContext(roots,budget=budget(0)),'SOURCE_DATA_RESOURCE')
        elif case=='low-before-abi':
            high=budget();RootContext(roots,budget=high);low=budget(high._used_work+1);o=RootContext(roots,budget=low)
            actual=C.importlib.util.spec_from_file_location
            def observed(name,path,*args,**kw):
                if str(path).endswith('/tools/smir-abi/candidate.py'):calls.append(1)
                return actual(name,path,*args,**kw)
            with patch.object(C.importlib.util,'spec_from_file_location',observed):reject(o.verify_abi,'SOURCE_DATA_RESOURCE')
        else:
            high=budget();o=RootContext(roots,budget=high);o.prepare_source_data(budget=high);o.verify_abi()
            low=budget(high._used_work+1);o=RootContext(roots,budget=low);o.prepare_source_data(budget=low);o.verify_abi()
            actual=V._verify_v3_body
            def observed(*args,**kw):calls.append(1);return actual(*args,**kw)
            with patch.object(V,'_verify_v3_body',observed):reject(lambda:o.verify_candidate_body(budget=low),'SOURCE_DATA_RESOURCE')
        need(not calls,'inherited factory entered before quota')
    elif case=='type-layout-parity':
        o,b=owner();root=o.sections[1];plain=Types(root);metered=Types(root,budget=b)
        for row in root['types']:
            r=ref(row['id']);need(plain.digest(r)==metered.digest(r) and plain.width(r)==metered.width(r),'actual type parity')
        plain_layouts=Layouts(root,plain);metered_layouts=Layouts(root,metered,budget=b)
        for row in root['memory_layouts']:
            need(plain_layouts.digest(ref(row['id']))==metered_layouts.digest(ref(row['id'])),'actual layout parity')
    elif case=='deepcopy-budget':
        o,b=owner();o.verify_abi();types=deepcopy(o.types);layouts=deepcopy(o.layouts);graph=deepcopy(o.abi_graph)
        need(types._factory_budget is b and layouts._factory_budget is b and layouts.types._factory_budget is b and graph.budget is b,'ledger replaced by deepcopy')
    elif case in ('spent-before-type-copy','spent-before-layout-copy'):
        o,b=owner();b.charge(work=b.max_work-b._used_work)
        reject(lambda:deepcopy(o.types if case=='spent-before-type-copy'else o.layouts),'SOURCE_DATA_RESOURCE')
    elif case=='zero-before-types':
        o,b=owner();reject(lambda:Types(o.sections[1],budget=budget(0)),'SOURCE_DATA_RESOURCE')
    elif case=='legacy-error-priority':reject(lambda:Types(dict(payload_revision=999)),'revision')
    elif case in ('targets-precharge','uses-precharge'):
        import candidate.verify as V
        o,b=owner();o.verify_abi();body=o.verify_candidate_body(budget=b);calls=[]
        selected='targets'if case=='targets-precharge'else'uses';actual=getattr(V,selected)
        def observed(*args,**kw):calls.append(1);return actual(*args,**kw)
        hook='body_node'if selected=='targets'else'operation_shell';actual_hook=getattr(M,hook)
        def exhausted(*args,**kw):
            ledger=args[-1];ledger.charge(work=ledger.max_work-ledger._used_work)
            return actual_hook(*args,**kw)
        from common import Limits
        function=body.verified.functions_root['functions'][0]
        with patch.object(V,selected,observed),patch.object(M,hook,exhausted):
            reject(lambda:V.verify_function(function,dict(regions=[],actions=[]),
                body.verified.types,body.verified.dependencies,Limits(),budget=b),'SOURCE_DATA_RESOURCE')
        need(not calls,'allocation helper entered before quota')
    elif case=='helper-precharge':
        import candidate.bindings as B
        o,b=owner();o.verify_abi();calls=[];actual=B.validate;actual_hook=M.internal_helper
        def observed(*args,**kw):calls.append(1);return actual(*args,**kw)
        def exhausted(binding,deps,ledger):
            ledger.charge(work=ledger.max_work-ledger._used_work)
            return actual_hook(binding,deps,ledger)
        with patch.object(B,'validate',observed),patch.object(M,'internal_helper',exhausted):
            reject(lambda:o.verify_candidate_body(budget=b),'SOURCE_DATA_RESOURCE')
        need(not calls,'helper oracle entered before quota')
    else:raise ValueError('unknown witness '+case)


if __name__=='__main__':
    case=sys.argv[1];check(case)
    print(json.dumps(dict(case=case,passed=True,optimize=sys.flags.optimize,
        scope='original-root3 finite static/reference context; no execution admission')))
