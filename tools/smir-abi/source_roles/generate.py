"""Regenerate only ABI-owned INT032 source-role conformance fixtures."""
from copy import deepcopy
import json
from pathlib import Path
from nominal import ref,some
from candidate_fixtures import seal
from .fixtures import sample


def generate():
    doc,parts=sample()
    probes=[]
    for name in ('tls_address','tls_guard_acquire','tls_guard_release','tls_guard_abort',
                 'guard_acquire','guard_release','guard_abort'):
        probes.append(dict(name='valid-'+name,helper=name,nominal=ref(108),
                           target={'owner':'main','reference':ref(108)} if name=='tls_address' else None,
                           type0=None,expected='accepted'))
    for name in ('atomic_flag_test','atomic_flag_test_and_set','atomic_flag_clear'):
        probes.append(dict(name='valid-'+name,helper=name,nominal=ref(107),target=None,type0=None,expected='accepted'))
        probes.append(dict(name='wrong-int32-'+name,helper=name,nominal=ref(101),target=None,type0=None,
                           expected='ABI_SOURCE_FLAG_KIND'))
    for name in ('va_start','va_copy','va_end','setjmp_capture','longjmp_restore'):
        selected=parts['va_list'] if name.startswith('va_') else parts['jmp_buf']
        probes.append(dict(name='valid-'+name,helper=name,nominal=selected,target=None,type0=None,expected='accepted'))
        probes.append(dict(name='state-not-wrapper-'+name,helper=name,nominal=parts['va_state'] if name.startswith('va_') else parts['jmp_state'],
                           target=None,type0=None,expected='ABI_CC_BUILTIN_STATE'))
    for name in ('va_arg','eh_allocate'):
        probes.append(dict(name='valid-'+name,helper=name,nominal=ref(101),target=None,
                           type0={'owner':'main','reference':ref(201)} if name=='va_arg' else None,expected='accepted'))
    probes.append(dict(name='wrong-va-transport',helper='va_arg',nominal=ref(101),target=None,
                       type0={'owner':'main','reference':ref(202)},expected='ABI_SOURCE_VARARG_TYPE0'))
    probes.append(dict(name='wrong-tls-source',helper='tls_address',nominal=ref(108),
                       target={'owner':'main','reference':ref(102)},type0=None,expected='ABI_SOURCE_TLS_TARGET'))
    data=dict(case='canonical-source-role-graphs',scope='Actual ABI/type reference predicates; no runtime/import/production proof.',
              abi=doc,execution_graph=parts['execution_graph'],probes=probes)
    bad=deepcopy(doc)
    state=next(t for t in bad['types'] if t['id']==103)
    state['record_input']['some']['fields'][0]['name']=some('different')
    next(l for l in bad['layouts'] if l['id']==103)['fields'][0]['name']='different'
    seal(bad)
    invalid=dict(case='unused-reserved-builtin-mismatch',scope='Whole ABI rejection before helper use.',
                 abi=bad,execution_graph=parts['execution_graph'],expected='ABI_CC_BUILTIN_STATE')
    out=Path(__file__).resolve().parents[3]/'docs/specifications/smir/portable/conformance/abi/source-roles'
    out.mkdir(parents=True,exist_ok=True)
    for name,value in [('canonical-source-role-graphs',data),('reject-unused-builtin-state',invalid)]:
        (out/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
    return data,invalid


if __name__=='__main__':
    data,invalid=generate();print('source-role probes',len(data['probes']),'plus one ABI rejection')
