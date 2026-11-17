"""Complete admitted ABI roots for C provider/C++ extern-C consumer comparison."""
from copy import deepcopy
import json
from pathlib import Path

from candidate_fixtures import build, field, declared_field, plain_cpp_record, seal
from nominal import NominalGraph, classify, option, ref, some


def build_pair():
    cpp,evidence=build(all_kinds=True)
    def add(template,*,size=None,align=None,fields=()):
        identifier=max(t['id'] for t in cpp['types'])+1
        typ=deepcopy(template);typ['id']=identifier
        typ['layout']=None if size is None else some(identifier)
        cpp['types'].append(typ)
        if size is not None:
            cpp['layouts'].append({'id':identifier,'type':ref(identifier),'size':size,'align':align,
                'data_size':size,'nonvirtual_size':size,'nonvirtual_align':align,
                'fields':[dict(f,declaration_index=i) for i,f in enumerate(fields)],'bases':[],'vptrs':[]})
        return typ
    boolean=next(t for t in cpp['types'] if t['identity']['entity']=='bool')
    wchar=next(t for t in cpp['types'] if t['identity']['entity']=='wchar_t')
    char16=next(t for t in cpp['types'] if t['identity']['entity']=='char16_t')
    wide_pointer=add(cpp['types'][6],size=8,align=8);wide_pointer['elements']=[ref(wchar['id'])]
    char16_pointer=add(cpp['types'][6],size=8,align=8);char16_pointer['elements']=[ref(char16['id'])]
    opaque=add(cpp['types'][3]);opaque.update(flags=[],execution=None,representation='none',elements=[])
    opaque['identity'].update(entity='example.Opaque',definition='0'*64)
    opaque['record_input']=None
    opaque_pointer=add(cpp['types'][6],size=8,align=8);opaque_pointer['elements']=[ref(opaque['id'])]
    record=add(cpp['types'][3],size=8,align=4,fields=[field('valid',boolean['id'],0,8),field('wide',wchar['id'],32,32)])
    record['identity']['entity']='example.CRecord';record['flags'].append('c_compatible')
    record['record_input']=some(plain_cpp_record([declared_field('valid',boolean['id']),declared_field('wide',wchar['id'])]))
    record_pointer=add(cpp['types'][6],size=8,align=8);record_pointer['elements']=[ref(record['id'])]
    callback=next(t for t in cpp['types'] if t['kind']=='pointer' and 'code' in t['flags'])
    params=[boolean['id'],wchar['id'],wide_pointer['id'],char16['id'],char16_pointer['id'],
            record['id'],opaque_pointer['id'],callback['id']]
    fn=add(cpp['types'][12]);fn.update(elements=[ref(t) for t in params]+[ref(1)],extent=some(len(params)),
        execution=some(ref(500)),flags=['complete','c_linkage'])
    signature={'id':len(cpp['signatures']),'function_type':ref(fn['id']),'params':[ref(t) for t in params],
        'result':some(ref(1)),'this_type':None,'vtt':False,'variadic':False,'noexcept':False,
        'lowered_params':[],'lowered_results':[ref(1)],'varargs':None,'return_noundef':True,
        'execution':ref(500)}
    graph=NominalGraph(cpp,'cpp')
    lowered,_=classify(graph,signature)
    for parameter in lowered:
        parameter.update(value_type=ref(record_pointer['id']) if parameter['mode']=='indirect_copy' else parameter['source_type'],
            copy=None,move=None,destroy=None)
    signature['lowered_params']=lowered;cpp['signatures'].append(signature)
    evidence['execution_graph'].append({'id':500,'kind':'function','cc':'portable','variadic':False,
        'params':[option(graph.resolve(p['value_type'])[1]['execution']) for p in lowered],
        'results':[ref(1)],'param_noundef':[True]*len(lowered),'result_noundef':[True]})
    seal(cpp)
    c=deepcopy(cpp)
    for identifier in [wchar['id'],char16['id'],record['id'],opaque['id'],fn['id'],12]:
        c['types'][identifier]['identity']['language']='c23'
    c['types'][wchar['id']]['identity']['entity']='int'
    c['types'][char16['id']]['identity']['entity']='unsigned short'
    c['types'][12]['flags'].append('c_linkage')
    for typ in c['types']:
        if typ['kind']=='record' and typ['identity']['language']=='c23' and typ['record_input'] is not None:
            for key in ('pod03','trivial','standard_layout','polymorphic','dynamic','empty'):
                typ['record_input']['some'][key]=False
    seal(c)
    return c,cpp,evidence,{'function':fn['id'],'signature':signature['id'],'record':record['id'],
                         'wide_pointer':wide_pointer['id'],'wchar':wchar['id']}


if __name__=='__main__':
    root=Path(__file__).resolve().parents[2]/'docs/specifications/smir/portable/conformance/abi/candidate'
    c,cpp,evidence,ids=build_pair()
    for name,value in [('c-provider',c),('cpp-consumer',cpp),('c-interop-evidence',evidence),('c-interop-ids',ids)]:
        (root/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
