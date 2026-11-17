"""Local ABI role witness declarations; no import or production authority."""
from copy import deepcopy
from candidate_fixtures import portable_identity_abi,seal,Context
from execution_shapes import ExecutionShapes
from nominal import ZERO,ref,some
from .builder import build_builtin_states,SOURCE_KEYS,EXECUTION_KEYS


def sample():
    parts=build_builtin_states(source_ids=dict(zip(SOURCE_KEYS,range(101,107))),
                              execution_ids=dict(zip(EXECUTION_KEYS,range(201,206))),domain_id=19)
    doc=portable_identity_abi();doc.update(types=parts['types'],layouts=parts['layouts'],signatures=[])
    doc['domains'][0]['id']=19
    flag=deepcopy(doc['types'][0]);flag.update(id=107,kind='atomic_flag',bits=8,execution=some(ref(203)),layout=some(107))
    flag['identity'].update(entity='atomic_flag');doc['types'].append(flag)
    flag_layout=deepcopy(doc['layouts'][0]);flag_layout.update(id=107,type=ref(107),size=1,align=1,data_size=1,
                                                               nonvirtual_size=1,nonvirtual_align=1)
    doc['layouts'].append(flag_layout)
    forward=deepcopy(doc['types'][2]);forward.update(id=109,layout=None,execution=None,record_input=None,
                                                   flags=[],representation='none')
    forward['identity'].update(language='cpp23',linkage='external',entity='example.Forward',definition=ZERO)
    doc['types'].append(forward)
    reference=deepcopy(doc['types'][0]);reference.update(id=108,kind='reference',bits=64,elements=[ref(109)],
        flags=sorted(['complete','trivial_copy','trivial_destroy','lvalue_ref']),execution=some(ref(206)),layout=some(108))
    reference['identity'].update(language='cpp23',entity='reference');doc['types'].append(reference)
    reference_layout=deepcopy(doc['layouts'][1]);reference_layout.update(id=108,type=ref(108));doc['layouts'].append(reference_layout)
    parts['execution_graph'].append(dict(id=206,kind='data_ptr',space='guest_data'))
    seal(doc)
    return doc,parts


def checked_context(document,execution_graph):
    shapes=ExecutionShapes(execution_graph)
    context=Context('main',shapes.describe,lambda r:{},lambda r:b'',{}, {},lambda r:{},lambda r:{},
                    {'main':('example','main',1)},lambda r:{})
    return context,shapes
