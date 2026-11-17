"""Draft scalar Raw8 atomic witnesses; no source ABI or parallel admission."""
from copy import deepcopy

from candidate.type_system import ref
from candidate.verify import verify
from common import Reject
from test_candidate import block, decl, fixture, operation

SUCCESS = ('relaxed', 'acquire', 'release', 'acq_rel', 'seq_cst')
FAILURE = ('relaxed', 'acquire', 'seq_cst')
MODE = dict(alignment=1, volatile=False, order='relaxed', failure_order='none',
            scope='process', elementwise=False)


def scalar_layout(identifier, typ, size):
    return dict(id=identifier, type=ref(typ), size=size, access_bytes=size,
                alignment=1, fields=[], element=None, stride=0)


def roots(kind='exchange', *, width=8, vector=False, elementwise=False,
          order='relaxed', failure='relaxed', weak=False, action=None, numeric=False):
    """Actual execution-only records, distinct from source category admission."""
    result = fixture()
    types, functions, _ = result
    types['types'] += [dict(id=17, kind='raw', bits=width),
                       dict(id=18, kind='vector', element=ref(17), count=2)]
    typ = 18 if vector else 17
    size = (width + 7) // 8
    types['memory_layouts'] = [scalar_layout(0, 17, size), scalar_layout(2, 1, 1)]
    if vector:
        types['memory_layouts'].append(dict(id=1, type=ref(18), size=2*size,
            access_bytes=2*size, alignment=1, fields=[], element={'some': ref(0)},
            stride=size*8))
    storage = dict(type=ref(1 if numeric else typ), layout=ref(2 if numeric else 1 if vector else 0),
                   nominal=None, abi_binding=None, bytes=1 if numeric else size*(2 if vector else 1))
    params = [7, typ, typ] if kind == 'cmpxchg' else [7, typ]
    fn = functions['functions'][0]
    fn['params'] = [decl(i, t) for i, t in enumerate(params)]
    types['types'][15].update(params=[ref(t) for t in params], param_noundef=[False]*len(params),
                             results=[ref(typ)], result_noundef=[False])
    mode = dict(MODE, order=order, failure_order=failure if kind == 'cmpxchg' else 'none',
                elementwise=elementwise)
    prefix = []
    if numeric:
        prefix.append(operation('bitcast', [decl(3, 1)], [1]))
    if kind == 'cmpxchg':
        node = operation('cmpxchg', [decl(10, typ), decl(11, 0)], [0, 1, 2],
                         storage=storage, mode=mode, weak=weak)
    else:
        node = operation('atomic_rmw', [decl(10, 1 if numeric else typ)], [0, 3 if numeric else 1],
                         storage=storage, mode=mode, action=action or kind)
    suffix = [operation('bitcast', [decl(12, typ)], [10])] if numeric else []
    fn['blocks'] = [block(0, prefix+[node]+suffix, {'op': 'return', 'values': [12 if numeric else 10]})]
    types['memory_layouts'].sort(key=lambda item: item['id'])
    return result


def observe(document, dependencies=None):
    try:
        verify(*document, dependencies=dependencies)
    except Reject as error:
        return error.code
    return 'ok'


def legacy_exchange(typ, *, elementwise=False):
    document = roots()
    document[0]['types'].append(dict(id=19, kind='code_address'))
    size = {1: 1, 2: 4, 5: 4, 7: 8, 8: 4, 16: 8, 19: 8}[typ]
    layout = scalar_layout(0, typ, size)
    if typ in (7, 16, 19):
        layout['alignment'] = 8
    if typ == 8:
        layout.update(element={'some': ref(2)}, stride=8)
    document[0]['memory_layouts'][0] = layout
    document[0]['types'][15].update(params=[ref(7), ref(typ)], results=[ref(typ)])
    fn = document[1]['functions'][0]
    fn['params'][1]['type'] = ref(typ)
    node = fn['blocks'][0]['ops'][0]
    node['results'][0]['type'] = ref(typ)
    node['storage'].update(type=ref(typ), bytes=size)
    node['mode']['elementwise'] = elementwise
    node['mode']['alignment'] = layout['alignment']
    return document


def cases():
    result = []
    def add(name, document, expected):
        result.append(dict(id=name, roots=document, expected=expected, rust_expected=expected))
    for order in SUCCESS:
        add('raw8-exchange-'+order, roots(order=order), 'ok')
    for typ, label in ((1, 'int8'), (2, 'int32'), (5, 'float32'), (7, 'data-pointer'),
                       (16, 'typed-code-pointer'), (19, 'code-address')):
        add('unchanged-exchange-'+label, legacy_exchange(typ), 'ok')
    for elementwise in (False, True):
        add('unchanged-exchange-int8-vector-'+str(elementwise).lower(),
            legacy_exchange(8, elementwise=elementwise), 'ok')
    for order in SUCCESS:
        for failure in FAILURE:
            for weak in (False, True):
                add('raw8-cas-'+order+'-'+failure+'-'+('weak' if weak else 'strong'),
                    roots('cmpxchg', order=order, failure=failure, weak=weak), 'ok')
    for width in (1, 7, 9, 16, 64, 128):
        add('reject-exchange-raw'+str(width), roots(width=width), 'atomic_action_type')
    for elementwise in (False, True):
        add('reject-exchange-raw8-vector-'+str(elementwise).lower(),
            roots(vector=True, elementwise=elementwise), 'atomic_action_type')
    for action in ('add', 'sub', 'and', 'or', 'xor'):
        add('reject-raw8-numeric-'+action, roots(action=action), 'atomic_action_type')
        add('int8-numeric-view-'+action, roots(action, numeric=True), 'ok')
    for order in ('none', 'unordered'):
        add('reject-exchange-order-'+order, roots(order=order), 'atomic_rmw_order')
    for failure in ('none', 'unordered', 'release', 'acq_rel'):
        add('reject-cas-failure-'+failure, roots('cmpxchg', failure=failure), 'cas_failure_order')
    return result
