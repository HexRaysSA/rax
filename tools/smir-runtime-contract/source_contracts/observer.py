"""DRAFT strict inline-retained observer source relation; no runtime issuer.

Private composition called after C.run's actual ABI/body/source checks. All roots
and source declarations remain original. This returns inspection coordinates only.
"""
from . import checker as C
from .comparison_values import same
from . import ContractToolError
from factory_meter import copy_cost, collection
from candidate import root3_context as V3
from candidate.source_grounding import prove_paths


def profile(test, code):
    if not test:
        raise ContractToolError('unavailable', 'SCVO_' + code)


def check(actual, document, *, budget):
    C.need(type(actual) is C.RootContext, 'ASC_OBSERVER_OWNER')
    V3.owner_budget(actual, budget)
    V3.require_abi(actual)
    before = actual.prepare_source_data(budget=budget)
    root = actual.sections[3]
    C.need(root['payload_revision'] == 3, 'ASC_OBSERVER_REVISION')
    budget.charge(work=1, copied_bytes=64)
    sites = []
    collection(budget, len(root['functions']), 65)
    for fn in root['functions']:
        collection(budget, len(fn['blocks']), 65)
        for block in fn['blocks']:
            collection(budget, len(block['ops']), 65)
            for index, op in enumerate(block['ops']):
                if op['op'] == 'source_journal_observe':
                    budget.charge(work=64, edges=1, copied_bytes=256)
                    C.need(len(op['results']) == 1 and not op['operands'], 'ASC_OBSERVER_SHAPE')
                    sites.append((fn['id'], block['id'], index, op))
    if not sites:
        return ()
    copy_cost([root, document['contract'], actual.sections[10]], budget)
    embedded = V3.codec().raw_contract(root['source_contract'], budget=budget)
    C.need(same(embedded, document['contract'], budget=budget), 'ASC_V3_EMBEDDED_CONTRACT_MISMATCH')
    C.need(not document['proposed_operations'], 'V3_OBSERVER_SEMANTICS_UNAVAILABLE')
    contract = document['contract']
    collection(budget, len(root['functions']), 65)
    functions = {fn['id']: fn for fn in root['functions']}
    collection(budget, len(actual.sections[6]['imports']), 65)
    imports = {row['id']: row for row in actual.sections[6]['imports']}
    budget.charge(work=2, copied_bytes=256)
    proven, checked = set(), []

    def equal(left, right, code):
        C.need(same(left, right, budget=budget), 'ASC_OBSERVER_' + code)

    def rows(table, fid):
        data = contract[table]
        collection(budget, len(data), 65)
        return [row for row in data if row['function'] == fid]

    def one(table, fid):
        data = rows(table, fid)
        profile(len(data) == 1, 'SINGLE_' + table.upper() + '_PROFILE')
        return data[0]

    def phase(row, site, within, event):
        equal(row['selector'], {'kind': 'always'}, 'SELECTOR')
        equal(row['site'], site, 'PHASE_SITE')
        equal(row['within'], within, 'PHASE_WITHIN')
        equal(row['event'], event, 'PHASE_EVENT')

    def enter(scope, value, phases, fid):
        C.need(scope['enter_value'] == value['id'], 'ASC_OBSERVER_ENTER_VALUE')
        C.need(value['origin']['kind'] == 'enter', 'ASC_OBSERVER_ENTER_ORIGIN')
        equal(value['origin'], dict(kind='enter', scope=scope['id'], phase=phases['id']), 'ENTER_ORIGIN')
        equal(scope['within'], {'kind': 'outside'}, 'SCOPE_WITHIN')
        C.need(scope['lifecycle'] is None, 'ASC_OBSERVER_LIFECYCLE_PROFILE')

    def returned(fid, scope, value, journal, block):
        ret, exit_row = one('returns', fid), one('exits', fid)
        equal(ret, dict(id=ret['id'], function=fid, scope=scope['id'], exit=exit_row['id'], disposition='retained_to_call'), 'RETURN_JOIN')
        equal(exit_row, dict(id=exit_row['id'], function=fid, scope_value=value['id'], site=dict(kind='return_exit', block=block['id']), outcome=dict(kind='normal_retained_call', journal=journal, **{'return': ret['id']})), 'RETAINED_EXIT')
        return ret, exit_row

    for fid, bid, index, op in sites:
        collection(budget, len(functions), 65)
        fn = functions[fid]
        collection(budget, len(fn['blocks']), 65)
        block = next(b for b in fn['blocks'] if b['id'] == bid)
        profile(len(fn['blocks']) == 1 and len(block['ops']) == 2 and index == 1 and block['term']['op'] == 'return', 'NORMAL_LAST_OPERATION_PROFILE')
        call = block['ops'][index - 1]
        profile(call['op'] == 'call' and call['target']['kind'] == 'direct' and call['target']['function']['module'] == {'kind': 'self'}, 'DIRECT_NORMAL_CALL_PROFILE')
        C.need(call['source_plan'] is not None, 'ASC_OBSERVER_CALL_PLAN')
        callee_id = C.qid(call['target']['function'])
        C.need(callee_id in functions, 'ASC_OBSERVER_CALLEE')
        callee = functions[callee_id]
        profile(len(callee['blocks']) == 1, 'CALLEE_BLOCK_PROFILE')
        cb = callee['blocks'][0]
        profile(len(cb['ops']) == 1 and cb['term']['op'] == 'return', 'CALLEE_OPERATIONS_PROFILE')
        begin = cb['ops'][0]
        profile(begin['op'] == 'call' and begin['target']['kind'] == 'import', 'CALLEE_JOURNAL_BEGIN_PROFILE')
        source, receiver = one('scopes', callee_id), one('scopes', fid)
        sv, rv = one('scope_values', callee_id), one('scope_values', fid)
        sb, rb = one('bindings', callee_id), one('bindings', fid)
        adoption = one('adoptions', fid)
        profile(not rows('adoptions', callee_id) and not rows('ends', callee_id) and not rows('ends', fid), 'ADDITIONAL_SOURCE_PROTOCOL_PROFILE')
        profile(source['subject'] == 'inline' and receiver['subject'] == 'existing_object', 'SUBJECT_PROFILE')
        C.need(source['binding'] == sb['id'] and receiver['binding'] == rb['id'], 'ASC_OBSERVER_SCOPE_BINDING')
        C.need(op['scope_value'] == rv['id'] and op['adoption'] == adoption['id'], 'ASC_OBSERVER_SOURCE_NAMESPACE')
        equal(adoption['receiver'], dict(kind='create', scope=receiver['id'], value=rv['id']), 'RECEIVER')
        equal(adoption['callee_function'], call['target']['function'], 'CALLEE')
        equal(adoption['plan'], call['source_plan']['some'], 'PLAN')
        call_site = dict(kind='pre_op', block=bid, index=index - 1)
        normal_site = dict(kind='normal_post', block=bid, index=index - 1)
        equal(adoption['call'], call_site, 'CALL_SITE')
        equal(receiver['enter'], normal_site, 'RECEIVER_ENTER')
        equal(source['program'], receiver['program'], 'PROGRAM')
        C.need(source['program'] is not None, 'ASC_OBSERVER_PROGRAM')
        equal(source['view'], receiver['view'], 'VIEW')
        equal(sb['source_class'], rb['source_class'], 'SOURCE_CLASS')
        import_id = C.qid(begin['target']['import'])
        collection(budget, len(imports), 65)
        C.need(import_id in imports, 'ASC_OBSERVER_JOURNAL_IMPORT')
        imported = imports[import_id]
        equal([imported['kind'], imported['name'], imported['contract'], imported['abi']], ['internal', 'journal_begin', 'construction', {'some': source['program']}], 'JOURNAL_IMPORT')
        C.need(len(begin['results']) == 1, 'ASC_OBSERVER_JOURNAL_RESULT')
        journal = begin['results'][0]['id']
        equal(begin['operands'], [sb['value']], 'JOURNAL_OBJECT')
        C.need(actual.types.get(begin['results'][0]['type'])['kind'] == 'journal', 'ASC_OBSERVER_JOURNAL_TYPE')
        result = op['results'][0]
        profile(result['id'] < 2**32 - 1, 'SOURCE_COORDINATE_PROFILE')
        C.need(actual.types.get(result['type'])['kind'] == 'journal', 'ASC_OBSERVER_RESULT_TYPE')
        for function in (fn, callee):
            signature = actual.types.get(function['signature'])
            collection(budget, len(signature['results']), 65)
            profile(all(actual.types.get(q)['kind'] != 'journal' for q in signature['results']), 'PHYSICAL_JOURNAL_RESULT_PROFILE')
        cr, ce = returned(callee_id, source, sv, journal, cb)
        rr, re = returned(fid, receiver, rv, result['id'], block)
        C.need(adoption['callee_return'] == cr['id'], 'ASC_OBSERVER_RETURN_SELECTION')
        cp, rp = rows('phase_sites', callee_id), rows('phase_sites', fid)
        profile(len(cp) == 3 and len(rp) == 4, 'PHASE_COUNT_PROFILE')
        enter(source, sv, cp[0], callee_id)
        enter(receiver, rv, rp[2], fid)
        begin_site = dict(kind='pre_op', block=cb['id'], index=0)
        bind_site = dict(kind='normal_post', block=cb['id'], index=0)
        equal(source['enter'], begin_site, 'CALLEE_ENTER')
        phase(cp[0], begin_site, dict(kind='outside'), dict(kind='enter_root', scope=source['id'], binding=sb['id'], vtt=None))
        phase(cp[1], bind_site, dict(kind='scope', value=sv['id']), dict(kind='bind_journal', scope_value=sv['id'], journal=journal))
        phase(cp[2], ce['site'], dict(kind='scope', value=sv['id']), dict(kind='scope_exit', exit=ce['id']))
        ticket = rp[0]['event'].get('ticket')
        phase(rp[0], call_site, dict(kind='outside'), dict(kind='call', ticket=ticket, plan=adoption['plan'], object_binding=None, parent=dict(kind='none'), return_adoptions=[adoption['id']]))
        phase(rp[1], normal_site, dict(kind='outside'), dict(kind='call_returned', ticket=ticket))
        phase(rp[2], normal_site, dict(kind='outside'), dict(kind='object_attach_returned', scope=receiver['id'], binding=rb['id'], adoption=adoption['id']))
        phase(rp[3], re['site'], dict(kind='scope', value=rv['id']), dict(kind='scope_exit', exit=re['id']))
        for function in (callee, fn):
            if function['id'] not in proven:
                prove_paths(function, contract, budget, source_observers=True)
                budget.charge(work=64, copied_bytes=128)
                proven.add(function['id'])
        budget.charge(work=64, edges=1, copied_bytes=256)
        checked.append((fid, bid, index, result['id']))
    C.need(actual.prepare_source_data(budget=budget) is before, 'ASC_ORIGINAL_STAMP_CHANGED')
    budget.charge(work=len(checked)+1, copied_bytes=128*(len(checked)+1))
    return tuple(checked)
