"""Declared local references; no dominance/source or runtime admission."""
from .errors import need
from .source_records import raw_contract
def validate_references(root,*,budget,roots=None):
    """Declared local references only; not SSA dominance/source/runtime admission."""
    if root['payload_revision']!=3:return
    raw=raw_contract(root['source_contract'],budget=budget)
    functions={}
    for function in root['functions']:
        budget.charge(work=8,edges=1,copied_bytes=128)
        need(function['id']not in functions,'V3_DUPLICATE');functions[function['id']]=function
    tables={}
    for name in ('bindings','scopes','scope_values','exits','phase_sites','ends','returns','adoptions'):
        rows=raw[name];budget.charge(work=64*(len(rows)+1),edges=8*len(rows),copied_bytes=128*len(rows));index={};previous=None
        for row in rows:
            key=row['function'],row['id']
            if name!='phase_sites':need(previous is None or previous<key,'V3_TABLE_ORDER',name)
            previous=key;need(row['function']in functions,'V3_REFERENCE','function');need(key not in index,'V3_DUPLICATE',name);index[key]=row
        tables[name]=index
    blocks={};values={}
    for fid,function in functions.items():
        bs={};vs={}
        def declared(row):
            budget.charge(work=8,edges=1,copied_bytes=128)
            need(row['id']not in vs,'V3_DUPLICATE','ordinary SSA');vs[row['id']]=row['type']
        for row in function['params']:declared(row)
        for block in function['blocks']:
            budget.charge(work=8,edges=1,copied_bytes=128)
            need(block['id']not in bs,'V3_DUPLICATE','block');bs[block['id']]=block
            for phi in block['phis']:declared(phi['result'])
            for op in block['ops']:
                budget.charge(work=8,edges=1)
                for row in op['results']:declared(row)
            term=block['term']
            if term['op']=='invoke':
                for row in term['normal']['results']:declared(row)
                declared(term['unwind']['exception'])
        need(function['entry']in bs,'V3_REFERENCE','entry');blocks[fid]=bs;values[fid]=vs
    def get(table,fid,identifier):
        budget.charge(work=1,edges=1);need((fid,identifier)in tables[table],'V3_REFERENCE',table);return tables[table][fid,identifier]
    def value(fid,identifier):
        budget.charge(work=1,edges=1);need(identifier in values[fid],'V3_REFERENCE','ordinary SSA')
    def site(fid,where):
        budget.charge(work=2,edges=1);need(where['block']in blocks[fid],'V3_REFERENCE','site block');block=blocks[fid][where['block']]
        if where['kind']in('pre_op','normal_post'):need(where['index']<len(block['ops']),'V3_REFERENCE','site index')
        if where['kind']=='entry':need(where['block']==functions[fid]['entry'],'V3_REFERENCE','entry locator')
        if where['kind']=='return_exit':need(block['term']['op']=='return','V3_REFERENCE','return locator')
        if where['kind']in('invoke_normal','invoke_unwind'):need(block['term']['op']=='invoke','V3_REFERENCE','invoke locator')
        if where['kind']=='unwind_exit'and where['call_index']is not None:need(where['call_index']<len(block['ops']),'V3_REFERENCE','unwind call index')
    def within(fid,row):
        if row['kind']=='scope':get('scope_values',fid,row['value'])
        elif row['kind']=='incoming':lifecycle(row['lifecycle'])
    qindices={};depindices={}
    if roots is not None:
        sources={'nominal':roots[10]['types'],'plan':roots[10]['signatures'],'journal':roots[10]['journals'],'function':root['functions'],'type':roots[1]['types']}
        for namespace,rows in sources.items():
            budget.charge(work=8*(len(rows)+1),edges=len(rows),copied_bytes=128*(len(rows)+1));index={}
            for row in rows:
                need(row['id']not in index,'V3_DUPLICATE',namespace);index[row['id']]=row
            qindices[namespace]=index
        dependencies=roots[2]['manifest']['dependencies'];budget.charge(work=8*(len(dependencies)+1),edges=len(dependencies),copied_bytes=128*(len(dependencies)+1))
        for dependency in dependencies:
            slot=dependency['slot'];need(slot not in depindices,'V3_DUPLICATE','dependency slot');rows=dependency['declarations']
            budget.charge(work=8*(len(rows)+1),edges=len(rows),copied_bytes=128*(len(rows)+1));depindices[slot]={row['id']for row in rows}
    def qref(reference,namespace):
        if roots is None:return
        budget.charge(work=4,edges=1)
        module=reference['module'];identifier=reference['id']
        if module['kind']=='dependency':
            need(module['slot']in depindices,'V3_REFERENCE','dependency slot')
            need(identifier in depindices[module['slot']],'V3_REFERENCE','dependency declaration');return
        need(identifier in qindices[namespace],'V3_REFERENCE',namespace)
    def lifecycle(row):
        for name,namespace in [('source_class','nominal'),('nominal_function','nominal'),('plan','plan'),('program','journal')]:qref(row[name],namespace)
    def element(fid,row):
        if row['kind']=='ssa':value(fid,row['value'])
    for (fid,_),row in tables['bindings'].items():
        value(fid,row['value']);qref(row['source_class'],'nominal');qref(row['static_pointer_type'],'nominal');qref(row['subject']['root_nominal'],'nominal')
        budget.charge(work=8*len(row['subject']['edges']),edges=len(row['subject']['edges']))
        for edge in row['subject']['edges']:
            if edge['kind']=='element':element(fid,edge['index'])
        origin=row['origin']
        for name in('site','call'):
            if name in origin:site(fid,origin[name])
        if 'plan'in origin:qref(origin['plan'],'plan')
        for name in('binding','old_binding'):
            if name in origin:get('bindings',fid,origin[name])
        if 'value'in origin:value(fid,origin['value'])
    for (fid,_),row in tables['scopes'].items():
        site(fid,row['enter']);get('scope_values',fid,row['enter_value']);within(fid,row['within'])
        if row['binding']is not None:get('bindings',fid,row['binding'])
        if row['program']is not None:qref(row['program'],'journal')
        if row['lifecycle']is not None:lifecycle(row['lifecycle'])
    for (fid,_),row in tables['scope_values'].items():
        origin=row['origin'];kind=origin['kind']
        if kind=='enter':get('scopes',fid,origin['scope']);get('phase_sites',fid,origin['phase'])
        if 'site'in origin:site(fid,origin['site'])
        if kind=='copy':get('scope_values',fid,origin['source'])
        if kind=='select':
            value(fid,origin['condition']);get('scope_values',fid,origin['if_true']);get('scope_values',fid,origin['if_false'])
        if kind=='phi':
            need(origin['block']in blocks[fid],'V3_REFERENCE','phi block')
            budget.charge(work=8*len(origin['incoming']),edges=len(origin['incoming']))
            for incoming in origin['incoming']:need(incoming['predecessor']in blocks[fid],'V3_REFERENCE','predecessor');get('scope_values',fid,incoming['value'])
    for (fid,_),row in tables['exits'].items():
        site(fid,row['site']);get('scope_values',fid,row['scope_value']);outcome=row['outcome']
        for name in('journal','exception'):
            if name in outcome:value(fid,outcome[name])
        if 'retained_scope_value'in outcome:get('scope_values',fid,outcome['retained_scope_value'])
        if 'return'in outcome:get('returns',fid,outcome['return'])
    for (fid,_),row in tables['ends'].items():
        site(fid,row['site']);get('bindings',fid,row['binding']);effect=row['effect']
        if 'call'in effect:site(fid,effect['call'])
        if 'plan'in effect:qref(effect['plan'],'plan')
        if 'program'in effect:qref(effect['program'],'journal')
    for (fid,_),row in tables['returns'].items():get('scopes',fid,row['scope']);get('exits',fid,row['exit'])
    for (fid,_),row in tables['adoptions'].items():
        site(fid,row['call']);qref(row['plan'],'plan');qref(row['callee_function'],'function');receiver=row['receiver'];get('scope_values',fid,receiver['value'])
        if receiver['kind']=='create':get('scopes',fid,receiver['scope'])
        if row['callee_function']['module']['kind']=='self':get('returns',row['callee_function']['id'],row['callee_return'])
    tickets=set()
    for (fid,_),row in tables['phase_sites'].items():
        event=row['event']
        if event['kind']=='call':
            key=fid,event['ticket'];need(key not in tickets,'V3_DUPLICATE','call ticket');tickets.add(key)
    for (fid,_),row in tables['phase_sites'].items():
        site(fid,row['site']);within(fid,row['within']);event=row['event'];kind=event['kind']
        if row['selector']['kind']=='incoming_lifecycle':lifecycle(row['selector']['lifecycle'])
        for name,table in [('scope','scopes'),('scope_value','scope_values'),('binding','bindings'),('object_binding','bindings'),('end','ends'),('exit','exits'),('adoption','adoptions')]:
            if name in event and event[name]is not None:get(table,fid,event[name])
        if kind=='scope_value':get('scope_values',fid,event['value'])
        for name in('journal','parent_journal','vtt','exception'):
            if name in event and event[name]is not None:value(fid,event[name])
        if 'element'in event:element(fid,event['element'])
        if 'plan'in event:qref(event['plan'],'plan')
        if 'parent'in event:
            parent=event['parent']
            if 'journal'in parent:value(fid,parent['journal'])
            if 'element'in parent:element(fid,parent['element'])
        if 'ticket'in event:need((fid,event['ticket'])in tickets,'V3_REFERENCE','call ticket')
        budget.charge(work=8*len(event.get('return_adoptions',[])),edges=len(event.get('return_adoptions',[])))
        for identifier in event.get('return_adoptions',[]):get('adoptions',fid,identifier)
    for fid,function in functions.items():
        budget.charge(work=4,edges=1)
        for block in function['blocks']:
            budget.charge(work=4,edges=1)
            for op in block['ops']:
                budget.charge(work=4,edges=1)
                if op['op']=='source_journal_observe':
                    get('scope_values',fid,op['scope_value']);get('adoptions',fid,op['adoption']);need(len(op['results'])==1 and not op['operands'],'V3_OBSERVER_SHAPE')
                    if roots is not None:
                        qref(op['results'][0]['type'],'type')
                        reference=op['results'][0]['type']
                        need(reference['module']['kind']=='self','V3_OBSERVER_EXTERNAL_TYPE_UNAVAILABLE')
                        need(qindices['type'][reference['id']]['kind']=='journal','V3_OBSERVER_TYPE')
