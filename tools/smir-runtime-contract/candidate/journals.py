"""Independent typed nested construction-journal checkpoint replay.

Resolver inputs are runtime-owned admitted program/nominal/object facts. This
validates state transfer; a serialized program/instance ID is not authority.
"""
from .errors import option, require, unique
from .lifetimes import seed_cells

TERMINAL={'destroyed','abandoned','terminated'}


def validate(documents, *, thread, highwater, modules, objects, handles, program,
             nominal, value_check, type_equal, lifetimes=None, partials=None):
    table=unique(documents,'id','RT_JOURNAL_INSTANCE')
    states,events={},[]
    for identifier,document in table.items():
        snapshot=document['state']
        require(identifier>0 and snapshot['instance']==identifier and snapshot['revision']==1,
                'RT_JOURNAL_INSTANCE')
        owner=modules.get(document['module'])
        require(owner is not None and owner['generation']==document['module_generation'],
                'RT_JOURNAL_MODULE')
        require(snapshot['thread']==thread and snapshot['program']==document['program'] and
                snapshot['activation']>0 and snapshot['generation']>0 and snapshot['transition']>0,
                'RT_JOURNAL_OWNER')
        key,definition=program(document['module'],document['program'])
        slots=unique(definition['slots'],'id')
        formals=unique(definition['params'],'id')
        captures=unique(document['captures'],'parameter','RT_JOURNAL_CAPTURE')
        require(captures.keys()==formals.keys(),'RT_JOURNAL_CAPTURE')
        dynamic={}
        for formal_id,formal in formals.items():
            value=captures[formal_id]['value']
            expected=nominal(document['module'],formal['type'])
            execution=option(expected['execution'])
            require(execution is not None and type_equal(document['module'],value['type'],execution),
                    'RT_JOURNAL_CAPTURE_TYPE')
            value_check(document['module'],value,snapshot['activation'])
            dynamic[formal_id]=(value,expected)
        counts=unique(document['counts'],'slot','RT_JOURNAL_COUNTS')
        require(counts.keys()==slots.keys(),'RT_JOURNAL_COUNTS')
        cells={}
        for slot_id,slot in slots.items():
            selected=option(slot['count_source'])
            count=slot['count']
            if selected is not None:
                require(selected in dynamic,'RT_JOURNAL_COUNT_CAPTURE')
                value,expected=dynamic[selected]
                require(expected['bits']==64 and expected['signed'] is False and
                        value['payload']['kind']=='scalar','RT_JOURNAL_COUNT_CAPTURE')
                count=int.from_bytes(bytes.fromhex(value['payload']['bits']),'little')
            require(counts[slot_id]['count']==count and count<=100000 and
                    count*slot['stride']<=slot['extent'], 'RT_JOURNAL_COUNTS')
            require(slot['role']!='vla' or count>0,'RT_JOURNAL_COUNTS')
            for element in range(count):
                cells[slot_id,element]={'phase':'empty','ticket':None,'ordinal':None}
        storage=objects.get(document['object'])
        require(storage is not None and storage['generation']==document['object_generation'] and
                storage['address']<=document['object_address']<=storage['address']+storage['size'],
                'RT_JOURNAL_OBJECT')
        require(snapshot['stage'] in TERMINAL or storage['live'],'RT_JOURNAL_OBJECT')
        for slot in slots.values():
            address=document['object_address']+slot['offset']
            require(address%slot['align']==0 and address+slot['extent']<=storage['address']+storage['size'],
                    'RT_JOURNAL_OBJECT_EXTENT')
        sequences=document['event_sequences']
        require(len(sequences)==len(snapshot['entries']) and sequences==sorted(set(sequences))
                and all(0<s<=highwater for s in sequences),'RT_JOURNAL_EVENT_SEQUENCE')
        for sequence,event in zip(sequences,snapshot['entries']):
            require(all(event[field]==snapshot[field] for field in
                        ['instance','transition','thread','activation','generation']), 'RT_JOURNAL_EVENT_OWNER')
            events.append((sequence,identifier,event))
        ordinal,stage=seed_cells(document,cells,lifetimes or {},partials)
        states[identifier]={'key':key,'document':document,'snapshot':snapshot,'slots':slots,'cells':cells,
                            'definition':definition,'ordinal':ordinal,'tickets':set(),'exception':None,'stage':stage,'children':{}}
    require(len({sequence for sequence,_,_ in events})==len(events),'RT_JOURNAL_EVENT_SEQUENCE')
    for identifier,state in states.items():
        parent=option(state['snapshot']['parent_instance'])
        if parent is None:
            continue
        require(parent['journal'] in states and parent['journal']!=identifier,'RT_JOURNAL_PARENT')
        outer=states[parent['journal']]
        cell=parent['slot'],parent['element']
        require(cell in outer['cells'] and cell not in outer['children'],'RT_JOURNAL_PARENT')
        slot=outer['slots'][parent['slot']]
        child_ref=option(slot['child_program'])
        require(child_ref is not None and program(outer['document']['module'],child_ref)[0]==state['key'],
                'RT_JOURNAL_PARENT_PROGRAM')
        source=outer['document']
        document=state['document']
        require(document['object']==source['object'] and document['object_generation']==source['object_generation']
                and document['object_address']==source['object_address']+slot['offset']+parent['element']*slot['stride'],
                'RT_JOURNAL_PARENT_RANGE')
        outer['children'][cell]=identifier
        visited={identifier}
        cursor=parent
        while cursor is not None:
            require(cursor['journal'] not in visited,'RT_JOURNAL_PARENT_CYCLE')
            visited.add(cursor['journal'])
            cursor=option(states[cursor['journal']]['snapshot']['parent_instance'])

    def live(state):
        return [(cell['ordinal'],slot,element) for (slot,element),cell in state['cells'].items()
                if cell['phase']=='alive']

    def complete(state):
        return all(cell['phase']=='alive' or cell['phase']=='empty' and state['slots'][slot]['role']=='union_member'
                   for (slot,_),cell in state['cells'].items())

    for _,identifier,event in sorted(events):
        state=states[identifier]
        key=event['slot'],event['element']
        require(key in state['cells'] and event['owner']==state['slots'][key[0]]['owner'],
                'RT_JOURNAL_EVENT_SLOT')
        cell,slot=state['cells'][key],state['slots'][key[0]]
        phase,ticket=event['phase'],event['ticket']
        require(ticket>0 and state['stage'] not in TERMINAL,'RT_JOURNAL_EVENT_PHASE')
        if phase=='construct_begin':
            require(state['stage']=='constructing' and cell['phase']=='empty' and ticket not in state['tickets'],
                    'RT_JOURNAL_REPLAY')
            require(key[1]==0 or state['cells'][key[0],key[1]-1]['phase']=='alive','RT_JOURNAL_ARRAY_PREFIX')
            require(all(all(c['phase']=='alive' for (s,_),c in state['cells'].items() if s==dependency)
                        for dependency in slot['dependencies']),'RT_JOURNAL_DEPENDENCY')
            parent_slot=option(slot['parent'])
            require(parent_slot is None or state['cells'][parent_slot,0]['phase']=='constructing',
                    'RT_JOURNAL_CONSTRUCTION_PARENT')
            if slot['role']=='union_member':
                require(all(s==key[0] or other['role']!='union_member' or other['parent']!=slot['parent'] or
                            all(c['phase']=='empty' for (n,_),c in state['cells'].items() if n==s)
                            for s,other in state['slots'].items()),'RT_JOURNAL_UNION')
            parent=option(state['snapshot']['parent_instance'])
            if parent is not None:
                require(states[parent['journal']]['cells'][parent['slot'],parent['element']]['phase']=='constructing',
                        'RT_JOURNAL_PARENT_NOT_CONSTRUCTING')
            state['tickets'].add(ticket)
            cell.update(phase='constructing',ticket=ticket)
        elif phase=='construct_commit':
            require(cell['phase']=='constructing' and cell['ticket']==ticket,'RT_JOURNAL_REPLAY')
            require(all(c['phase']=='alive' or other['role']=='union_member' and c['phase']=='empty'
                        for child,other in state['slots'].items() if option(other['parent'])==key[0]
                        for (s,_),c in state['cells'].items() if s==child),'RT_JOURNAL_INCOMPLETE')
            if slot['child_program'] is not None:
                require(key in state['children'] and complete(states[state['children'][key]]),
                        'RT_JOURNAL_CHILD_INCOMPLETE')
            state['ordinal']+=1
            cell.update(phase='alive',ordinal=state['ordinal'])
        elif phase=='construct_failed':
            require(cell['phase']=='constructing' and cell['ticket']==ticket,'RT_JOURNAL_REPLAY')
            child=state['children'].get(key)
            require(child is None or all(c['phase'] in {'empty','failed','destroyed'} for c in states[child]['cells'].values()),'RT_JOURNAL_CHILD_CLEANUP')
            state['stage']='unwinding'
            cell['phase']='failed'
        elif phase=='destroy_begin':
            if state['stage']=='constructing':
                require(complete(state),'RT_JOURNAL_INCOMPLETE')
                state['stage']='alive'
            covered={s for _,root,_ in live(state) for s in state['slots'][root]['covers']}
            plan=[(s,e) for _,s,e in sorted(live(state),reverse=True) if s not in covered]
            schedule=state['definition']['exception_order' if state['stage']=='unwinding' else 'normal_order']
            rank={slot:index for index,slot in enumerate(schedule)}
            ranks=[rank[s] for s,_ in plan]
            require(ranks==sorted(ranks),'RT_JOURNAL_CLEANUP_ORDER')
            parent=option(state['snapshot']['parent_instance'])
            if parent is not None:
                require(states[parent['journal']]['cells'][parent['slot'],parent['element']]['phase']
                        in {'constructing','destroying'},'RT_JOURNAL_PARENT_CLEANUP')
            require(plan and plan[0]==key and ticket not in state['tickets'],'RT_JOURNAL_CLEANUP_ORDER')
            state['tickets'].add(ticket)
            cell.update(phase='destroying',ticket=ticket)
            for (s,_),child in state['cells'].items():
                if s in slot['covers'] and child['phase']=='alive':
                    child['phase']='delegated'
        elif phase in {'destroy_commit','destroy_raised','terminate'}:
            require(cell['phase']=='destroying' and cell['ticket']==ticket,'RT_JOURNAL_REPLAY')
            child=state['children'].get(key)
            require(child is None or all(c['phase'] in {'empty','failed','destroyed'}
                        for c in states[child]['cells'].values()),'RT_JOURNAL_CHILD_CLEANUP')
            if phase=='terminate':
                require(state['stage']=='unwinding','RT_JOURNAL_TERMINATION')
                state['stage']='terminated'
            else:
                cell['phase']='destroyed'
                if phase=='destroy_raised':
                    state['stage']='unwinding'
                for (s,_),child_cell in state['cells'].items():
                    if s in slot['covers'] and child_cell['phase']=='delegated':
                        child_cell['phase']='destroyed'
        else:
            require(False,'RT_JOURNAL_EVENT_PHASE')
        selected=option(event['exception_lease'])
        if phase in {'construct_failed','destroy_raised'}:
            require(selected in handles and handles[selected]['live'] and handles[selected]['kind']=='exception',
                    'RT_JOURNAL_EXCEPTION')
            state['exception']=selected
        require(selected==state['exception'] and event['ordinal']==state['ordinal'],
                'RT_JOURNAL_EVENT_STATE')
    for state in states.values():
        snapshot=state['snapshot']
        require(snapshot['next_ordinal']==state['ordinal'] and option(snapshot['exception_lease'])==state['exception'],
                'RT_JOURNAL_FINAL_STATE')
        final=snapshot['stage']
        require(final in {'constructing','alive','unwinding','cleanup'}|TERMINAL,'RT_JOURNAL_STAGE')
        if final=='alive':
            require(state['stage'] in {'constructing','alive'} and
                    (state['stage']=='alive' or complete(state)), 'RT_JOURNAL_FINAL_STATE')
        elif final=='destroyed':
            require(all(c['phase'] in {'empty','failed','destroyed'} for c in state['cells'].values()),
                    'RT_JOURNAL_FINAL_STATE')
        elif final=='abandoned':
            require(not any(c['phase'] in {'alive','constructing','destroying'} and
                            state['slots'][s]['destructor'] is not None for (s,_),c in state['cells'].items()),
                    'RT_JOURNAL_LONGJMP_NONTRIVIAL')
        elif final=='cleanup':
            require(state['stage'] in {'alive','unwinding'} or complete(state),'RT_JOURNAL_FINAL_STATE')
        else:
            require(final==state['stage'],'RT_JOURNAL_FINAL_STATE')
    return states
