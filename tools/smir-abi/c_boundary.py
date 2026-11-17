"""Explicit C-linkage ABI view; ordinary C++ identity is never changed in place."""
from copy import deepcopy

from layout import ABIError
from nominal import NominalGraph

ALIASES={'size_t':'unsigned long','ptrdiff_t':'long','wint_t':'unsigned int',
         'wchar_t':'int','char8_t':'unsigned char','char16_t':'unsigned short','char32_t':'unsigned int'}
FORBIDDEN={'reference','member_pointer','handle','snapshot'}


def compatible(graph,left,right,left_owner,right_owner,*,address_only=False):
    views=deepcopy(graph.modules)
    projected=NominalGraph(views[graph.module_id],graph.module_id,
        {name:doc for name,doc in views.items() if name!=graph.module_id},graph.bindings,graph.families)
    pending=[(left,right,left_owner,right_owner,not address_only)]
    seen=set()
    try:
        while pending:
            ar,br,ao,bo,value=pending.pop()
            am,a=graph.resolve(ar,ao);bm,b=graph.resolve(br,bo)
            pair=am,a['id'],bm,b['id'],value
            if pair in seen:
                continue
            seen.add(pair)
            if a['kind']!=b['kind'] or a['kind'] in FORBIDDEN:
                return False
            originals=[(am,a),(bm,b)]
            targets=[projected.tables[owner][item['id']] for owner,item in originals]
            kind=a['kind']
            opaque=(kind=='record' and not value and any('complete' not in item['flags'] for _,item in originals))
            for (owner,item),target in zip(originals,targets):
                target['identity']['language']='c23'
                target['flags']=[flag for flag in item['flags'] if flag not in ('c_linkage','c_compatible')]
                if kind=='scalar':
                    target['identity']['entity']=ALIASES.get(item['identity']['entity'],item['identity']['entity'])
                if kind=='function':
                    target['identity'].update(entity='function',linkage='builtin',unit=None)
                elif kind in {'pointer','array','vector','complex','atomic','bitint'}:
                    target['identity'].update(entity=kind,linkage='builtin',unit=None)
                if kind in ('record','enum'):
                    if opaque:
                        continue
                    if 'complete' not in item['flags']:
                        if value:
                            return False
                    else:
                        if item['identity']['language']=='cpp23' and 'c_compatible' not in item['flags']:
                            return False
                        if 'trivial_copy' not in item['flags'] or 'trivial_destroy' not in item['flags'] or item['methods']:
                            return False
                        if 'scoped' in item['flags']:
                            return False
                        if kind=='record':
                            layout=graph.layout({'module':{'kind':'self'},'id':item['id']},owner)
                            if layout['bases'] or layout['vptrs'] or not layout['fields'] or any(
                                    set(field['flags']) & {'no_unique_address','private','protected'} for field in layout['fields']):
                                return False
                        target['flags']=[flag for flag in target['flags'] if flag not in ('class','fixed_base')]
                        if kind=='record' and target['record_input'] is not None:
                            source=target['record_input']['some']
                            if source['kind']=='class':source['kind']='struct'
                            for key in ('pod03','trivial','standard_layout','polymorphic','dynamic','empty'):
                                source[key]=False
            if opaque:
                continue
            if len(a['elements'])!=len(b['elements']):
                return False
            next_value=kind not in ('pointer','reference','member_pointer')
            pending += [(ac,bc,am,bm,next_value) for ac,bc in zip(a['elements'],b['elements'])]
            if kind=='record' and a['layout'] is not None and b['layout'] is not None:
                al=graph.layout(ar,ao);bl=graph.layout(br,bo)
                if len(al['fields'])!=len(bl['fields']):
                    return False
                pending += [(ac['type'],bc['type'],am,bm,True) for ac,bc in zip(al['fields'],bl['fields'])]
        if address_only and graph.resolve(left,left_owner)[1]['layout'] is None:
            return projected.compatible(left,right,left_owner,right_owner)
        return projected.boundary_compatible(left,right,left_owner,right_owner)
    except (ABIError,KeyError):
        return False
