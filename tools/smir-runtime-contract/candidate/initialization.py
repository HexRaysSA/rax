"""R041: private constant-initialization transaction, not production admission.

Resolvers/evaluator and memory reservations are trusted loader inputs over the
same admitted roots. File bytes never supply a Python callable or capability.
"""
from copy import copy, deepcopy
from dataclasses import dataclass
from threading import Lock

from .errors import option, require
from .relocations import Registry as Relocations, interval, remove_origins


def physical_symbols(roots):
    """Resolve EVERY alias owner to actual storage, retaining alias selection."""
    symbols={s['id']:s for s in roots[2]['symbols']};resolved={}
    for identity in symbols:
        path=[];cursor=identity
        while cursor not in resolved:
            require(cursor in symbols and cursor not in path,'RT_ALIAS_CYCLE')
            path.append(cursor);definition=option(symbols[cursor]['definition'])
            if definition is None or definition['kind']!='alias':
                target=None if definition is None or definition['kind'] not in {'data','tls'} else (
                    definition['kind'],definition['segment'])
                break
            require(definition['target']['module']['kind']=='self','RT_DEFINITION_SELF')
            cursor=definition['target']['id']
        else:target=resolved[cursor]
        for member in path:resolved[member]=target
    return {i:storage for i,storage in resolved.items() if storage is not None}


def validate_records(roots, context):
    records=roots[5]['constant_initializers']
    require([r['id'] for r in records]==sorted({r['id'] for r in records}), 'RT_INITIALIZER_ORDER')
    data={s['id']:s for s in roots[4]['segments']}
    tls={s['storage']['id']:s['storage'] for s in roots[7]['segments']}
    symbols={s['id']:s for s in roots[2]['symbols']}
    physical=physical_symbols(roots)
    physical_groups={}
    for identity,key in physical.items():
        physical_groups.setdefault(key,set()).add(option(symbols[identity]['comdat']))
    require(all(len(groups)==1 for groups in physical_groups.values()),'RT_INITIALIZER_SHARED_SELECTION')
    regions={}
    for r in records:
        require(r['source_kind'] in {'data','tls'},'RT_INITIALIZER_SOURCE')
        source=(data if r['source_kind']=='data' else tls).get(r['source'])
        require(source is not None,'RT_INITIALIZER_SOURCE')
        require(r['layout']['module']['kind']==r['function']['module']['kind']=='self',
                'RT_INITIALIZER_SELF')
        layout=context.storage_layout(r['layout'])
        size=len(bytes.fromhex(source['initial']))+source['zero_fill']
        require(layout['access_bytes']>0 and r['offset']+layout['access_bytes']<=size,
                'RT_INITIALIZER_BOUNDS')
        body=context.function(r['function']);signature=context.execution(body['signature'])
        require(body['abi_signature'] is None and signature['kind']=='function' and
                signature['cc']=='portable' and not signature['variadic'] and signature['params']==[] and
                signature['param_noundef']==[] and signature['result_noundef']==[False] and
                len(signature['results'])==1 and context.execution_equal(signature['results'][0],layout['type']) and
                body['escape']=='propagate' and not body['no_return'], 'RT_INITIALIZER_SIGNATURE')
        require(len(body['blocks'])==1 and not body['blocks'][0]['phis'] and
                body['blocks'][0]['term']['op']=='return' and len(body['blocks'][0]['term']['values'])==1,
                'RT_INITIALIZER_CONTROL')
        owner=option(r['association'])
        owners=[symbols[i] for i,key in physical.items() if key==(r['source_kind'],r['source'])]
        if owner is None:
            require(not any(s['comdat'] is not None or s['binding'] in {'weak','external_weak','common'}
                            for s in owners),'RT_INITIALIZER_OWNER_REQUIRED')
        else:
            require(owner['module']['kind']=='self' and owner['id'] in symbols,'RT_INITIALIZER_OWNER')
            actual=symbols[owner['id']]
            require(actual in owners and option(actual['definition'])['kind']==r['source_kind'] and
                    all(s['comdat']==actual['comdat'] for s in owners),
                    'RT_INITIALIZER_SHARED_SELECTION')
        # Offsets are private Raw8 patch coordinates: access alignment is ONE.
        key=r['source_kind'],r['source'];lo,hi=r['offset'],r['offset']+layout['access_bytes']
        require(all(hi<=a or b<=lo for a,b in regions.setdefault(key,[])), 'RT_INITIALIZER_OVERLAP')
        regions[key].append((lo,hi))
        for leaf in roots[5]['relocations']:
            if (leaf['source_kind'],leaf['source'])==key:
                require(hi<=leaf['offset'] or leaf['offset']+leaf['width']<=lo,'RT_INITIALIZER_OVERLAP')
    return records


@dataclass(frozen=True)
class Ticket:
    registry: object
    identity: int


class Store:
    """One static transaction across modules and per-TID TLS instances.

    images keys are (artifact, data|tls, segment, None|logical_thread). Each
    image has bytes/poison/undef/origins/mutable/sealed. `machines` has SAME keys
    (artifact,None|thread) and actual SEM memory/symbol/code reservation objects.
    This oracle publishes no namespace and executes no source constructor.
    """
    def __init__(self, images, modules, machines, selection, *, retained_modules=None,
                 max_bytes=1048576,max_nodes=100000):
        self.max_bytes=max_bytes;self.max_nodes=max_nodes
        self._budget(images,max_bytes,max_nodes)
        plan=selection.__dict__
        require(sum(len(v) if isinstance(v,(dict,list,tuple,set,frozenset)) else 1 for v in plan.values())<=max_nodes,
                'RT_INITIALIZER_RESOURCE')
        self._selection_snapshot=deepcopy(plan)
        self.images=deepcopy(images);self.modules=modules;self.machines=machines;self.selection=selection
        self.retained_modules={} if retained_modules is None else retained_modules
        self.exposed=set();self.exposed_code=set();self.bindings=[]
        self.revision=1;self._next=1;self._prepared={};self._lock=Lock()
        self.committed=False

    @staticmethod
    def _budget(images,max_bytes,max_nodes):
        require(type(max_bytes) is int and max_bytes>=0 and type(max_nodes) is int and max_nodes>=0,
                'RT_INITIALIZER_RESOURCE')
        total=nodes=0
        for image in images.values():
            size=len(image['bytes']);total+=size;nodes+=1+len(image['origins'])
            require(total<=max_bytes and nodes<=max_nodes and
                    len(image['poison'])==len(image['undef'])==size,'RT_INITIALIZER_RESOURCE')
        return total,nodes

    def _facts(self):
        require(self.selection.__dict__==self._selection_snapshot,'RT_INITIALIZER_SELECTION')
        facts={}
        for artifact,module in self.modules.items():
            context=module['context'];context.assert_snapshot()
            require(context.abi_checked and context.execution_checked is not None and module['pins']>0 and
                    module['phase']=='admitted','RT_INITIALIZER_ADMISSION')
            facts[artifact]=(context,module['generation'])
        return facts

    def _kept(self,artifact,record):
        association=option(record['association'])
        return association is None or self.selection.symbols.get((artifact,association['id']))==(artifact,association['id'])

    def _providers(self):
        require(not self.modules.keys()&self.retained_modules.keys(),'RT_INITIALIZER_PROVIDER')
        facts={}
        for artifact,module in self.retained_modules.items():
            context=module['context'];context.assert_snapshot()
            require(context.abi_checked and context.execution_checked is not None and
                    module['phase'] in {'published','closing'} and module['generation']>0 and module['pins']>0,
                    'RT_INITIALIZER_PROVIDER')
            capability=module.get('held_lease');table=module.get('lease_table',{})
            require(capability is not None and capability in table,'RT_INITIALIZER_PROVIDER_LEASE')
            entry=table[capability]
            require(entry['module']==artifact and entry['generation']==module['generation'] and entry['live'] and
                    entry['kind'] in {'object','code','import','tls','callback','exception','descriptor','frame'},
                    'RT_INITIALIZER_PROVIDER_LEASE')
            facts[artifact]=(context,module['generation'],capability,entry['kind'])
        return facts

    def _storage_kept(self,artifact,roots,kind,segment):
        owners=[i for i,key in physical_symbols(roots).items() if key==(kind,segment)]
        retained=[]
        for identity in owners:
            target=self.selection.symbols.get((artifact,identity))
            if target is None:retained.append(False);continue
            provider,symbol=target
            # Existing published winners deliberately do not belong to this
            # new-SCC Store. A different artifact cannot own THIS allocation.
            if provider!=artifact:retained.append(False);continue
            other=self.modules[provider]['context'].sections
            storage=physical_symbols(other).get(symbol)
            retained.append((provider,storage)==(artifact,(kind,segment)))
        require(not retained or all(retained) or not any(retained),'RT_INITIALIZER_SHARED_SELECTION')
        return not retained or all(retained)

    def prepare(self,order, runtime_contexts, evaluator, resolve_relocation, *, max_operations=65536,max_bytes=1048576):
        """O(patches^2 + evaluator cost), O(staged storage + evaluator quota).

        Order is the trusted loader's deterministic SCC/module order. Complete
        all-root/deployment admission precedes this API. Evaluator independently
        verifies actual executable functions; this is not an envelope executor.
        """
        with self._lock:
            require(not self.committed,'RT_INITIALIZER_ALREADY_COMMITTED')
            require(type(max_operations) is int and max_operations>=0 and type(max_bytes) is int and
                    0<=max_bytes<=self.max_bytes,'RT_INITIALIZER_RESOURCE')
            total,nodes=self._budget(self.images,min(max_bytes,self.max_bytes),self.max_nodes)
            facts=self._facts();providers=self._providers();revision=self.revision
            exposed=set(self.exposed);exposed_code=set(self.exposed_code)
        require(len(order)==len(set(order)) and set(order)==facts.keys(),'RT_INITIALIZER_MODULE_ORDER')
        generations={a:fact[1] for a,fact in (facts|providers).items()};bindings=[];selected=[]
        roots_by_owner={};records_by_owner={};jobs=[];operations=0
        for artifact in order:
            context=facts[artifact][0]
            roots={i:context.sections[i] for i in (2,4,5,6,7,9)}
            records=validate_records(roots,runtime_contexts[artifact])
            roots_by_owner[artifact]=roots;records_by_owner[artifact]=records
            selected.extend((artifact,r) for r in records if self._kept(artifact,r) and
                            self._storage_kept(artifact,roots,r['source_kind'],r['source']))
        # Cumulative input, SSA, component, and output preflight precedes EVERY
        # staging clone. The independent evaluator repeats its own per-job gate.
        for artifact,record in selected:
            context=facts[artifact][0];graph=context.execution_checked.types
            tids=sorted({k[3] for k in self.images if k[:3]==(artifact,record['source_kind'],record['source'])},
                        key=lambda tid:-1 if tid is None else tid)
            require(tids and (record['source_kind']!='data' or tids==[None]),'RT_INITIALIZER_TLS_RESERVATION')
            for thread in tids:
                machine=self.machines[artifact,thread];body=context.function(record['function'])
                operations+=len(body['blocks'][0]['ops'])
                total+=context.layouts.items[('self',record['layout']['id'])]['access_bytes']
                nodes+=len(machine.memory.objects)+len(machine.symbols)+len(machine.code_pointers)
                for item in machine.memory.objects.values():
                    require(type(item['size']) is int and 0<=item['size']<=max_bytes-total,
                            'RT_INITIALIZER_RESOURCE')
                    total+=item['size']
                for op in body['blocks'][0]['ops']:
                    for result in op['results']:
                        total+=(graph.width(result['type'])+7)//8
                        module=result['type']['module']
                        typ=('self',result['type']['id']) if module['kind']=='self' else (
                            'dependency',module['slot'],result['type']['id'])
                        nodes+=graph.value_costs[typ]
                    if op['op']=='address_of':
                        module=op['symbol']['module']
                        sym=('self',op['symbol']['id']) if module['kind']=='self' else (
                            'dependency',module['slot'],op['symbol']['id'])
                        actual=context.execution_checked.dependencies.symbols[sym]
                        require(record['source_kind']=='tls' or actual['kind']!='tls','RT_INITIALIZER_AMBIENT_TLS')
                require(total<=max_bytes and nodes<=self.max_nodes and operations<=max_operations,
                        'RT_INITIALIZER_RESOURCE')
                jobs.append((artifact,record,thread,machine))
        # Images are only this NEW SCC's unpatched initial storage; old live
        # modules are external reservations and cannot be changed by this Store.
        for (artifact,kind,segment,thread),image in self.images.items():
            require(artifact in facts and kind in {'data','tls'} and
                    (thread is None if kind=='data' else type(thread) is int and thread>0),
                    'RT_INITIALIZER_IMAGE')
            roots=roots_by_owner[artifact]
            records=roots[4]['segments'] if kind=='data' else [r['storage'] for r in roots[7]['segments']]
            actual=next((r for r in records if r['id']==segment),None)
            require(actual is not None and len(image['bytes'])==len(actual['initial'])//2+actual['zero_fill'] and
                    image['mutable']==actual['mutable'] and not image['sealed'] and not image['origins'],
                    'RT_INITIALIZER_IMAGE')
            require(image['bytes']==bytes.fromhex(actual['initial'])+bytes(actual['zero_fill']) and
                    image['poison']==bytes.fromhex(actual['poison'])+bytes([255 if actual['zero_shadow']=='poison' else 0])*actual['zero_fill'] and
                    image['undef']==bytes.fromhex(actual['undef'])+bytes([255 if actual['zero_shadow']=='undef' else 0])*actual['zero_fill'],
                    'RT_INITIALIZER_IMAGE')
        with self._lock:
            require(self._facts()==facts and self._providers()==providers and self.revision==revision,'RT_INITIALIZER_STALE')
            staged=deepcopy(self.images)
        for artifact in order:
            roots=roots_by_owner[artifact];records=records_by_owner[artifact]
            threads={key[3] for key in staged if key[0]==artifact}
            for thread in threads:
                local={(kind,segment):image for (owner,kind,segment,tid),image in staged.items()
                       if owner==artifact and tid==thread}
                leaf=[]
                for r in roots[5]['relocations']:
                    if (r['source_kind']=='tls')!=(thread is not None):continue
                    if not self._storage_kept(artifact,roots,r['source_kind'],r['source']):continue
                    # Whole segment COMDAT selection was validated above. A
                    # discarded owner cannot cause relocation exposure either.
                    owners=[v for v in records if (v['source_kind'],v['source'])==(r['source_kind'],r['source'])]
                    if owners and not self._kept(artifact,owners[0]):continue
                    leaf.append(r)
                oracle=Relocations(local,generations)
                ticket=oracle.prepare(leaf,lambda ref:resolve_relocation(artifact,thread,ref))
                oracle.commit(ticket)
                for (kind,segment),image in oracle.images.items():staged[artifact,kind,segment,thread]=image
                exposed|=oracle.exposed;bindings+=oracle.bindings
                for identity in oracle.exposed_code:
                    matches={token for m in self.machines.values() for token,(pointer,_) in m.code_pointers.items()
                             if (pointer.origin,pointer.generation)==identity}
                    require(len(matches)==1,'RT_INITIALIZER_CODE_RESERVATION')
                    exposed_code|=matches
        for artifact,record,thread,machine in jobs:
            context=facts[artifact][0];key=artifact,record['source_kind'],record['source'],thread
            # S074 preflights every actual object before its own bounded
            # clone and guarantees no input mutation. Do not pre-clone its
            # backing here and thereby bypass that resource preflight.
            private=copy(machine.memory)
            private.exposed=set(machine.memory.exposed)
            # Both oracles use their actual object identities, never numeric
            # addresses. Imported relocation IDs must use that same registry.
            private.exposed|={identity for identity,generation in exposed if identity in private.objects and
                              private.objects[identity]['generation']==generation}
            result=evaluator(context,record['function'],record['layout'],memory=private,
                symbols=machine.symbols,code_pointers=machine.code_pointers,
                exposed_code=machine.exposed_code|{v for v in exposed_code if type(v) is int},
                max_operations=max_operations,max_bytes=max_bytes)
            image=staged[key];offset=record['offset'];size=len(result.bytes)
            require(not image.get('sealed',False) and offset+size<=len(image['bytes']),
                    'RT_INITIALIZER_SEALED')
            image['origins']=remove_origins(image['origins'],offset*8,(offset+size)*8)
            for index,byte in enumerate(result.bytes):
                require(byte.width==8,'RT_INITIALIZER_RAW8')
                image['bytes'][offset+index]=byte.bits;image['poison'][offset+index]=byte.poison
                image['undef'][offset+index]=byte.undef
                for span in byte.origins:
                    pointer=span.pointer
                    image['origins'].append({'object':None if pointer.origin is None else {'some':pointer.origin},
                        'generation':pointer.generation,'domain':pointer.domain,'pointer_bits':pointer.address,
                        'offset':(offset+index)*8+span.offset,'length':span.length,'source_bit':span.source,
                        'range':interval(pointer.access_range)})
            image['origins'].sort(key=lambda origin:origin['offset'])
            exposed|={(identity,private.objects[identity]['generation']) for identity in result.data_exposed}
            exposed_code|=result.code_exposed
        for image in staged.values():image['sealed']=True
        with self._lock:
            require(self._facts()==facts and self._providers()==providers and self.revision==revision,'RT_INITIALIZER_STALE')
            require(self._next<2**64-1,'RT_INITIALIZER_RESOURCE')
            ticket=Ticket(self,self._next);self._next+=1
            self._prepared[id(ticket)]=(ticket,revision,facts,providers,staged,exposed,exposed_code,bindings)
            return ticket

    def commit(self,ticket):
        with self._lock:
            pending=self._prepared.get(id(ticket))
            require(isinstance(ticket,Ticket) and ticket.registry is self and pending is not None and
                    pending[0] is ticket,'RT_INITIALIZER_AUTHORITY')
            _,revision,facts,providers,images,exposed,code,bindings=pending
            require(self.revision==revision and self._facts()==facts and self._providers()==providers,'RT_INITIALIZER_STALE')
            require(self.revision<2**64-1,'RT_INITIALIZER_RESOURCE')
            self.images,self.exposed,self.exposed_code,self.bindings=images,exposed,code,bindings
            self.revision+=1;self.committed=True;del self._prepared[id(ticket)]
