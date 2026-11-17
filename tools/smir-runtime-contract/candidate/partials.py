"""R042 process-owned partial objects and activation-local journal factories.

Only actual source transitions populate this registry. Snapshots are evidence,
never authority to construct/adopt/resume an object or to extend its lifetime.
"""
from copy import deepcopy
from dataclasses import dataclass

from .errors import option, require, some
from .wire import validate_shape

MAX=2**64-1
OPAQUE={'exception','journal','stack_mark','va_list'}


def owner_of(document):
    state=document['state']
    return {key:state[key] for key in ('thread','activation','generation')}|{'instance':document['id']}


def owner_valid(owner):
    require(type(owner) is dict and set(owner)=={'thread','activation','generation','instance'} and
            all(type(v) is int and 0<v<=MAX for v in owner.values()),'RT_JOURNAL_OWNER')


@dataclass(frozen=True)
class Journal:
    registry: object
    identity: int


class Registry:
    def __init__(self,lifetimes,types,nominal,value_check,*,modules,exception_check=None,failure_check=None):
        self.lifetimes=lifetimes;self.lock=lifetimes.lock
        self.types=types;self.nominal=nominal;self.value_check=value_check
        self.exception_check=exception_check
        self.failure_check=failure_check
        self.modules=modules
        self.items={};self.active={};self.handles={};self.next_id=1;self.next_handle=1
        lifetimes.partials=self

    def _pointer(self,pointer):
        require(getattr(pointer,'domain',None)=='data','RT_PARTIAL_POINTER')
        identity=pointer.origin;obj=self.lifetimes.objects.get(identity)
        require(obj is not None and obj['live'] and obj['generation']==pointer.generation and
                obj['address']<=pointer.address<obj['address']+obj['size'],'RT_PARTIAL_POINTER')
        return identity,obj

    def _capture(self,module,definition,captures,owner):
        require(len(captures)==len(definition['params']) and [v['parameter'] for v in captures]==
                [p['id'] for p in definition['params']],'RT_PARTIAL_CAPTURES')
        graph=self.types(module)
        for captured,formal in zip(captures,definition['params']):
            value=captured['value'];nominal=self.nominal(module,formal['type'])
            expected=option(nominal['execution'])
            require(not graph.contains_value_kind(value['type'],OPAQUE) and expected is not None and
                    graph.equal(value['type'],expected),'RT_PARTIAL_CAPTURE_TYPE')
            self.value_check(module,value,owner['activation'])

    def _counts(self,definition,captures,counts):
        require([c['slot'] for c in counts]==[s['id'] for s in definition['slots']], 'RT_PARTIAL_COUNTS')
        actual={c['slot']:c['count'] for c in counts}
        values={c['parameter']:c['value'] for c in captures}
        for slot in definition['slots']:
            count=slot['count'];source=option(slot['count_source'])
            if source is not None:
                payload=values[source]['payload']
                require(payload['kind']=='scalar','RT_PARTIAL_COUNTS')
                count=int.from_bytes(bytes.fromhex(payload['bits']),'little')
            require(actual[slot['id']]==count and 0<=count<=100000 and count*slot['stride']<=slot['extent'] and
                    (slot['role']!='vla' or count>0),'RT_PARTIAL_COUNTS')

    def _issue(self,builder,owner,cleanup=False,exception=None):
        require(self.next_handle<MAX,'RT_PARTIAL_RESOURCE')
        handle=Journal(self,self.next_handle);self.next_handle+=1
        builder['phase']='cleanup' if cleanup else 'owned';builder['claim']=some(deepcopy(owner))
        self.handles[id(handle)]=handle
        self.active[id(handle)]={'builder':builder['id'],'owner':deepcopy(owner),'pending':set(),
                                 'exception':exception,'cleanup':cleanup}
        return handle

    def _active(self,handle,owner):
        owner_valid(owner)
        require(isinstance(handle,Journal) and handle.registry is self and
                self.handles.get(id(handle)) is handle and id(handle) in self.active,'RT_PARTIAL_JOURNAL')
        active=self.active[id(handle)];builder=self.items[active['builder']]
        require(active['owner']==owner==option(builder['claim']),'RT_PARTIAL_OWNER')
        self.lifetimes._storage(builder)
        require(builder['module'] in self.modules and self.modules[builder['module']]['generation']==
                builder['module_generation'] and self.modules[builder['module']]['pins']>0,'RT_PARTIAL_MODULE')
        return active,builder

    def _revision(self,builder):
        require(builder['revision']<MAX,'RT_PARTIAL_RESOURCE')
        builder['revision']+=1

    def begin(self,module,program,pointer,owner,captures,counts,leases):
        """Fresh owner, or fresh reclaim after BEFORE-await_suspend detach."""
        with self.lock:
            owner_valid(owner);identity,obj=self._pointer(pointer)
            require(module in self.modules and self.modules[module]['generation']>0 and
                    self.modules[module]['pins']>0,'RT_PARTIAL_MODULE')
            _,definition=self.lifetimes.program(module,program)
            self._capture(module,definition,captures,owner);self._counts(definition,captures,counts)
            matches=[b for b in self.items.values() if (b['module'],b['object'],b['object_generation'],b['address'],b['program'])==
                     (module,identity,obj['generation'],pointer.address,program) and b['phase']!='dead']
            require(len(matches)<=1,'RT_PARTIAL_DUPLICATE')
            if matches:
                builder=matches[0]
                require(builder['phase']=='partial' and builder['claim'] is None and
                        builder['captures']==captures and builder['counts']==counts,'RT_PARTIAL_BUSY')
                self._revision(builder)
            else:
                require(self.next_id<MAX,'RT_PARTIAL_RESOURCE')
                builder={'id':self.next_id,'revision':1,'module':module,
                    'module_generation':self.modules[module]['generation'],'object':identity,
                    'object_generation':obj['generation'],'address':pointer.address,'program':deepcopy(program),
                    'captures':deepcopy(captures),'counts':deepcopy(counts),'completed':[],'current':[],
                    'phase':'partial','claim':None,'leases':list(leases)}
                self.lifetimes._storage(builder)
                self.items[self.next_id]=builder;self.next_id+=1
            return self._issue(builder,owner)

    def begin_effect(self,handle,owner,ticket):
        with self.lock:
            active,_=self._active(handle,owner)
            require(type(ticket) is int and ticket>0 and ticket not in active['pending'],'RT_PARTIAL_EFFECT')
            active['pending'].add(ticket)

    def end_effect(self,handle,owner,ticket):
        with self.lock:
            active,_=self._active(handle,owner)
            require(ticket in active['pending'],'RT_PARTIAL_EFFECT')
            active['pending'].remove(ticket)

    def adopt_child(self,handle,owner,slot,element,child_id,lifetime):
        with self.lock:
            active,builder=self._active(handle,owner)
            require(not active['cleanup'] and not active['pending'],'RT_PARTIAL_EFFECT')
            _,definition=self.lifetimes.program(builder['module'],builder['program'])
            descriptor=next((s for s in definition['slots'] if s['id']==slot),None)
            counts={c['slot']:c['count'] for c in builder['counts']}
            require(descriptor is not None and 0<=element<counts[slot] and
                    not any((e['slot'],e['element'])==(slot,element) for e in builder['completed']),
                    'RT_PARTIAL_SLOT')
            require(element==0 or any((e['slot'],e['element'])==(slot,element-1) for e in builder['current']),
                    'RT_PARTIAL_ARRAY_PREFIX')
            require(all(all(any((e['slot'],e['element'])==(dependency,i) for e in builder['current'])
                        for i in range(counts[dependency])) for dependency in descriptor['dependencies']),
                    'RT_PARTIAL_DEPENDENCY')
            if descriptor['role']=='union_member':
                active_union={s['id'] for s in definition['slots'] if s['role']=='union_member' and
                              s['parent']==descriptor['parent'] and s['id']!=slot}
                require(not any(e['slot'] in active_union for e in builder['current']),'RT_PARTIAL_UNION')
            child=self.lifetimes.items.get(child_id);expected=option(descriptor['child_program'])
            require(expected is not None and child is not None and child['phase']=='alive' and child['claim'] is None
                    and child.get('owner') is None and child['object']==builder['object'] and
                    child['object_generation']==builder['object_generation'] and
                    child['address']==builder['address']+descriptor['offset']+element*descriptor['stride'] and
                    self.lifetimes.program(child['module'],child['program'])[0]==
                    self.lifetimes.program(builder['module'],expected)[0], 'RT_PARTIAL_CHILD')
            self.lifetimes._storage(child)
            _,child_definition=self.lifetimes.program(child['module'],child['program'])
            require(all(s['offset']+s['extent']<=descriptor['stride'] for s in child_definition['slots']),
                    'RT_PARTIAL_CHILD_EXTENT')
            require(child['revision']<MAX and type(lifetime) is int and lifetime>0,'RT_PARTIAL_RESOURCE')
            ordinal=max((e['ordinal'] for e in builder['completed']),default=0)
            require(ordinal<MAX,'RT_PARTIAL_RESOURCE')
            self._revision(builder)
            entry={'slot':slot,'element':element,'lifetime':lifetime,'ordinal':ordinal+1,'child':some(child_id)}
            builder['completed'].append(entry);builder['current'].append(deepcopy(entry))
            child['owner']=some({'kind':'partial','id':builder['id'],'slot':slot,'element':element})
            child['revision']+=1
            return deepcopy(entry)

    def detach(self,handle,owner):
        with self.lock:
            active,builder=self._active(handle,owner)
            require(not active['pending'] and not active['cleanup'],'RT_PARTIAL_EFFECT')
            self._revision(builder)
            builder.update(phase='partial',claim=None)
            del self.active[id(handle)]
            # Old handle cannot act even if await_suspend never returns.
            return deepcopy(builder)

    def commit_replayed_leaf(self,handle,owner,slot,element,lifetime,state):
        """Actual journal_advance commit after independent source-effect replay.

        `state` is trusted journals.validate output over this SAME issued J and
        seed, not deserialized cells. Scalar/trivial leaves need no child cert.
        """
        with self.lock:
            active,builder=self._active(handle,owner);document=state['document']
            seed=option(document['seed']);key=slot,element
            require(not active['cleanup'] and not active['pending'] and owner_of(document)==owner and
                    seed=={'kind':'partial','builder':builder['id'],'revision':builder['revision']} and
                    document['object']==builder['object'] and document['object_generation']==builder['object_generation'] and
                    document['object_address']==builder['address'] and document['program']==builder['program'] and
                    document['captures']==builder['captures'] and document['counts']==builder['counts'],
                    'RT_PARTIAL_REPLAY')
            require(key in state['cells'] and state['cells'][key]['phase']=='alive' and
                    state['slots'][slot]['child_program'] is None and
                    not any((e['slot'],e['element'])==key for e in builder['completed']), 'RT_PARTIAL_REPLAY')
            ordinal=max((e['ordinal'] for e in builder['completed']),default=0)
            require(type(lifetime) is int and lifetime>0 and ordinal<MAX and
                    state['cells'][key]['ordinal']==ordinal+1,'RT_PARTIAL_REPLAY')
            self._revision(builder)
            entry={'slot':slot,'element':element,'lifetime':lifetime,'ordinal':ordinal+1,'child':None}
            builder['completed'].append(entry);builder['current'].append(deepcopy(entry))
            return deepcopy(entry)

    def claim_partial(self,pointer,owner,exception=None,*,failed_journal=None,previous_owner=None,failed_ticket=None):
        with self.lock:
            owner_valid(owner);identity,obj=self._pointer(pointer)
            matches=[b for b in self.items.values() if b['object']==identity and b['object_generation']==obj['generation']
                     and b['address']==pointer.address and b['phase'] in {'partial','owned'}]
            require(len(matches)==1,'RT_PARTIAL_ABSENT')
            if exception is not None:
                require(self.exception_check is not None,'RT_PARTIAL_EXCEPTION')
                self.exception_check(exception,owner['thread'])
            builder=matches[0]
            if builder['phase']=='owned':
                require(exception is not None and self.failure_check is not None,'RT_PARTIAL_FAILED_FRONTIER')
                active,actual=self._active(failed_journal,previous_owner)
                require(actual is builder and not active['cleanup'] and active['pending']=={failed_ticket} and
                        all(owner[k]==previous_owner[k] for k in ('thread','activation','generation')) and
                        owner['instance']!=previous_owner['instance'],'RT_PARTIAL_FAILED_FRONTIER')
                self.failure_check(previous_owner,failed_ticket,exception)
                require(builder['revision']<MAX and self.next_handle<MAX,'RT_PARTIAL_RESOURCE')
                del self.active[id(failed_journal)]
            else:
                require(failed_journal is previous_owner is failed_ticket is None,'RT_PARTIAL_FAILED_FRONTIER')
            self._revision(builder)
            return self._issue(builder,owner,True,exception)

    def cleanup_order(self,handle,owner):
        with self.lock:
            active,builder=self._active(handle,owner)
            require(active['cleanup'],'RT_PARTIAL_CLEANUP')
            return deepcopy(sorted(builder['current'],key=lambda e:e['ordinal'],reverse=True))

    def end_child(self,handle,owner,slot,element,*,explicit=False):
        """Actual source lifetime-end/destructor completion, no fabricated effect."""
        with self.lock:
            active,builder=self._active(handle,owner)
            order=sorted(builder['current'],key=lambda e:e['ordinal'],reverse=True)
            require(order and (explicit or active['cleanup'] and (order[0]['slot'],order[0]['element'])==(slot,element)),
                    'RT_PARTIAL_CLEANUP_ORDER')
            entry=next((e for e in order if (e['slot'],e['element'])==(slot,element)),None)
            require(entry is not None,'RT_PARTIAL_DEAD_CHILD')
            child=None if entry['child'] is None else self.lifetimes.items[option(entry['child'])]
            if child is not None:
                require(all(option(e['child']) is None or self.lifetimes.items[option(e['child'])]['phase']=='dead'
                            for e in child['subobjects']),'RT_PARTIAL_CHILD_CLEANUP')
                require(child['revision']<MAX,'RT_PARTIAL_RESOURCE')
            self._revision(builder)
            if child is not None:child.update(phase='dead',claim=None,owner=None,revision=child['revision']+1)
            builder['current'].remove(entry)

    def finish_cleanup(self,handle,owner):
        with self.lock:
            active,builder=self._active(handle,owner)
            require(active['cleanup'] and not builder['current'] and not active['pending'],'RT_PARTIAL_CLEANUP')
            self._revision(builder);builder.update(phase='dead',claim=None)
            del self.active[id(handle)]
            return deepcopy(builder)

    def publish(self,handle,owner):
        """Aggregate completion consumes builder; never invokes complete-parent ctor."""
        with self.lock:
            active,builder=self._active(handle,owner)
            require(not active['cleanup'] and not active['pending'],'RT_PARTIAL_EFFECT')
            _,definition=self.lifetimes.program(builder['module'],builder['program'])
            counts={c['slot']:c['count'] for c in builder['counts']}
            completed={(e['slot'],e['element']) for e in builder['completed']}
            require(all((s['id'],i) in completed for s in definition['slots'] if s['role']!='union_member'
                        for i in range(counts[s['id']])),'RT_PARTIAL_INCOMPLETE')
            require(self.lifetimes.next_id<MAX and builder['revision']<MAX,'RT_PARTIAL_RESOURCE')
            certificate={key:deepcopy(builder[key]) for key in ('module','module_generation','object','object_generation',
                'address','program','captures','counts','leases')}
            certificate.update(id=self.lifetimes.next_id,revision=1,subobjects=deepcopy(builder['current']),
                               phase='alive',claim=None,owner=None)
            self.lifetimes._storage(certificate)
            validate_shape('runtime_object_lifetime',certificate)
            for entry in builder['current']:
                if entry['child'] is not None:
                    require(self.lifetimes.items[option(entry['child'])]['revision']<MAX,'RT_PARTIAL_RESOURCE')
            self.lifetimes.next_id+=1;self.lifetimes.items[certificate['id']]=certificate
            for entry in builder['current']:
                if entry['child'] is None:continue
                child=self.lifetimes.items[option(entry['child'])]
                child['owner']=some({'kind':'object','id':certificate['id'],'slot':entry['slot'],'element':entry['element']})
                child['revision']+=1
            self._revision(builder);builder.update(phase='dead',claim=None)
            del self.active[id(handle)]
            return deepcopy(certificate)

    def snapshots(self):
        with self.lock:return deepcopy(self.items)

    def snapshot(self,handle,owner,*,transition):
        """Fresh seeded checkpoint; no construction event from a former TID."""
        with self.lock:
            active,builder=self._active(handle,owner)
            require(type(transition) is int and transition>0,'RT_PARTIAL_TRANSITION')
            state={'revision':1,'instance':owner['instance'],'program':deepcopy(builder['program']),
                'parent_instance':None,'transition':transition,**{k:owner[k] for k in ('thread','activation','generation')},
                'stage':'cleanup' if active['cleanup'] else 'constructing',
                'next_ordinal':max((e['ordinal'] for e in builder['completed']),default=0),
                'exception_lease':None if active['exception'] is None else some(active['exception']), 'entries':[]}
            return {'id':owner['instance'],'module':builder['module'],'module_generation':builder['module_generation'],
                'object':builder['object'],'object_generation':builder['object_generation'],
                'object_address':builder['address'],'program':deepcopy(builder['program']),
                'seed':some({'kind':'partial','builder':builder['id'],'revision':builder['revision']}),'state':state,
                'event_sequences':[],'captures':deepcopy(builder['captures']),'counts':deepcopy(builder['counts']),
                'leases':list(builder['leases'])}
