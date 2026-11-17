"""Preissued per-thread TLS slots and pure raw-address contract (R017).

This models reservation/address/once guards; it is not the production TLS loader.
"""
from dataclasses import dataclass
from threading import Condition

from .errors import option, require


@dataclass(frozen=True)
class Pointer:
    # lower/upper are OBJECT EXTENT facts, not LLVM inrange/access_range.
    object: int
    generation: int
    bits: int
    lower: int
    upper: int


@dataclass(frozen=True)
class External:
    consumer: str
    slot: int
    declaration: int
    provider: str
    generation: int
    symbol: int
    segment: int


@dataclass(frozen=True)
class Initialization:
    registry: object
    identity: int
    thread: int
    modules: frozenset
    generations: tuple


class Registry:
    def __init__(self,modules=None):
        self.condition=Condition()
        self.slots={}
        self.guards={}
        self.modules=modules or {}
        self.external={}
        self.consumers={}
        self.providers={}
        self.threads=set()
        self.initializations={}
        self.cohorts={}
        self.next_initialization=1

    def reserve(self,thread,module,segment,obj):
        with self.condition:
            key=thread,module,segment
            require(key not in self.slots and obj['live'] and obj['address']>0 and
                    obj['address']+obj['size']<=2**64-1,'RT_TLS_RESERVATION')
            self.slots[key]=dict(obj)
            self.threads.add(thread)
            self.guards[key]={'state':'uninitialized','owner':None}

    def address_raw(self,thread,module,segment,offset):
        require(type(offset) is int and 0<=offset<2**64,'RT_TLS_OFFSET')
        # Admitted thread/module entry guarantees this slot; no missing-slot
        # allocation/wait/initialization fallback is part of the pure operation.
        key=thread,module,segment
        require(key in self.slots,'RT_TLS_UNRESERVED')
        obj=self.slots[key]
        return Pointer(obj['id'],obj['generation'],(obj['address']+offset)%2**64,
                       obj['address'],obj['address']+obj['size'])

    def acquire(self,thread,module,segment,actor):
        with self.condition:
            guard=self.guards[thread,module,segment]
            # This guard belongs to ONE logical thread. A second activation
            # seeing initializing is recursive, even on a different host worker.
            require(guard['state']!='initializing','RT_TLS_RECURSIVE_INITIALIZATION')
            require(guard['state']!='terminated','RT_TLS_NAMESPACE_TERMINATE')
            if guard['state']=='initialized':return False
            guard.update(state='initializing',owner=actor)
            return True

    def release(self,thread,module,segment,actor,*,abort=False,namespace=False):
        with self.condition:
            guard=self.guards[thread,module,segment]
            require(guard['state']=='initializing' and guard['owner']==actor,'RT_TLS_GUARD_OWNER')
            if abort and namespace:
                guard.update(state='terminated',owner=None)
                self.condition.notify_all()
                require(False,'RT_TLS_NAMESPACE_TERMINATE')
            guard.update(state='uninitialized' if abort else 'initialized',owner=None)
            self.condition.notify_all()

    def bind_external(self,consumer,reference,*,deployment,selection,contexts):
        module=reference['module']
        require(module['kind']=='dependency','RT_TLS_EXTERNAL_REFERENCE')
        slot,identity=module['slot'],reference['id']
        context=contexts[consumer];context.assert_snapshot()
        dependency=next((d for d in context.sections[2]['manifest']['dependencies'] if d['slot']==slot),None)
        require(dependency is not None,'RT_TLS_EXTERNAL_DECLARATION')
        declaration=next((d for d in dependency['declarations'] if d['id']==identity),None)
        require(declaration is not None and declaration['kind']=='symbol' and declaration['symbol_kind']=='tls',
                'RT_TLS_EXTERNAL_STORAGE_KIND')
        target=deployment['bindings'].get((consumer,slot,identity))
        require(target is not None,'RT_TLS_EXTERNAL_UNRESOLVED')
        provider,symbol=selection.symbol(*target)
        require(provider in contexts and provider in self.modules,'RT_TLS_PROVIDER')
        provider_context=contexts[provider];provider_context.assert_snapshot()
        fact=self.modules[provider]
        require(fact['context'] is provider_context and fact['phase'] in {'prepared','admitted','initializing','published'}
                and fact['generation']>0 and fact['pins']>0,
                'RT_TLS_PROVIDER_STALE')
        actual=provider_context.runtime_symbol({'module':{'kind':'self'},'id':symbol})
        definition=option(actual['definition'])
        require(actual['kind']=='tls' and definition is not None and definition['kind']=='tls','RT_TLS_PROVIDER_KIND')
        segment=definition['segment']
        require(any(s['storage']['id']==segment for s in provider_context.sections[7]['segments']),
                'RT_TLS_PROVIDER_SEGMENT')
        # Full cross-root type/source equality was checked by the accepted
        # deployment+selection transaction; this API consumes that trusted plan.
        binding=External(consumer,slot,identity,provider,fact['generation'],symbol,segment)
        self.external[id(binding)]=binding
        self.consumers[id(binding)]=context
        self.providers[id(binding)]=provider_context
        return binding

    def metadata_external(self,binding,consumer_context=None,reference=None):
        """Actual provider-owned metadata, available before thread reservation.

        RootContext external_tls[(slot,decl)] consumes (this Registry,binding).
        Metadata validation never claims a runnable process or issues a pointer.
        """
        require(isinstance(binding,External) and self.external.get(id(binding)) is binding,
                'RT_TLS_BINDING_AUTHORITY')
        if consumer_context is not None or reference is not None:
            require(consumer_context is self.consumers[id(binding)] and reference=={
                'module':{'kind':'dependency','slot':binding.slot},'id':binding.declaration},
                'RT_TLS_BINDING_CONSUMER')
        fact=self.modules.get(binding.provider)
        require(fact is not None and fact['context'] is self.providers[id(binding)] and
                fact['phase'] in {'prepared','admitted','initializing','published','closing'}
                and fact['pins']>0 and fact['generation']==binding.generation,
                'RT_TLS_PROVIDER_STALE')
        provider=fact['context'];consumer=self.consumers[id(binding)]
        provider.assert_snapshot();consumer.assert_snapshot()
        segment=next(s for s in provider.sections[7]['segments'] if s['storage']['id']==binding.segment)
        return {'binding':binding,'consumer_context':consumer,'provider_context':provider,
                'provider_symbol':{'module':{'kind':'self'},'id':binding.symbol},
                'module_generation':binding.generation,'segment':segment}

    def _external(self,binding,thread,initialization=None):
        require(isinstance(binding,External) and self.external.get(id(binding)) is binding,
                'RT_TLS_BINDING_AUTHORITY')
        fact=self.modules.get(binding.provider)
        require(fact is not None and fact['context'] is self.providers[id(binding)] and
                fact['pins']>0 and fact['generation']==binding.generation,
                'RT_TLS_PROVIDER_STALE')
        if fact['phase']!='published':
            require(fact['phase'] in {'initializing','closing'} and isinstance(initialization,Initialization) and
                    self.initializations.get(id(initialization)) is initialization and
                    thread in self.cohorts[id(initialization)]['authorized'] and
                    binding.provider in initialization.modules,
                    'RT_TLS_NOT_PUBLISHED')
        fact['context'].assert_snapshot()
        key=thread,binding.provider,binding.segment
        require(key in self.slots and self.slots[key]['live'],'RT_TLS_UNRESERVED')
        return fact['context']

    def address_external(self,thread,binding,offset,*,initialization=None):
        self._external(binding,thread,initialization)
        return self.address_raw(thread,binding.provider,binding.segment,offset)

    def initialize_external(self,thread,binding,actor,invoke,*,initialization=None):
        context=self._external(binding,thread,initialization)
        segment=next(s for s in context.sections[7]['segments'] if s['storage']['id']==binding.segment)
        if segment['initialization']=='static':return False
        if not self.acquire(thread,binding.provider,binding.segment,actor):return False
        try:
            for hook in segment['initializers']:invoke(binding.provider,hook,thread)
        except BaseException:
            self.release(thread,binding.provider,binding.segment,actor,abort=True,
                         namespace=segment['initialization']=='namespace_dynamic')
            raise
        self.release(thread,binding.provider,binding.segment,actor)
        return True

    def register_thread(self,thread):
        with self.condition:
            require(type(thread) is int and thread>0,'RT_TLS_THREAD')
            self.threads.add(thread)

    def _reserved(self,artifacts):
        for artifact in artifacts:
            context=self.modules[artifact]['context'];context.assert_snapshot()
            for thread in self.threads:
                for record in context.sections[7]['segments']:
                    key=thread,artifact,record['storage']['id']
                    require(key in self.slots and self.slots[key]['live'],'RT_TLS_UNRESERVED')

    def begin_initialization(self,artifacts,thread):
        """Trusted loader already discharged ALL local/cross-root admission gates."""
        with self.condition:
            artifacts=frozenset(artifacts)
            require(artifacts and thread in self.threads and all(self.modules[a]['phase']=='admitted'
                and self.modules[a]['pins']>0 for a in artifacts),'RT_TLS_SCC_ADMISSION')
            self._reserved(artifacts)
            require(self.next_initialization<2**64-1,'RT_TLS_RESOURCE')
            lease=Initialization(self,self.next_initialization,thread,artifacts,
                                 tuple(sorted((a,self.modules[a]['generation']) for a in artifacts)))
            self.next_initialization+=1
            self.initializations[id(lease)]=lease
            self.cohorts[id(lease)]={'authorized':{thread},'children':set(),'escapes':set()}
            for artifact in artifacts:self.modules[artifact]['phase']='initializing'
            return lease

    def delegate_initialization(self,lease,parent,child):
        """Trusted source thread creation/captured-entry dispatch, never public entry.

        The caller already verified the actual source thread or captured code
        capability. An integer TID supplied by module metadata is not authority.
        """
        with self.condition:
            require(self.initializations.get(id(lease)) is lease and
                    parent in self.cohorts[id(lease)]['authorized'] and child in self.threads and
                    child not in self.cohorts[id(lease)]['authorized'] and
                    all(self.modules[a]['phase']=='initializing' for a in lease.modules),
                    'RT_TLS_INIT_DELEGATION')
            self._reserved(lease.modules)
            self.cohorts[id(lease)]['authorized'].add(child)
            self.cohorts[id(lease)]['children'].add(child)

    def complete_child(self,lease,thread):
        with self.condition:
            require(self.initializations.get(id(lease)) is lease and
                    thread in self.cohorts[id(lease)]['children'],'RT_TLS_INIT_CHILD')
            self.cohorts[id(lease)]['children'].remove(thread)
            self.cohorts[id(lease)]['authorized'].remove(thread)

    def retain_escape(self,lease,capability):
        """Trusted code/object/EH/TLS owner lease, not a serialized capability."""
        with self.condition:
            require(self.initializations.get(id(lease)) is lease and
                    all(self.modules[a]['phase']=='initializing' for a in lease.modules),
                    'RT_TLS_INIT_LEASE')
            require(capability not in self.cohorts[id(lease)]['escapes'],'RT_TLS_INIT_ESCAPE')
            self.cohorts[id(lease)]['escapes'].add(capability)

    def release_escape(self,lease,capability):
        with self.condition:
            require(self.initializations.get(id(lease)) is lease and
                    capability in self.cohorts[id(lease)]['escapes'],'RT_TLS_INIT_ESCAPE')
            self.cohorts[id(lease)]['escapes'].remove(capability)

    def publish_initialization(self,lease):
        with self.condition:
            require(isinstance(lease,Initialization) and self.initializations.get(id(lease)) is lease and
                    all(self.modules[a]['phase']=='initializing' for a in lease.modules) and
                    all(self.modules[a]['generation']==generation for a,generation in lease.generations),
                    'RT_TLS_INIT_LEASE')
            self._reserved(lease.modules)
            for artifact in lease.modules:self.modules[artifact]['phase']='published'
            # Surviving children/escaped owners now use normal published-module
            # leases. Publication transfers them; it does not terminate them.
            del self.initializations[id(lease)]
            del self.cohorts[id(lease)]

    def admit_metadata(self,artifacts,validate):
        """Reference outer gate: actual ABI+SEM plus caller's all-root validators.

        validate(contexts) is a trusted integrator function over these SAME roots;
        not file data. This protocol oracle creates no production admission token.
        """
        with self.condition:
            facts={a:(self.modules[a]['context'],self.modules[a]['generation']) for a in artifacts}
            require(facts and all(self.modules[a]['phase']=='prepared' and self.modules[a]['pins']>0 for a in facts),
                    'RT_TLS_SCC_ADMISSION')
        for context,_ in facts.values():
            context.assert_snapshot()
            require(context.abi_checked and context.execution_checked is not None,'RT_TLS_SCC_SEMANTICS')
        validate({a:context for a,(context,_) in facts.items()})
        with self.condition:
            require(all(self.modules[a]['phase']=='prepared' and self.modules[a]['context'] is context and
                        self.modules[a]['generation']==generation for a,(context,generation) in facts.items()),
                    'RT_TLS_SCC_ADMISSION')
            for artifact in facts:self.modules[artifact]['phase']='admitted'

    def fail_initialization(self,lease):
        with self.condition:
            require(self.initializations.get(id(lease)) is lease and
                    all(self.modules[a]['phase']=='initializing' for a in lease.modules),'RT_TLS_INIT_LEASE')
            for artifact in lease.modules:self.modules[artifact]['phase']='closing'

    def finish_failed_cleanup(self,lease):
        with self.condition:
            require(self.initializations.get(id(lease)) is lease and
                    all(self.modules[a]['phase']=='closing' for a in lease.modules),'RT_TLS_INIT_LEASE')
            require(not self.cohorts[id(lease)]['children'] and not self.cohorts[id(lease)]['escapes'],
                    'RT_TLS_INIT_NOT_QUIESCENT')
            for artifact in lease.modules:self.modules[artifact]['phase']='dead'
            for (thread,artifact,segment),obj in self.slots.items():
                if artifact in lease.modules:obj['live']=False
            del self.initializations[id(lease)]
            del self.cohorts[id(lease)]
