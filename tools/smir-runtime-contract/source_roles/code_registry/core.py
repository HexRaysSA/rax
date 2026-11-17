"""Actual source registration and private selection; no executable entry bypass."""
import sys
from threading import RLock
import weakref

B=sys.modules['_rax_smir_code_addresses_v1']._base
A=lambda:sys.modules['_rax_smir_code_addresses_v1']


class Registry:
    def __init__(self,*,budget,policy):
        B.require(type(self) is A().CodeRegistry and not hasattr(self,'_budget'))
        B.ledger(budget);B.require(type(policy) is A().RegistryPolicy and
            A()._POLICIES.get(id(policy)) is policy,'RT_CODE_POLICY')
        budget.charge(work=8,edges=8,copied_bytes=1024)
        self._budget=budget;self._policy=policy;self._lock=RLock();self._records={}
        self._owners=[];self._targets={};self._permits=[];self._entries=[]
        self._roots=[];self._captures=[];self._activations=[];self._attachments=[]
        self._root_count=0
        self._revision=0;self._generation=0;self._exposed_address=[];self._exposed_code=[]
        pool=B.load('_rax_smir_code_token_pool_v1','tools/smir-runtime-contract/source_roles/code_token_pool.py')
        self._pool=pool._Pool(budget,policy.max_targets)

    def _check(self,budget):
        B.require(budget is self._budget);B.ledger(budget);budget.work(1)

    def _row(self,value,cls=None):
        B.require(type(value) in A()._HANDLE_TYPES,'RT_CODE_REFERENCE')
        entry=self._records.get(id(value))
        B.require(entry is not None and entry[0]() is value and value._registry is self,
                  'RT_CODE_REFERENCE')
        data=entry[1];B.require(data['alive'],'RT_CODE_REFERENCE')
        B.require(cls is None or type(value) is cls,'RT_CODE_REFERENCE')
        if data.get('root') is not None:self._row(data['root'],A().RootRef)
        return data

    def _issue(self,cls,**data):
        value=object.__new__(cls);object.__setattr__(value,'_registry',self)
        data['alive']=True
        # Explicit release governs physical roots. Metadata-only handles may GC.
        identity=id(value)
        def discard(reference):
            with self._lock:
                old=self._records.get(identity)
                if old is not None and old[0] is reference:self._records.pop(identity)
        self._records[identity]=(weakref.ref(value,discard),data)
        return value

    def _source(self,owner,budget):
        data=self._row(owner,A().OwnerRef)
        B.SEM.validate_source_registry_context(data['source'],budget=budget)
        return data

    def _open(self,owner):
        data=self._row(owner,A().OwnerRef)
        if data['phase']!='open':B.fail('code_address_stale')
        return data

    def _bits(self,value):
        row=self._row(value)
        B.require(row['state']=='concrete','RT_CODE_NONCONCRETE_BITS')
        return row['bits']

    def register_source(self,source,*,budget):
        self._check(budget);B.SEM.validate_source_registry_context(source,budget=budget)
        with self._lock:
            for owner in self._owners:
                old=self._row(owner)
                if old['source'] is source and old['phase']=='open':return owner
        roots={n:B.plain(source.root(n,budget=budget),budget) for n in B.LINK.ROOTS}
        call=source.call_context(budget=budget)
        budget.work(64)
        B.require(roots[2]['manifest']['site']==B.SITE_IDENTITY,'RT_SITE_IDENTITY')
        # The first actual slice validates local source fields directly. Runtime
        # imports, dependency providers and storage need their actual adapters.
        if roots[6]['imports'] or roots[2]['manifest']['dependencies']:
            B.unavailable('local no-import/no-dependency source slice')
        for n in (4,7):
            if roots[n]['segments']:B.unavailable('actual source storage admission required')
        if roots[2]['comdats']:B.unavailable('actual COMDAT comparison projection required')
        if roots[2]['manifest']['foreign_isa']!='none':B.unavailable('actual native issuer required')
        if roots[2]['manifest']['kind']!='object' or roots[2]['initializers'] or roots[2]['finalizers']:
            B.unavailable('actual image/cleanup admission required')
        if roots[9]['capabilities'] or roots[9]['requirements'] or roots[9]['limits']:
            B.unavailable('actual runtime grant/resource policy admission required')
        def actual(namespace,reference):
            return B.plain(call.record(namespace,reference,budget=budget).record,budget)
        def nominal_equal(left,right):
            # This finite local source slice requires the same original nominal.
            # Equivalent foreign/DEP graphs need the separate full comparator.
            budget.work(16)
            return left==right
        def abi_entity(namespace,reference):
            if namespace=='nominal_domain':
                return actual('domain',B.ref(actual('nominal',reference)['domain']))
            return actual(namespace,reference)
        def unavailable(*args):B.unavailable('actual storage/import projection required')
        adapter=B.LINK.Context(site=roots[2]['manifest']['site'],
            execution=lambda q:actual('execution',q),nominal=lambda q:actual('nominal',q),
            function=lambda q:B.plain(source.record('function',q,budget=budget).record,budget),
            symbol=lambda q:B.plain(source.record('symbol',q,budget=budget).record,budget),
            execution_equal=lambda x,y:B.SHAPE.same_execution_shape(call,x,call,y,budget=budget),
            nominal_compatible=nominal_equal,storage_layout=unavailable,symbol_body=unavailable,
            symbol_identity=unavailable,abi_entity=abi_entity,
            signature_compatible=lambda x,y:B.MODEL.ordinary_address_call_compatible(call,x,call,y,budget=budget))
        B.LINK.validate(roots,adapter)
        # Every source symbol is validated against its genuine actual records;
        # callers cannot substitute a Context/comparator/definition dictionary.
        for symbol in roots[2]['symbols']:
            budget.work(16)
            if symbol['kind']!='function':B.unavailable('actual nonfunction definition admission required')
            definition=B.option(symbol['definition'])
            if definition is None or definition['kind']!='function':
                B.unavailable('actual unresolved/alias selection admission required')
            function=source.record('function',definition['target'],budget=budget).record
            plan=B.option(symbol['abi_signature'])
            if plan is None:
                # Generic functions can provide address metadata, but a missing
                # ordinary source plan cannot subsequently pass code_bind.
                B.require(B.option(function['abi_signature']) is None and symbol['nominal'] is None,
                          'RT_CODE_SOURCE_PLAN')
                continue
            B.require(plan is not None and plan==B.option(function['abi_signature']),'RT_CODE_SOURCE_PLAN')
            actual=call.record('signature',plan,budget=budget).record
            B.require(B.SHAPE.same_execution_shape(call,actual['execution'],call,function['signature'],budget=budget),
                      'RT_CODE_SOURCE_PLAN')
            B.require(B.MODEL.ordinary_address_call_compatible(call,plan,call,plan,budget=budget),
                      'RT_CODE_SOURCE_PLAN')
            B.require(B.option(symbol['nominal'])==actual['function_type'],'RT_CODE_SOURCE_PLAN')
        B.SEM.validate_source_registry_context(source,budget=budget)
        budget.charge(work=8,edges=4,copied_bytes=512)
        with self._lock:
            # The source walk happened outside the state lock. Identity is
            # checked again before publication; concurrent registrations merge.
            for owner in self._owners:
                row=self._row(owner)
                if row['source'] is source and row['phase']=='open':return owner
            self._generation+=1
            owner=self._issue(A().OwnerRef,source=source,call=call,roots=roots,
                generation=self._generation,phase='open',active=0,pins=0,membership=0)
            self._owners.append(owner);self._revision+=1
            return owner

    def prepare_deployment(self,owners,*,budget):
        self._check(budget);B.require(type(owners) is tuple and owners,'RT_CODE_DEPLOYMENT')
        budget.charge(work=len(owners),edges=len(owners),copied_bytes=128*len(owners))
        B.require(len({id(v) for v in owners})==len(owners),'RT_CODE_DEPLOYMENT')
        rows=[self._source(o,budget) for o in owners]
        for owner in owners:self._open(owner)
        if len(owners)!=1:B.unavailable('cross-module actual deployment join not implemented')
        owner=owners[0];row=rows[0];artifact=row['roots'][2]['manifest']['identity'];call=row['call']
        def shape(a,x,b,y):
            B.require(a==b==artifact);return B.SHAPE.same_execution_shape(call,x,call,y,budget=budget)
        def ordinary(a,x,b,y):
            B.require(a==b==artifact)
            return B.MODEL.ordinary_address_call_compatible(call,x,call,y,budget=budget)
        def missing(*args):B.unavailable('actual source body/data comparison required')
        context=B.LINK.Context(site=row['roots'][2]['manifest']['site'],execution=None,
            nominal=None,function=None,symbol=None,execution_equal=None,nominal_compatible=None,
            storage_layout=None,symbol_body=missing,symbol_identity=missing)
        selection=B.SELECT.select_definitions({artifact:row['roots']},{artifact:context},[artifact],
            shape,missing,signature_compatible=ordinary)
        deployment={'payload_revision':1,'modules':[{'key':row['roots'][2]['manifest']['key'],
            'artifact':artifact}],'edges':[]}
        bindings=B.LINK.bind_deployment({artifact:row['roots'][2]},deployment,shape,missing,
            signature_compatible=ordinary)
        self._source(owner,budget);budget.charge(work=4,edges=4,copied_bytes=256)
        with self._lock:
            self._open(owner)
            return self._issue(A().DeploymentRef,owners=owners,artifact=artifact,
                selection=selection,bindings=bindings,revision=self._revision)

    def resolve(self,deployment,consumer,namespace,reference,*,budget):
        self._check(budget);deploy=self._row(deployment,A().DeploymentRef)
        B.require(consumer in deploy['owners']);row=self._source(consumer,budget)
        B.require(namespace in ('function','symbol','import'),'RT_CODE_REFERENCE')
        record=row['source'].record(namespace,reference,budget=budget)
        original=B.plain(record.original_reference,budget);selected=B.plain(record.record,budget)
        self._open(consumer)
        if namespace=='symbol':
            target=deploy['selection'].symbol(deploy['artifact'],selected['id'])
            B.require(target[0]==deploy['artifact'],'RT_CODE_DEPLOYMENT')
            selected=B.plain(row['source'].record('symbol',B.ref(target[1]),budget=budget).record,budget)
            definition=B.option(selected['definition'])
            if definition is None:return self._issue(A().ProviderMissing,owner=consumer)
            if definition['kind']=='native':return self._issue(A().NativeBridgeMissing,owner=consumer)
            B.require(definition['kind']=='function','RT_CODE_REFERENCE')
            reference=definition['target'];namespace='function'
            record=row['source'].record(namespace,reference,budget=budget)
            selected=B.plain(record.record,budget)
        if namespace=='import':B.unavailable('actual import entry issuer required')
        function=selected['id'];target=deploy['selection'].functions.get((deploy['artifact'],function),
            (deploy['artifact'],function));B.require(target is not None,'RT_CODE_SELECTION')
        B.require(target==(deploy['artifact'],function),'RT_CODE_SELECTION')
        key=(consumer,row['generation'],'function',function)
        budget.charge(work=4,edges=4,copied_bytes=256)
        with self._lock:
            self._open(consumer)
            if key not in self._targets:
                if len(self._targets)>=self._policy.max_targets:B.fail('RT_CODE_RESOURCE','targets','resource')
                self._targets[key]=self._issue(A().SelectedTarget,owner=consumer,key=key,
                    namespace='function',reference=B.ref(function),record=selected,
                    original_reference=original,deployment=deployment,source_record=record)
            return self._targets[key]

    def address(self,target,*,budget):
        self._check(budget);row=self._row(target)
        if type(target) is A().WeakAbsent:return self.originless(0,budget=budget)
        if type(target) in (A().ProviderMissing,A().NativeBridgeMissing):B.unavailable('selected target unavailable')
        B.require(type(target) is A().SelectedTarget,'RT_CODE_REFERENCE')
        self._source(row['owner'],budget);self._open(row['owner'])
        bits=self._pool.reserve(row['key'],budget=budget)
        budget.charge(work=2,edges=2,copied_bytes=128)
        with self._lock:
            self._open(row['owner'])
            return self._issue(A().AddressLane,state='concrete',bits=bits,target=target,permit=None,owned=True)

    def originless(self,bits,*,budget):
        self._check(budget);B.require(type(bits) is int and 0<=bits<2**64,'RT_CODE_REFERENCE')
        budget.charge(work=1,copied_bytes=96)
        return self._issue(A().AddressLane,state='concrete',bits=bits,target=None,permit=None,owned=True)

    def poison(self,*,budget):return self._negative('poison',budget)
    def undef(self,*,budget):return self._negative('undef',budget)
    def _negative(self,state,budget):
        self._check(budget);budget.charge(work=1,copied_bytes=96)
        return self._issue(A().AddressLane,state=state,bits=None,target=None,permit=None,owned=True)

    def __getattr__(self,name):
        if name.startswith('_'):raise AttributeError(name)
        raise AttributeError(name)


for _component,_class in (('machine','MachineMethods'),('values','ValueMethods'),('roots','RootMethods'),
                         ('retirement','RetirementMethods'),('conversions','ConversionMethods')):
    _module=B.load('_rax_smir_code_addresses_v1._'+_component,
        'tools/smir-runtime-contract/source_roles/'+
        ('' if _component=='retirement' else 'code_registry/')+_component+'.py')
    for _name,_method in vars(getattr(_module,_class)).items():
        if callable(_method) and not _name.startswith('__'):setattr(Registry,_name,_method)
