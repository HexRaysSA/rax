"""State-carrying integer conversions over private exposure ledgers."""
import sys
B=sys.modules['_rax_smir_code_addresses_v1']._base
A=lambda:sys.modules['_rax_smir_code_addresses_v1']
PURE=B.load('_rax_smir_code_values_v1','tools/smir-runtime-contract/source_roles/code_values.py')


class ConversionMethods:
    def integer(self,bits,context,integer,*,budget):
        self._check(budget);return PURE.integer(bits,context,integer,budget=budget)
    def integer_poison(self,context,integer,*,budget):
        self._check(budget);return PURE.integer_poison(context,integer,budget=budget)
    def integer_undef(self,context,integer,*,budget):
        self._check(budget);return PURE.integer_undef(context,integer,budget=budget)

    def expose(self,value,result_context,integer,*,activation,budget):
        self._check(budget);row=self._row(value)
        B.require(type(value) in (A().AddressLane,A().BoundLane),'RT_CODE_REFERENCE')
        active=self._observe(activation,'expose',value,budget)
        source=self._source(active['owner'],budget)
        B.require(result_context is source['source'].call_context(budget=budget))
        destination=result_context.record('execution',integer,budget=budget).record
        B.require(destination['kind']=='int','RT_CODE_REFERENCE')
        width=destination['bits'];budget.charge(work=4+(width+7)//8,edges=4,copied_bytes=128)
        if row['state']=='poison':return PURE.integer_poison(result_context,integer,budget=budget)
        bits=0 if row['state']=='undef' else row['bits']
        result=PURE.integer(bits if width>=64 else bits&((1<<width)-1),result_context,integer,budget=budget)
        eligible=False;target=None
        if row['target'] is not None:
            target=self._row(row['target'],A().SelectedTarget)
            self._source(target['owner'],budget)
            eligible=self._row(target['owner'])['phase']=='open'
        self._observe(activation,'expose',value,budget)
        budget.work(len(self._exposed_code)+len(self._exposed_address))
        with self._lock:
            B.require(self._row(value) is row,'RT_CODE_REFERENCE')
            self._row(activation,A().ActivationRef)
            if eligible and self._row(target['owner'])['phase']=='open':
                if type(value) is A().BoundLane and row['permit'] is not None:
                    permit=self._row(row['permit'],A().BindingPermit)
                    if not any(v[1] is row['permit'] for v in self._exposed_code):
                        if self._root_count>=self._policy.max_roots:
                            B.fail('RT_CODE_RESOURCE','CODE exposure root','resource')
                        self._exposed_code.append((bits,row['permit'],row['target']))
                        permit['pins']+=1;self._row(permit['owner'])['pins']+=1;self._root_count+=1
                elif type(value) is A().AddressLane:
                    if not any(v[0]==bits and v[1] is row['target'] for v in self._exposed_address):
                        self._exposed_address.append((bits,row['target']))
            return result

    def recover(self,integer,target_context,execution,*,activation,budget):
        self._check(budget);PURE.validate_integer(integer,budget=budget)
        active=self._observe(activation,'recover',integer,budget)
        source=self._source(active['owner'],budget)
        B.require(target_context is source['source'].call_context(budget=budget))
        destination=target_context.record('execution',execution,budget=budget).record
        B.require(destination['kind'] in ('code_address','code_ptr'),'RT_CODE_REFERENCE')
        state=integer.state;bits=None if state=='poison' else 0 if state=='undef' else integer.bits(budget=budget)&(2**64-1)
        kind=A().AddressLane if destination['kind']=='code_address' else A().BoundLane
        permit=None;target=None
        while True:
            with self._lock:
                ledger=self._exposed_address if kind is A().AddressLane else self._exposed_code
                count=len(ledger)
            budget.charge(work=count+4,edges=2*count,copied_bytes=128+32*count)
            with self._lock:
                if len(ledger)!=count:continue
                candidates=tuple(ledger);break
        if state=='concrete' and bits:
            for candidate in candidates:
                if candidate[0]!=bits:continue
                possible=candidate[1] if kind is A().AddressLane else candidate[2]
                target_row=self._row(possible,A().SelectedTarget)
                owner=self._source(target_row['owner'],budget)
                if owner['phase']!='open':continue
                if kind is A().BoundLane:
                    offered=self._row(candidate[1],A().BindingPermit)
                    if not B.SHAPE.same_execution_shape(offered['expected'],offered['execution'],
                            target_context,destination['signature'],budget=budget):continue
                    if permit is not None and self._row(permit)['id']<offered['id']:continue
                    permit=candidate[1]
                target=possible
        self._observe(activation,'recover',integer,budget)
        with self._lock:
            if target is not None and self._row(self._row(target)['owner'])['phase']!='open':
                target=None;permit=None
            if permit is not None:
                if self._root_count>=self._policy.max_roots:
                    B.fail('RT_CODE_RESOURCE','recovered callable root','resource')
                actual=self._row(permit);actual['pins']+=1;self._row(actual['owner'])['pins']+=1
                self._root_count+=1
            return self._issue(kind,state='poison' if state=='poison' else 'concrete',bits=bits,
                target=target,permit=permit,owned=True,activation=activation,
                execution=destination.get('signature'))

    def expose_group(self,*args,budget,**kwargs):
        self._check(budget);B.unavailable('vector/group exposure is not a scalar loop')
    def recover_group(self,*args,budget,**kwargs):
        self._check(budget);B.unavailable('vector/group recovery is not a scalar loop')
