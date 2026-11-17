"""Actual source-view binding and original-permit entry; no Fn-only promotion."""
import sys
B=sys.modules['_rax_smir_code_addresses_v1']._base
A=lambda:sys.modules['_rax_smir_code_addresses_v1']


class ValueMethods:
    def bind(self,address,expected,plan,*,activation,budget):
        self._check(budget);lane=self._row(address,A().AddressLane)
        active=self._observe(activation,'bind',address,budget,plan)
        caller=self._source(active['owner'],budget)
        B.require(expected is caller['source'].call_context(budget=budget))
        # Even null/poison/undef must use a genuine admitted ordinary plan first.
        B.require(B.MODEL.ordinary_address_call_compatible(expected,plan,expected,plan,budget=budget),
                  'code_address_plan')
        signature=expected.record('signature',plan,budget=budget).record
        budget.charge(work=8,edges=8,copied_bytes=512)
        state=lane['state'];bits=lane['bits']
        if state=='undef':state='concrete';bits=0
        if state=='poison' or bits==0:
            with self._lock:
                B.require(self._row(address,A().AddressLane) is lane,'RT_CODE_REFERENCE')
                self._row(activation,A().ActivationRef)
                return self._issue(A().BoundLane,state=state,bits=bits,target=None,permit=None,
                    owned=True,activation=activation,execution=signature['execution'])
        if lane['target'] is None:B.fail('code_address_invalid')
        target=self._row(lane['target'],A().SelectedTarget)
        provider=self._source(target['owner'],budget);self._open(target['owner'])
        actual_plan=B.option(target['record']['abi_signature'])
        if actual_plan is None:B.unavailable('actual provider ordinary plan missing')
        if not B.MODEL.ordinary_address_call_compatible(provider['call'],actual_plan,expected,plan,budget=budget):
            B.fail('code_address_plan')
        self._source(active['owner'],budget);self._source(target['owner'],budget)
        self._observe(activation,'bind',address,budget,plan)
        budget.charge(work=8,edges=12,copied_bytes=768)
        with self._lock:
            B.require(self._row(address,A().AddressLane) is lane,'RT_CODE_REFERENCE')
            B.require(self._row(activation,A().ActivationRef) is active,'RT_CODE_REFERENCE')
            self._open(active['owner']);owner=self._open(target['owner'])
            if len(self._permits)>=self._policy.max_permits or len(self._permits)>=2**64-1:
                B.fail('RT_CODE_RESOURCE','permits','resource')
            if self._root_count>=self._policy.max_roots:
                B.fail('RT_CODE_RESOURCE','temporary callable root','resource')
            permit=self._issue(A().BindingPermit,id=len(self._permits)+1,target=lane['target'],
                owner=target['owner'],actual=provider['call'],actual_plan=actual_plan,
                expected=expected,plan=plan,execution=signature['execution'],pins=1)
            value=self._issue(A().BoundLane,state='concrete',bits=bits,target=lane['target'],
                permit=permit,owned=True,activation=activation,execution=signature['execution'])
            self._permits.append(permit);owner['pins']+=1;self._root_count+=1;return value

    def entry(self,code,call,*,activation,budget):
        self._check(budget);lane=self._row(code,A().BoundLane);active=self._activation(activation,budget)
        checked=B.hook('validate_source_ordinary_call')(call,activation=active['source'],budget=budget)
        B.hook('validate_source_call_operand')(call,code,activation=active['source'],budget=budget)
        caller=self._source(active['owner'],budget)
        B.require(checked.context is caller['source'].call_context(budget=budget))
        if lane['state']!='concrete' or lane['bits']==0 or lane['permit'] is None:
            B.fail('code_token_invalid')
        permit=self._row(lane['permit'],A().BindingPermit)
        owner=self._source(permit['owner'],budget);self._open(permit['owner'])
        if not B.MODEL.ordinary_address_call_compatible(permit['expected'],permit['plan'],
                checked.context,checked.plan,budget=budget):B.fail('code_token_signature')
        if not B.MODEL.ordinary_address_call_compatible(permit['actual'],permit['actual_plan'],
                checked.context,checked.plan,budget=budget):B.fail('code_token_signature')
        if not B.SHAPE.same_execution_shape(permit['expected'],permit['execution'],
                checked.context,checked.execution,budget=budget):B.fail('code_token_signature')
        self._source(active['owner'],budget);self._source(permit['owner'],budget)
        B.hook('validate_source_ordinary_call')(call,activation=active['source'],budget=budget)
        B.hook('validate_source_call_operand')(call,code,activation=active['source'],budget=budget)
        budget.charge(work=8,edges=8,copied_bytes=384)
        with self._lock:
            # Explicit root destruction can occur during the charged source
            # comparisons. Recheck the exact original private associations at
            # publication; saved row dictionaries cannot revive a borrowed lane.
            B.require(self._row(code,A().BoundLane) is lane,'RT_CODE_REFERENCE')
            B.require(self._row(lane['permit'],A().BindingPermit) is permit,'RT_CODE_REFERENCE')
            B.require(self._row(activation,A().ActivationRef) is active,'RT_CODE_REFERENCE')
            target=self._open(permit['owner'])
            entry=self._issue(A().EntryRef,target=permit['target'],owner=permit['owner'],
                activation=activation,call=call,permit=lane['permit'],state='active')
            self._entries.append(entry);target['active']+=1;return entry

    def erase(self,code,*,activation,budget):
        self._check(budget);row=self._row(code)
        B.require(type(code) in (A().BoundLane,A().LegacyCodeRef),'RT_CODE_REFERENCE')
        operand=row['source'] if type(code) is A().LegacyCodeRef else code
        if type(code) is A().LegacyCodeRef:
            B.require(row['activation'] is activation,'RT_CODE_CONTEXT')
        self._observe(activation,'erase',operand,budget)
        if row['state']=='poison':return self.poison(budget=budget)
        if row['state']=='undef':return self.originless(0,budget=budget)
        if type(code) is A().LegacyCodeRef and row['invalid'] is not None:
            B.fail('code_address_invalid')
        if row['bits']==0:return self.originless(0,budget=budget)
        if row['target'] is None:B.fail('code_address_invalid')
        target=self._row(row['target'],A().SelectedTarget);self._source(target['owner'],budget)
        self._open(target['owner']);budget.charge(work=2,edges=2,copied_bytes=128)
        with self._lock:
            B.require(self._row(code) is row,'RT_CODE_REFERENCE')
            self._row(activation,A().ActivationRef)
            self._open(target['owner'])
            return self._issue(A().AddressLane,state='concrete',bits=row['bits'],target=row['target'],
                permit=None,owned=True)

    def drop_lane(self,value,*,budget):
        self._check(budget);row=self._row(value)
        B.require(type(value) in (A().AddressLane,A().BoundLane),'RT_CODE_REFERENCE')
        B.require(row['owned'],'RT_CODE_OWNED_REFERENCE');budget.work(2)
        with self._lock:
            row=self._row(value);B.require(row['owned'],'RT_CODE_OWNED_REFERENCE')
            if row['permit'] is not None:
                permit=self._row(row['permit'],A().BindingPermit)
                owner=self._row(permit['owner'],A().OwnerRef)
                B.require(permit['pins']>0 and owner['pins']>0)
                permit['pins']-=1;owner['pins']-=1
                self._root_count-=1
            row['alive']=False
