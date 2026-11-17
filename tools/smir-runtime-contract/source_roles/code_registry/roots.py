"""Private actual holder/root retention; raw copies keep original permits."""
import sys
B=sys.modules['_rax_smir_code_addresses_v1']._base
A=lambda:sys.modules['_rax_smir_code_addresses_v1']


class RootMethods:
    def adopt_lane(self,value,*,holder,budget):
        """DRAFT result-transfer join; same owned reference, no duplicate pin.

        Consumers require the named SOURCE-RESULT-RESOURCE-01 decision. Logical
        preflight failures leave the owned lane and holder membership unchanged.
        """
        self._check(budget);row=self._row(value)
        B.require(type(value) in (A().AddressLane,A().BoundLane),'RT_CODE_REFERENCE')
        B.require(row['owned'],'RT_CODE_OWNED_REFERENCE')
        membership=self._holder(holder,budget)
        budget.charge(work=8,edges=8,copied_bytes=512)
        self._holder(holder,budget)
        with self._lock:
            B.require(self._row(value) is row and row['owned'],'RT_CODE_OWNED_REFERENCE')
            B.require(self._row(holder,A().HolderRef) is membership,'RT_CODE_REFERENCE')
            owner=self._open(membership['owner'])
            # A concrete bound temporary already owns its exact permit root.
            # Other lanes gain one metadata root, still under the same quota.
            extra=0 if row['permit'] is not None else 1
            if self._root_count+extra>self._policy.max_roots:
                B.fail('RT_CODE_RESOURCE','result root transfer','resource')
            root=self._issue(A().RootRef,holder=holder,owner=membership['owner'],
                lane_type=type(value),state=row['state'],bits=row['bits'],target=row['target'],
                permit=row['permit'],execution=row.get('execution'))
            borrowed=self._issue(type(value),root=root,state=row['state'],bits=row['bits'],
                target=row['target'],permit=row['permit'],execution=row.get('execution'),owned=False)
            row['alive']=False;owner['membership']+=1;self._root_count+=extra
            self._roots.append(root)
            return root,borrowed

    def activation_holder(self,activation,*,budget):
        self._check(budget);row=self._activation(activation,budget)
        budget.charge(work=2,edges=2,copied_bytes=128)
        with self._lock:
            existing=row.get('holder')
            if existing is not None:return existing
            holder=self._issue(A().HolderRef,kind='activation',activation=activation,owner=row['owner'])
            row['holder']=holder;return holder

    def _holder(self,holder,budget):
        row=self._row(holder,A().HolderRef)
        if row['kind']=='activation':self._activation(row['activation'],budget)
        elif row['kind']=='snapshot':self._row(row['capture'],A().CaptureRef)
        else:B.unavailable('actual storage holder required')
        self._open(row['owner']);return row

    def retain(self,value,*,holder,budget):
        self._check(budget);row=self._row(value)
        B.require(type(value) in (A().AddressLane,A().BoundLane),'RT_CODE_REFERENCE')
        membership=self._holder(holder,budget)
        budget.charge(work=4,edges=4,copied_bytes=192)
        with self._lock:
            row=self._row(value);owner=self._open(membership['owner'])
            if self._root_count>=self._policy.max_roots:B.fail('RT_CODE_RESOURCE','roots','resource')
            root=self._issue(A().RootRef,holder=holder,owner=membership['owner'],
                lane_type=type(value),state=row['state'],bits=row['bits'],target=row['target'],
                permit=row['permit'],execution=row.get('execution'))
            if row['permit'] is not None:
                permit=self._row(row['permit'],A().BindingPermit)
                permit['pins']+=1;self._row(permit['owner'])['pins']+=1
            owner['membership']+=1;self._root_count+=1;self._roots.append(root);return root

    def value(self,root,*,budget):
        self._check(budget);row=self._row(root,A().RootRef)
        budget.charge(work=2,edges=2,copied_bytes=128)
        with self._lock:
            self._row(root,A().RootRef)
            return self._issue(row['lane_type'],root=root,state=row['state'],bits=row['bits'],
                target=row['target'],permit=row['permit'],execution=row['execution'],owned=False)

    def release(self,root,*,budget):
        self._check(budget);row=self._row(root,A().RootRef);budget.work(4)
        with self._lock:
            row=self._row(root,A().RootRef)
            if row['permit'] is not None:
                permit=self._row(row['permit'],A().BindingPermit)
                target=self._row(permit['owner'],A().OwnerRef)
                B.require(permit['pins']>0 and target['pins']>0)
                permit['pins']-=1;target['pins']-=1
            self._row(row['owner'],A().OwnerRef)['membership']+=1
            self._root_count-=1
            row['alive']=False

    def storage_holder(self,source,*,budget):
        self._check(budget);B.unavailable('actual source-backed storage registration required')

    def capture(self,roots,*,activation,budget):
        self._check(budget);row=self._activation(activation,budget)
        B.require(type(roots) is tuple,'RT_CODE_REFERENCE')
        budget.charge(work=len(roots)+4,edges=len(roots),copied_bytes=128+192*len(roots))
        prepared=[]
        for root in roots:
            original=self._row(root,A().RootRef)
            B.require(original['owner'] is row['owner'],'RT_CODE_CONTEXT')
            prepared.append(original.copy())
        with self._lock:
            self._open(row['owner'])
            for root in roots:self._row(root,A().RootRef)
            if len(self._captures)>=self._policy.max_snapshots:
                B.fail('RT_CODE_RESOURCE','captures','resource')
            extra=sum(value['permit'] is not None for value in prepared)
            if self._root_count+extra>self._policy.max_roots:
                B.fail('RT_CODE_RESOURCE','capture roots','resource')
            capture=self._issue(A().CaptureRef,owner=row['owner'],activation=activation,values=tuple(prepared))
            for value in prepared:
                if value['permit'] is not None:
                    permit=self._row(value['permit'],A().BindingPermit)
                    permit['pins']+=1;self._row(permit['owner'])['pins']+=1
            self._root_count+=extra;self._captures.append(capture);return capture

    def restore(self,capture,*,activation,budget):
        self._check(budget);row=self._row(capture,A().CaptureRef);active=self._activation(activation,budget)
        B.require(row['activation'] is activation and row['owner'] is active['owner'])
        budget.charge(work=len(row['values'])+4,edges=2*len(row['values']),copied_bytes=128*len(row['values']))
        with self._lock:
            self._row(capture,A().CaptureRef)
            extra=sum(original['permit'] is not None for original in row['values'])
            if self._root_count+extra>self._policy.max_roots:
                B.fail('RT_CODE_RESOURCE','restore roots','resource')
            result=[]
            for original in row['values']:
                value=self._issue(original['lane_type'],state=original['state'],bits=original['bits'],
                    target=original['target'],permit=original['permit'],execution=original['execution'],
                    owned=True,activation=activation)
                if original['permit'] is not None:
                    permit=self._row(original['permit'],A().BindingPermit)
                    permit['pins']+=1;self._row(permit['owner'])['pins']+=1
                result.append(value)
            self._root_count+=extra;return tuple(result)

    def drop_capture(self,capture,*,budget):
        self._check(budget);row=self._row(capture,A().CaptureRef);budget.work(len(row['values'])+2)
        with self._lock:
            self._row(capture,A().CaptureRef)
            for value in row['values']:
                if value['permit'] is not None:
                    permit=self._row(value['permit'],A().BindingPermit)
                    permit['pins']-=1;self._row(permit['owner'])['pins']-=1
                    self._root_count-=1
            row['alive']=False

    def capture_holder(self,capture,*,budget):
        self._check(budget);row=self._row(capture,A().CaptureRef)
        budget.charge(work=2,edges=2,copied_bytes=128)
        return self._issue(A().HolderRef,kind='snapshot',capture=capture,owner=row['owner'])
