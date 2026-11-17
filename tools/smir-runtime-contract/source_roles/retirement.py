"""Actual private registry retirement for the no-cleanup reference slice.

This consumes registry owners/roots/entries, never synthetic retirement_core
identities. Actual frame-lifetime drain without a committed producer stays busy.
"""
import sys
B=sys.modules['_rax_smir_code_addresses_v1']._base
A=lambda:sys.modules['_rax_smir_code_addresses_v1']


class RetirementMethods:
    def retire(self,owners,*,budget):
        self._check(budget);B.require(type(owners) is tuple and owners,'RT_CODE_REFERENCE')
        budget.charge(work=len(owners)+len(self._exposed_code)+len(self._exposed_address)+8,
            edges=len(owners),copied_bytes=256+32*(len(owners)+len(self._exposed_code)+len(self._exposed_address)))
        B.require(len({id(v) for v in owners})==len(owners),'RT_CODE_REFERENCE')
        for owner in owners:self._source(owner,budget);self._open(owner)
        with self._lock:
            for owner in owners:self._open(owner)
            remaining_code=[];remaining_address=[];removed=[]
            for exposure in self._exposed_code:
                if self._row(exposure[1])['owner'] in owners:removed.append(exposure[1])
                else:remaining_code.append(exposure)
            for exposure in self._exposed_address:
                if self._row(exposure[1])['owner'] not in owners:remaining_address.append(exposure)
            transaction=self._issue(A().RetirementRef,owners=owners,phase='busy_active',revision=self._revision)
            for owner in owners:self._row(owner)['phase']='closing'
            self._exposed_code=remaining_code;self._exposed_address=remaining_address
            for permit in removed:
                row=self._row(permit);row['pins']-=1;self._row(row['owner'])['pins']-=1
                self._root_count-=1
            self._revision+=1
            return transaction

    def retire_poll(self,transaction,*,budget):
        self._check(budget);row=self._row(transaction,A().RetirementRef)
        budget.charge(work=len(self._roots)+len(self._activations)+len(self._exposed_code)+8,
                      edges=len(self._roots),copied_bytes=128+16*len(self._roots))
        with self._lock:
            owners=row['owners']
            if row['phase']=='reclaimed':return self._issue(A().RetirementStatus,phase='reclaimed')
            if any(self._row(owner)['active'] for owner in owners):
                return self._issue(A().RetirementStatus,phase='busy_active')
            # Parked callers remain ACTIVE. We do not infer quiescence merely
            # from zero R entries, a completed callee or a public empty stack.
            if any(self._row(active)['owner'] in owners for active in self._activations):
                return self._issue(A().RetirementStatus,phase='busy_active')
            if any(self._row(attachment)['owner'] in owners for attachment in self._attachments):
                # An attached evaluator can already own an original frame before
                # its first observing instruction. No public stack inspection
                # substitutes for an actual lifetime-drain receipt.
                return self._issue(A().RetirementStatus,phase='busy_active')
            for root in self._roots:
                data=self._records[id(root)][1]
                if data['alive'] and data['owner'] in owners:
                    # No actual activation/storage holder can exist in this
                    # empty-lifetime slice; retain conservative busy otherwise.
                    return self._issue(A().RetirementStatus,phase='busy_cleanup')
            if any(self._row(owner)['pins'] for owner in owners):
                return self._issue(A().RetirementStatus,phase='busy_external')
            for owner in owners:self._row(owner)['phase']='reclaimed'
            row['phase']='reclaimed';self._revision+=1
            return self._issue(A().RetirementStatus,phase='reclaimed')

    def cleanup_entry(self,work,*,budget):
        self._check(budget);B.unavailable('actual retained cleanup work/dispatcher required')

    def cleanup_complete(self,entry,outcome,*,budget):
        self._check(budget);B.unavailable('actual cleanup outcome/child drain required')
