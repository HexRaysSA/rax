"""One private monotonic even-token pool per actual reference registry process."""
from threading import RLock


class _Pool:
    __slots__=('_budget','_capacity','_next','_keys','_lock')
    def __init__(self,budget,capacity):
        self._budget=budget;self._capacity=capacity;self._next=2
        self._keys={};self._lock=RLock()

    def reserve(self,key,*,budget):
        # All keys are created inside the actual owning registry after source
        # checks. This internal method is never an evaluator authority factory.
        from _rax_smir_code_addresses_v1 import CodeRegistryError
        if budget is not self._budget:raise CodeRegistryError('semantic','RT_CODE_CONTEXT')
        budget.charge(work=4,edges=1,copied_bytes=96)
        with self._lock:
            old=self._keys.get(key)
            if old is not None:return old
            if len(self._keys)>=self._capacity or self._next>2**64-2:
                raise CodeRegistryError('resource','RT_CODE_RESOURCE','token pool exhausted')
            bits=self._next;self._keys[key]=bits;self._next+=2
            return bits
