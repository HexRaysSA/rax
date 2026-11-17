"""Independent S-028 rooted execution-shape normalization for ABI contexts.

The caller supplies an admitted section1 graph, not a file-provided shape digest.
This module intentionally has no dependency on the SEMANTICS implementation.
"""

import hashlib
import json
from copy import deepcopy
import factory_meter as M

from layout import require
from nominal import unique


class ExecutionShapes:
    def __init__(self, records, *, budget=None):
        M.check_budget(budget)
        self.budget=budget
        M.copy_cost(records,budget)
        M.collection(budget,len(records))
        self.items = unique(records, 'EXECUTION_TYPE')
        self.cache = {}
        for item in records:
            require('identity' not in item, 'ABI_CC_PRODUCER_SHAPE_DIGEST')
            for child in self._children(item):
                require(child['module']['kind'] == 'self' and child['id'] in self.items,
                        'ABI_CC_EXECUTION_REFERENCE')

    def __deepcopy__(self,memo):
        M.collection(self.budget,len(self.items))
        for item in self.items.values():M.copy_cost(item,self.budget)
        M.collection(self.budget,len(self.cache),64)
        result=type(self).__new__(type(self));memo[id(self)]=result
        result.budget=self.budget
        result.items=deepcopy(self.items,memo);result.cache=deepcopy(self.cache,memo)
        return result

    def _children(self,item):
        M.copy_cost(item,self.budget)
        return self.children(item)

    def _label(self,item):
        M.copy_cost(item,self.budget)
        return self.label(item)

    @staticmethod
    def children(item):
        if item['kind'] == 'function':
            return item['params'] + item['results']
        if item['kind'] in ('array', 'vector'):
            return [item['element']]
        if item['kind'] == 'struct':
            return item['fields']
        if item['kind'] == 'code_ptr':
            return [item['signature']]
        return []

    @staticmethod
    def label(item):
        result = {name: value for name, value in item.items() if name not in
                  {'id', 'params', 'results', 'element', 'fields', 'signature'}}
        if item['kind'] == 'function':
            result['parameter_count'] = len(item['params'])
            result['result_count'] = len(item['results'])
        return result

    def digest(self, reference):
        require(reference['module']['kind'] == 'self' and reference['id'] in self.items,
                'ABI_CC_EXECUTION_REFERENCE')
        M.charge(self.budget,work=len(self.items)+1)
        root = reference['id']
        if root in self.cache:
            return self.cache[root]
        M.charge(self.budget,work=1,copied_bytes=128)
        reachable, pending = set(), [root]
        while pending:
            M.collection(self.budget,len(reachable)+1)
            current = pending.pop()
            if current in reachable:
                continue
            reachable.add(current)
            pending += [child['id'] for child in self._children(self.items[current])]
        M.collection(self.budget,len(reachable))
        labels = {current: M.encoded_json(self._label(self.items[current]),self.budget)
                  for current in reachable}
        M.collection(self.budget,len(reachable))
        edges = {current: [child['id'] for child in self._children(self.items[current])] for current in reachable}
        longest=max((len(v)for v in labels.values()),default=0)
        n=len(reachable);edge_count=sum(len(v)for v in edges.values());maximum=max((len(v)for v in edges.values()),default=0)
        M.collection(self.budget,n,longest)
        colors = {label: index for index, label in enumerate(sorted(set(labels.values())))}
        M.collection(self.budget,n)
        partition = {current: colors[labels[current]] for current in reachable}
        rounds=0
        while True:
            rounds+=1
            if self.budget is not None and rounds>n:raise RuntimeError('ABI_FACTORY_REFINEMENT_ROUND_BOUND')
            M.collection(self.budget,n)
            M.charge(self.budget,work=edge_count,edges=edge_count,copied_bytes=64*edge_count)
            signatures = {current: (labels[current], tuple(partition[child] for child in edges[current]))
                          for current in reachable}
            M.collection(self.budget,n,longest+maximum)
            names = {signature: index for index, signature in enumerate(sorted(set(signatures.values())))}
            M.collection(self.budget,n,longest+maximum)
            refined = {current: names[signature] for current, signature in signatures.items()}
            # Refinement is monotone; same class count means stable equivalence.
            M.collection(self.budget,n);M.collection(self.budget,n)
            stable = len(set(refined.values())) == len(set(partition.values()))
            partition = refined
            if stable:
                break
        M.collection(self.budget,n);M.collection(self.budget,n)
        representative = {}
        for current in sorted(reachable):
            representative.setdefault(partition[current], current)
        M.charge(self.budget,work=1,copied_bytes=256)
        order = [partition[root]]
        indices = {partition[root]: 0}
        quotient = []
        for color in order:
            M.charge(self.budget,work=2*(n+1))
            current = representative[color]
            targets = []
            M.charge(self.budget,work=4*(n+1)*(len(edges[current])+1),edges=len(edges[current]),copied_bytes=128*(len(edges[current])+1))
            for child in edges[current]:
                child_color = partition[child]
                if child_color not in indices:
                    indices[child_color] = len(order)
                    order.append(child_color)
                targets.append(indices[child_color])
            M.charge(self.budget,work=len(labels[current]),copied_bytes=128*len(labels[current]))
            quotient.append({'label': json.loads(labels[current]), 'children': targets})
        encoded = M.encoded_bytes(quotient,self.budget)
        M.charge(self.budget,work=len(encoded)+64,copied_bytes=len(encoded)+128)
        result = hashlib.sha256(b'SMIR-TYPE-SHAPE-V1\0' + encoded).hexdigest()
        M.collection(self.budget,len(self.cache)+1,64)
        self.cache[root] = result
        return result

    def equal(self, left, right):
        pending, seen = [(left['id'], right['id'])], set()
        while pending:
            M.collection(self.budget,len(seen)+1)
            pair = pending.pop()
            if pair in seen:
                continue
            seen.add(pair)
            a, b = (self.items[identifier] for identifier in pair)
            if self._label(a) != self._label(b):
                return False
            ac, bc = self._children(a), self._children(b)
            if len(ac) != len(bc):
                return False
            M.charge(self.budget,work=4*len(ac),edges=len(ac),copied_bytes=128*len(ac))
            pending.extend((x['id'], y['id']) for x, y in zip(ac, bc))
        return True

    def describe(self, reference):
        M.charge(self.budget,work=len(self.items)+1)
        item = self.items[reference['id']]
        result = {**self._label(item), 'identity': self.digest(reference)}
        # ABI3 consumers need original child refs for actual structural checks;
        # the normalized identity remains a cache/index aid, never the predicate.
        M.copy_cost(item,self.budget)
        result['record'] = deepcopy(item)
        if item['kind'] == 'function':
            result['params'] = [self.digest(child) for child in item['params']]
            result['results'] = [self.digest(child) for child in item['results']]
        if item['kind'] in ('array', 'vector'):
            result['element_identity'] = self.digest(item['element'])
        if item['kind'] == 'struct':
            result['fields'] = [self.digest(child) for child in item['fields']]
        if item['kind'] == 'code_ptr':
            result['signature_identity'] = self.digest(item['signature'])
        return result
