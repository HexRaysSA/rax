"""Module-qualified typed values, recursive shape equivalence and literal checks."""
import hashlib
import json

from common import bit_pattern, require
from . import factory_meter as M

FLOATS = {'binary16': 16, 'bfloat16': 16, 'binary32': 32, 'binary64': 64, 'binary128': 128}
HANDLES = {'exception', 'stack_mark', 'va_list', 'journal'}
SCALARS = {'int', 'raw', 'float', 'data_ptr', 'code_ptr', 'code_address'}


def ref(identifier, module=None):
    return {'module': {'kind': 'self'} if module is None else {'kind': 'dependency', 'slot': module}, 'id': identifier}


def key(reference):
    module = reference['module']
    return (('self', reference['id']) if module['kind'] == 'self'
            else ('dependency', module['slot'], reference['id']))


def unique(items, field='id'):
    identifiers = [item[field] for item in items]
    require(identifiers == sorted(set(identifiers)), 'duplicate_order', field)
    return {item[field]: item for item in items}


class Types:
    def __init__(self, root, external=None, *, budget=None):
        self._factory_budget = M.check(budget)
        if budget is not None: M.json_bound(root, budget)
        if budget is not None: M.collection(budget, len(root['types']))
        require(root['payload_revision'] == 2, 'revision', 'types')
        local = unique(root['types'])
        self.items = {('self', identifier): item for identifier, item in local.items()}
        from candidate.wire import encode
        if budget is not None: M.collection(budget, len(external or {}))
        for identity, item in (external or {}).items():
            if budget is not None: M.json_bound(item, budget)
            require(type(identity) is tuple and len(identity) == 3 and identity[0] == 'dependency'
                    and all(type(number) is int and 0 <= number < 2**32 for number in identity[1:]), 'type_dependency_declaration')
            encode('type', item)
            self.items[identity] = item
        self.widths = {}
        self.value_costs = {}
        self.value_kinds = {}
        if budget is not None: M.collection(budget, len(self.items))
        for identity, item in self.items.items():
            if budget is not None: M.json_bound(item, budget)
            kind = item['kind']
            if kind in {'int', 'raw'}:
                require(1 <= item['bits'] <= 2**23, 'type_width')
            elif kind == 'float':
                require(item['format'] in FLOATS, 'type_float')
            elif kind == 'data_ptr':
                require(item['space'] == 'guest_data', 'type_space')
            elif kind == 'code_ptr':
                require(self.get(item['signature'])['kind'] == 'function', 'type_signature')
            elif kind in {'array', 'vector'}:
                child = self.get(item['element'])
                require(child['kind'] != 'function', 'type_value')
                if kind == 'vector':
                    require(1 <= item['count'] <= 65535 and child['kind'] in SCALARS, 'type_vector')
            elif kind == 'struct':
                require(all(self.get(child)['kind'] != 'function' for child in item['fields']), 'type_value')
            elif kind == 'function':
                require(item['cc'] == 'portable' and not item['variadic'], 'calling_convention',
                        'source ellipsis is ABI metadata; execution signatures are fixed')
                for group, attrs in [('params', 'param_noundef'), ('results', 'result_noundef')]:
                    require(len(item[group]) == len(item[attrs]), 'type_signature')
                    require(all(self.get(child)['kind'] != 'function' for child in item[group]), 'type_signature')
        # Bounded DFS over by-value edges; no recursion through signatures.
        active, depths = set(), {}
        for identity in self.items:
            pending = [(identity, False)]
            while pending:
                if budget is not None: M.lookup(budget, len(self.items))
                current, finish = pending.pop()
                if current in self.widths:
                    continue
                item = self.items[current]
                children = self.children(item, by_value=True)
                if budget is not None: M.collection(budget, len(children) + len(self.items))
                if not finish:
                    require(current not in active, 'type_cycle')
                    active.add(current)
                    pending.append((current, True))
                    pending.extend((key(child), False) for child in reversed(children))
                    continue
                active.remove(current)
                depths[current] = 1 + max((depths[key(child)] for child in children), default=0)
                require(depths[current] <= 64, 'reference_resource', 'by-value type depth')
                kind = item['kind']
                if kind in {'int', 'raw'}:
                    width = item['bits']
                elif kind == 'float':
                    width = FLOATS[item['format']]
                elif kind in {'data_ptr', 'code_ptr', 'code_address'}:
                    width = 64
                elif kind in {'array', 'vector'}:
                    width = item['count'] * self.widths[key(item['element'])]
                elif kind == 'struct':
                    width = sum(self.widths[key(child)] for child in item['fields'])
                else:
                    width = 0
                require(width <= 2**64 - 1, 'type_extent', 'logical bit extent exceeds record offset domain')
                self.widths[current] = width
                if kind in {'array', 'vector'}:
                    cost = 1 + item['count'] * self.value_costs[key(item['element'])]
                elif kind == 'struct':
                    cost = 1 + sum(self.value_costs[key(child)] for child in item['fields'])
                else:
                    cost = 1
                self.value_costs[current] = min(100001, cost)
                present = children if kind not in {'array', 'vector'} or item['count'] else []
                self.value_kinds[current] = (frozenset().union(*(self.value_kinds[key(child)] for child in present))
                                             if kind in {'array', 'vector', 'struct'} else frozenset({kind}))

    def __deepcopy__(self, memo):
        from copy import deepcopy
        for name, value in self.__dict__.items():
            if name != '_factory_budget': M.snapshot_bound(value, self._factory_budget)
        M.charge(self._factory_budget, work=4, copied_bytes=128)
        result = type(self).__new__(type(self))
        memo[id(self)] = result
        for name, value in self.__dict__.items():
            setattr(result, name, value if name == '_factory_budget' else deepcopy(value, memo))
        return result

    def get(self, reference):
        if self._factory_budget is not None: M.lookup(self._factory_budget, len(self.items))
        identity = key(reference)
        require(identity in self.items, 'type_reference', str(identity))
        return self.items[identity]

    def width(self, reference):
        M.lookup(self._factory_budget, len(self.widths))
        return self.widths[key(reference)]

    def contains_value_kind(self, reference, kinds):
        """Present by-value leaves; zero-length arrays contain no child values."""
        if self._factory_budget is not None:
            M.lookup(self._factory_budget, len(self.value_kinds))
            M.collection(self._factory_budget, len(self.value_kinds[key(reference)]) + len(kinds))
        return bool(self.value_kinds[key(reference)] & kinds)

    def resolve(self, reference):
        """Admission-recomputed execution identity API for ABI/link consumers."""
        from copy import deepcopy
        item = self.get(reference)
        if self._factory_budget is not None: M.json_bound(item, self._factory_budget)
        result = deepcopy(item)
        if self._factory_budget is not None: M.json_bound(item, self._factory_budget)
        result.update(identity=self.digest(reference), logical_bits=self.width(reference), record=deepcopy(item))
        return result

    def children(self, item, by_value=False):
        if self._factory_budget is not None: M.charge(self._factory_budget, work=8, copied_bytes=64)
        if item['kind'] in {'vector', 'array'}:
            return [item['element']]
        if item['kind'] == 'struct':
            return item['fields']
        if not by_value and item['kind'] == 'function':
            if self._factory_budget is not None: M.collection(self._factory_budget, len(item['params']) + len(item['results']))
            return item['params'] + item['results']
        if not by_value and item['kind'] == 'code_ptr':
            return [item['signature']]
        return []

    def equal(self, left, right):
        pending, seen = [(left, right)], set()
        excluded = {'id', 'fields', 'params', 'results', 'element', 'signature'}
        while pending:
            if self._factory_budget is not None: M.collection(self._factory_budget, len(seen) + len(pending))
            a_ref, b_ref = pending.pop()
            pair = key(a_ref), key(b_ref)
            if pair in seen:
                continue
            seen.add(pair)
            a, b = self.get(a_ref), self.get(b_ref)
            if self._factory_budget is not None: M.json_bound(a, self._factory_budget)
            if self._factory_budget is not None: M.json_bound(b, self._factory_budget)
            if ({name: value for name, value in a.items() if name not in excluded}
                    != {name: value for name, value in b.items() if name not in excluded}):
                return False
            ac, bc = self.children(a), self.children(b)
            if len(ac) != len(bc) or (a['kind'] == 'function' and len(a['params']) != len(b['params'])):
                return False
            if self._factory_budget is not None: M.collection(self._factory_budget, len(ac) + len(bc))
            pending.extend(zip(ac, bc))
        return True

    def scalar(self, reference):
        item = self.get(reference)
        return self.get(item['element']) if item['kind'] == 'vector' else item

    def components(self, reference):
        item = self.get(reference)
        if item['kind'] == 'struct':
            return item['fields']
        if item['kind'] in {'array', 'vector'}:
            require(item['count'] <= 100000, 'reference_resource', 'materialized components')
            if self._factory_budget is not None: M.collection(self._factory_budget, item['count'])
            return [item['element']] * item['count']
        return None

    def materializable(self, reference):
        require(self.width(reference) <= 64 * 1024 * 1024 and self.value_costs[key(reference)] <= 100000,
                'reference_resource', 'SSA value materialization quota')

    def child(self, reference, index):
        item = self.get(reference)
        if item['kind'] == 'struct':
            require(0 <= index < len(item['fields']), 'aggregate_index')
            return item['fields'][index]
        require(item['kind'] in {'array', 'vector'} and 0 <= index < item['count'], 'aggregate_index')
        return item['element']

    def literal(self, reference, literal):
        if self._factory_budget is not None: M.json_bound(literal, self._factory_budget)
        item = self.get(reference)
        kind = literal['kind']
        if kind in {'poison', 'undef', 'zero'}:
            require(item['kind'] != 'function' and (kind != 'zero' or
                    not self.contains_value_kind(reference, HANDLES | {'fenv'})), 'literal')
            return
        if item['kind'] in {'struct', 'array', 'vector'}:
            count = len(item['fields']) if item['kind'] == 'struct' else item['count']
            require(kind == 'aggregate' and len(literal['elements']) == count, 'literal')
            for index, value in enumerate(literal['elements']):
                self.literal(self.child(reference, index), value)
        else:
            require(kind == 'bits' and item['kind'] in SCALARS, 'literal')
            value = bit_pattern(literal['value'], self.width(reference))
            if item['kind'] in {'data_ptr', 'code_ptr'}:
                require(value == 0, 'literal_pointer', 'non-null pointer requires admitted symbol/relocation')

    def digest(self, reference):
        """ID-independent digest of the rooted bisimulation quotient graph.

        Equal duplicate subgraphs and differently alpha-renamed recursive code
        signatures receive the same identity. This is execution shape only,
        never nominal ABI or object-generation authority.
        """
        root = key(reference)
        pending, reachable = [root], []
        seen = set()
        while pending:
            if self._factory_budget is not None: M.collection(self._factory_budget, len(seen) + len(pending))
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            reachable.append(current)
            pending.extend(key(child) for child in self.children(self.items[current]))
        excluded = {'id', 'fields', 'params', 'results', 'element', 'signature'}
        labels = {}
        edges = {}
        if self._factory_budget is not None: M.collection(self._factory_budget, len(reachable))
        for current in reachable:
            item = self.items[current]
            if self._factory_budget is not None: M.json_bound(item, self._factory_budget)
            label = {name: value for name, value in item.items() if name not in excluded}
            if item['kind'] == 'function':
                label['parameter_count'] = len(item['params'])
                label['result_count'] = len(item['results'])
            if self._factory_budget is not None: M.json_bound(label, self._factory_budget)
            labels[current] = json.dumps(label, sort_keys=True, separators=(',', ':'))
            edges[current] = [key(child) for child in self.children(item)]
        edge_count = sum(map(len, edges.values()))
        label_size = sum(map(len, labels.values()))
        if self._factory_budget is not None: M.graph(self._factory_budget, len(reachable), edge_count, label_size)
        classes = {label: index for index, label in enumerate(sorted(set(labels.values())))}
        groups = {current: classes[labels[current]] for current in reachable}
        while True:
            signatures = {current: (groups[current], tuple(groups[child] for child in edges[current]))
                          for current in reachable}
            distinct = {signature: index for index, signature in enumerate(sorted(set(signatures.values())))}
            refined = {current: distinct[signature] for current, signature in signatures.items()}
            stable = len(set(refined.values())) == len(set(groups.values()))
            groups = refined
            if stable:
                break
        representatives = {}
        for current in reachable:
            representatives.setdefault(groups[current], current)
        order = [groups[root]]
        indices = {groups[root]: 0}
        output = []
        for group in order:
            current = representatives[group]
            children = []
            for child in edges[current]:
                child_group = groups[child]
                if child_group not in indices:
                    indices[child_group] = len(order)
                    order.append(child_group)
                children.append(indices[child_group])
            output.append({'label': json.loads(labels[current]), 'children': children})
        if self._factory_budget is not None: M.json_bound(output, self._factory_budget)
        encoded = json.dumps(output, sort_keys=True, separators=(',', ':')).encode('ascii')
        return hashlib.sha256(b'SMIR-TYPE-SHAPE-V1\0' + encoded).hexdigest()
