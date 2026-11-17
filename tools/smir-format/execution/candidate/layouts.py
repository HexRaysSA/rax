"""Explicit physical execution layouts; no implicit nominal/source field layout."""
import hashlib
import json

from common import require
from . import factory_meter as M
from candidate.operations import optional, power2
from candidate.type_system import key, unique


class Layouts:
    def __init__(self, root, types, external=None, *, budget=None):
        self._factory_budget = M.check(budget)
        if budget is not None: M.json_bound(root, budget)
        if budget is not None: M.collection(budget, len(root['memory_layouts']))
        self.types = types
        self.items = {('self', identifier): layout for identifier, layout in unique(root['memory_layouts']).items()}
        if budget is not None: M.collection(budget, len(external or {}))
        for identity, layout in (external or {}).items():
            if budget is not None: M.json_bound(layout, budget)
            require(identity[0] == 'dependency', 'layout_dependency')
            self.items[identity] = layout
        for identity, layout in self.items.items():
            if budget is not None: M.json_bound(layout, budget)
            if budget is not None: M.collection(budget, len(layout['fields']))
            require(power2(layout['alignment']) and layout['alignment'] <= 2**31
                    and layout['size'] % layout['alignment'] == 0
                    and layout['access_bytes'] <= layout['size'], 'layout_extent')
            typ = types.get(layout['type'])
            kind = typ['kind']
            if kind in {'int', 'raw', 'float', 'data_ptr', 'code_ptr', 'code_address'}:
                if kind == 'code_address':
                    require(layout['size'] == layout['alignment'] == layout['access_bytes'] == 8,
                            'code_address_layout')
                require(layout['access_bytes'] == (types.width(layout['type']) + 7) // 8
                        and not layout['fields'] and layout['element'] is None and layout['stride'] == 0, 'layout_scalar')
            elif kind == 'struct':
                indices = [field['value_index'] for field in layout['fields']]
                require(indices == list(range(len(typ['fields']))) and layout['element'] is None
                        and layout['stride'] == 0 and layout['access_bytes'] == layout['size'], 'layout_struct')
                spans = []
                for field in layout['fields']:
                    child = self.get(field['layout'])
                    expected = typ['fields'][field['value_index']]
                    require(types.equal(child['type'], expected), 'layout_child_type')
                    require(types.width(expected) <= field['bit_width'] <= 8 * child['access_bytes']
                            and field['bit_offset'] + field['bit_width'] <= 8 * layout['access_bytes'], 'layout_field_extent')
                    spans.append((field['bit_offset'], field['bit_offset'] + field['bit_width']))
                ordered = sorted(spans)
                require(all(left[1] <= right[0] for left, right in zip(ordered, ordered[1:])), 'layout_overlap')
            elif kind in {'array', 'vector'}:
                element = optional(layout['element'])
                require(not layout['fields'] and element is not None, 'layout_sequence')
                child = self.get(element)
                require(types.equal(child['type'], typ['element']), 'layout_child_type')
                if kind == 'array':
                    require(layout['stride'] == 8 * child['size'] and layout['access_bytes'] == layout['size'], 'layout_array_stride')
                    occupied = typ['count'] * layout['stride']
                else:
                    require(layout['stride'] == types.width(typ['element']), 'layout_vector_stride')
                    occupied = typ['count'] * layout['stride']
                    require(layout['access_bytes'] == (occupied + 7) // 8, 'layout_vector_access')
                require(occupied <= 8 * layout['size'], 'layout_sequence_extent')
            else:
                require(False, 'layout_opaque', 'opaque value requires explicit branded helper, not raw memory')
        # Physical child layouts must be finite even for zero-size cyclic graphs.
        complete, active = set(), set()
        for root_key in self.items:
            pending = [(root_key, False)]
            while pending:
                if budget is not None: M.collection(budget, len(complete) + len(pending))
                current, finish = pending.pop()
                if current in complete:
                    continue
                if finish:
                    active.remove(current); complete.add(current)
                    continue
                require(current not in active, 'layout_cycle')
                active.add(current)
                pending.append((current, True))
                item = self.items[current]
                refs = [field['layout'] for field in item['fields']]
                if item['element'] is not None:
                    refs.append(optional(item['element']))
                pending.extend((key(reference), False) for reference in refs)

    def __deepcopy__(self, memo):
        from copy import deepcopy
        for name, value in self.__dict__.items():
            if name not in ('_factory_budget', 'types'):
                M.snapshot_bound(value, self._factory_budget)
        M.charge(self._factory_budget, work=4, copied_bytes=128)
        result = type(self).__new__(type(self))
        memo[id(self)] = result
        for name, value in self.__dict__.items():
            setattr(result, name, value if name == '_factory_budget' else deepcopy(value, memo))
        return result

    def get(self, reference):
        if self._factory_budget is not None: M.lookup(self._factory_budget, len(self.items))
        require(key(reference) in self.items, 'layout_reference')
        return self.items[key(reference)]

    def digest(self, reference):
        # Internal resolver identity, not a serialized authority field. Hash
        # child digests, avoiding exponential expansion of shared zero-size DAGs.
        memo, pending = {}, [(key(reference), False)]
        while pending:
            if self._factory_budget is not None: M.collection(self._factory_budget, len(memo) + len(pending))
            current, finish = pending.pop()
            if current in memo:
                continue
            layout = self.items[current]
            if self._factory_budget is not None: M.json_bound(layout, self._factory_budget)
            if self._factory_budget is not None: M.collection(self._factory_budget, len(layout['fields']))
            children = [field['layout'] for field in layout['fields']]
            if layout['element'] is not None:
                children.append(optional(layout['element']))
            if not finish:
                pending.append((current, True))
                pending.extend((key(child), False) for child in children)
                continue
            shape = {'type': self.types.digest(layout['type']), 'size': layout['size'],
                     'alignment': layout['alignment'], 'access_bytes': layout['access_bytes'], 'stride': layout['stride'],
                     'fields': [{'value_index': field['value_index'], 'bit_offset': field['bit_offset'],
                                 'bit_width': field['bit_width'], 'layout': memo[key(field['layout'])]} for field in layout['fields']],
                     'element': None if layout['element'] is None else memo[key(optional(layout['element']))]}
            if self._factory_budget is not None: M.json_bound(shape, self._factory_budget)
            data = json.dumps(shape, sort_keys=True, separators=(',', ':')).encode('ascii')
            memo[current] = hashlib.sha256(b'SMIR-MEMORY-LAYOUT-V1\0' + data).hexdigest()
        return memo[key(reference)]
