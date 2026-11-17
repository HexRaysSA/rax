"""Component poison, raw fragments and pointer exposure in one typed value model."""
from dataclasses import dataclass, field

from common import require
from candidate.raw import Raw, concat


@dataclass(frozen=True)
class Pointer:
    address: int
    origin: object = None
    generation: int = 0
    domain: str = 'data'
    access_range: tuple | None = None
    permit: object = None
    authority: object = field(default=None, compare=False)
    lineage: object = None

    @property
    def identity(self):
        return self.origin


@dataclass(frozen=True)
class Value:
    type: dict
    state: str
    data: object = None


@dataclass(frozen=True)
class Handle:
    kind: str
    identity: int
    generation: int


def validate(types, value, handles=None):
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        require(visited <= 100000 and isinstance(current, Value)
                and current.state in {'concrete', 'poison', 'undef'}, 'runtime_value_shape')
        item = types.get(current.type)
        if current.state != 'concrete':
            require(current.data is None and item['kind'] != 'function', 'runtime_value_state')
            continue
        types.materializable(current.type)
        components = types.components(current.type)
        if components is not None:
            require(type(current.data) is tuple and len(current.data) == len(components), 'runtime_value_components')
            require(all(types.equal(child.type, typ) for child, typ in zip(current.data, components)), 'runtime_component_type')
            pending.extend(current.data)
        elif item['kind'] in {'int', 'float'}:
            require(type(current.data) is int and 0 <= current.data < 1 << types.width(current.type), 'runtime_scalar_bits')
        elif item['kind'] == 'raw':
            require(isinstance(current.data, Raw) and current.data.width == item['bits'], 'runtime_raw')
        elif item['kind'] in {'data_ptr', 'code_ptr', 'code_address'}:
            require(isinstance(current.data, Pointer) and 0 <= current.data.address < 2**64, 'runtime_pointer')
        elif item['kind'] == 'fenv':
            from candidate.fenv import pack
            pack(current.data)
        else:
            require(isinstance(current.data, Handle) and current.data.kind == item['kind'], 'runtime_handle')
            require(handles is not None and current.data.identity in handles, 'runtime_handle_registry')
            entry = handles[current.data.identity]
            require(entry['live'] and entry['generation'] == current.data.generation
                    and entry['kind'] == current.data.kind, 'runtime_handle_generation')
    return value


def literal(types, reference, source):
    kind = source['kind']
    if kind in {'poison', 'undef'}:
        return Value(reference, kind)
    types.materializable(reference)
    children = types.components(reference)
    if children is not None:
        items = source['elements'] if kind == 'aggregate' else [source] * len(children)
        return Value(reference, 'concrete', tuple(literal(types, child, item)
                                                 for child, item in zip(children, items)))
    bits = 0 if kind == 'zero' else int.from_bytes(bytes.fromhex(source['value']), 'little')
    item = types.get(reference)
    if item['kind'] in {'data_ptr', 'code_ptr', 'code_address'}:
        domain = 'code_address' if item['kind'] == 'code_address' else 'code' if item['kind'] == 'code_ptr' else 'data'
        return Value(reference, 'concrete', Pointer(bits, domain=domain))
    if item['kind'] == 'raw':
        return Value(reference, 'concrete', Raw.integer(item['bits'], bits))
    return Value(reference, 'concrete', bits)


def zero(types, reference):
    from candidate.type_system import HANDLES
    require(types.get(reference)['kind'] != 'function' and not types.contains_value_kind(reference, HANDLES),
            'freeze_opaque')
    types.materializable(reference)
    if types.get(reference)['kind'] == 'fenv':
        return Value(reference, 'concrete', {'rounding': 'nearest_even', 'flags': [], 'traps': []})
    children = types.components(reference)
    if children is not None:
        return Value(reference, 'concrete', tuple(zero(types, child) for child in children))
    return literal(types, reference, {'kind': 'zero'})


def materialize(types, value):
    if value.state == 'undef':
        return zero(types, value.type)
    return value


def freeze(types, value):
    from candidate.type_system import HANDLES
    require(not types.contains_value_kind(value.type, HANDLES), 'freeze_opaque')
    if value.state in {'poison', 'undef'}:
        return zero(types, value.type)
    children = types.components(value.type)
    if children is not None:
        return Value(value.type, 'concrete', tuple(freeze(types, child) for child in value.data))
    if types.get(value.type)['kind'] == 'raw':
        return Value(value.type, 'concrete', value.data.freeze())
    return value


def well_defined(types, value):
    if value.state != 'concrete':
        return False
    children = types.components(value.type)
    if children is not None:
        return all(well_defined(types, child) for child in value.data)
    return types.get(value.type)['kind'] != 'raw' or not (value.data.poison | value.data.undef)


def raw_bits(types, value):
    width = types.width(value.type)
    require(width <= 2**23, 'reference_resource', 'raw materialization width')
    if value.state == 'poison':
        return Raw.integer(width, 0, (1 << width) - 1)
    if value.state == 'undef':
        return Raw.integer(width, 0, undef=(1 << width) - 1)
    children = types.components(value.type)
    if children is not None:
        return concat([raw_bits(types, child) for child in value.data])
    item = types.get(value.type)
    if item['kind'] == 'raw':
        return value.data
    if item['kind'] in {'data_ptr', 'code_ptr', 'code_address'}:
        pointer = value.data
        if pointer.origin is None and pointer.access_range is None:
            return Raw.integer(64, pointer.address)
        return Raw.pointer(pointer)
    require(item['kind'] in {'int', 'float'}, 'opaque_bitcast')
    return Raw.integer(width, value.data)


def from_raw(types, reference, raw):
    item = types.get(reference)
    children = types.components(reference)
    if children is not None:
        result, offset = [], 0
        for child in children:
            width = types.width(child)
            result.append(from_raw(types, child, raw.slice(offset, width)))
            offset += width
        return Value(reference, 'concrete', tuple(result))
    if item['kind'] == 'raw':
        return Value(reference, 'concrete', raw)
    if raw.poison:
        return Value(reference, 'poison')
    if item['kind'] in {'data_ptr', 'code_ptr', 'code_address'}:
        pointer = raw.as_pointer()
        if item['kind'] == 'code_address' and (pointer['domain'] != 'code_address' or pointer.get('permit') is not None):
            # A raw typed destination is not observing code_erase and cannot
            # convert callable code authority to address authority.
            return Value(reference, 'concrete', Pointer(raw.bits, domain='code_address',
                                                        access_range=pointer.get('access_range')))
        return Value(reference, 'concrete', Pointer(raw.bits, pointer['identity'], pointer['generation'] or 0,
                                                    (pointer['domain'] if pointer['identity'] is not None else
                                                     'code_address' if item['kind'] == 'code_address' else
                                                     'code' if item['kind'] == 'code_ptr' else 'data'),
                                                    pointer.get('access_range'), pointer.get('permit'),
                                                    pointer.get('authority'), pointer.get('lineage')))
    if any(getattr(span.pointer, 'access_range', None) is not None for span in raw.origins):
        from candidate.memory import GuestFault
        raise GuestFault('ub_inrange_address_conversion', True)
    return Value(reference, 'concrete', raw.bits & ~raw.undef)


def component(types, value, indices):
    current = value
    for index in indices:
        if current.state != 'concrete':
            current = Value(types.child(current.type, index), current.state)
        else:
            current = current.data[index]
    return current


def insert(types, value, indices, replacement):
    types.materializable(value.type)
    children = types.components(value.type)
    values = (list(value.data) if value.state == 'concrete'
              else [Value(child, value.state) for child in children])
    index = indices[0]
    values[index] = replacement if len(indices) == 1 else insert(types, values[index], indices[1:], replacement)
    return Value(value.type, 'concrete', tuple(values))
