"""Componentwise pure execution and explicit floating environment effects."""
from evaluate import POISON as OLD_POISON, UNDEF as OLD_UNDEF, Trap, Value as OldValue, integer, signed

from candidate import fp

_UNBOUND_SELECT_ISSUER = object()
from candidate.memory import GuestFault
from candidate.operations import optional
from candidate.values import Pointer, Value, component, freeze, from_raw, insert, literal, materialize, raw_bits, zero


def execute(machine, operation, arguments):
    types, name = machine.types, operation['op']
    output = operation['results'][0]['type'] if operation['results'] else None
    if name == 'constant':
        return [literal(types, output, operation['literal'])]
    if name == 'copy':
        return [Value(output, arguments[0].state, arguments[0].data)]
    if name == 'freeze':
        return [freeze(types, arguments[0])]
    if name in {'extract', 'insert'}:
        return [component(types, arguments[0], operation['indices']) if name == 'extract' else
                insert(types, arguments[0], operation['indices'], arguments[1])]
    if name in {'extract_element', 'insert_element'}:
        vector, index = arguments[0], materialize(types, arguments[-1])
        count = types.get(vector.type)['count']
        if index.state == 'poison' or index.data >= count:
            return [Value(output, 'poison')]
        if name == 'extract_element':
            return [component(types, vector, [index.data])]
        return [insert(types, vector, [index.data], arguments[1])]
    if name == 'shuffle':
        result = []
        children = types.components(output)
        count = types.get(arguments[0].type)['count']
        for child, wrapped in zip(children, operation['mask']):
            index = optional(wrapped)
            result.append(Value(child, 'poison') if index is None else
                          component(types, arguments[index // count], [index % count]))
        return [Value(output, 'concrete', tuple(result))]
    if name == 'select':
        condition, a, b = arguments
        if types.get(condition.type)['kind'] == 'vector':
            results = []
            for index, child in enumerate(types.components(output)):
                cond = materialize(types, component(types, condition, [index]))
                results.append(Value(child, 'poison') if cond.state == 'poison' else
                               component(types, a if cond.data else b, [index]))
            return [Value(output, 'concrete', tuple(results))]
        original_condition = condition
        condition = materialize(types, condition)
        if getattr(machine, '_unbound_flow', None) is not None:
            machine._note_unbound_selection(original_condition, condition,
                None if condition.state == 'poison' else 1 if condition.data else 2,
                _UNBOUND_SELECT_ISSUER)
        return [Value(output, 'poison') if condition.state == 'poison' else a if condition.data else b]
    if name == 'bitcast':
        return [from_raw(types, output, raw_bits(types, arguments[0]))]

    # Unary/binary integer, FP and casts map over matching fixed-vector lanes.
    source_vector = bool(arguments and types.get(arguments[0].type)['kind'] == 'vector')
    if source_vector:
        children = types.components(output)
        result = []
        raised = set()
        for index, child in enumerate(children):
            lane_args = [component(types, value, [index]) for value in arguments]
            value, flags = scalar(machine, name, child, lane_args, operation)
            result.append(value)
            raised |= flags
        machine.fp_commit(operation.get('mode'), raised)
        return [Value(output, 'concrete', tuple(result))]
    value, raised = scalar(machine, name, output, arguments, operation)
    machine.fp_commit(operation.get('mode'), raised)
    return [value]


def scalar(machine, name, output, arguments, operation):
    types = machine.types
    args = [materialize(types, value) for value in arguments]
    source = types.get(args[0].type) if args else None
    if name.startswith('i_') or name == 'icmp':
        width = source.get('bits', 64)
        converted = []
        if name == 'icmp' and all(value.state == 'concrete' for value in args) and isinstance(args[0].data, Pointer):
            for pointer_value in args:
                pointer = pointer_value.data
                if pointer.access_range is not None and not all(
                        pointer.access_range[0] <= other.data.address <= pointer.access_range[1] for other in args):
                    raise GuestFault('ub_inrange_compare', True)
        for value in args:
            data = value.data.address if isinstance(value.data, Pointer) else value.data
            converted.append(OLD_POISON if value.state == 'poison' else OldValue('bits', data))
        action = name.removeprefix('i_')
        if action in {'rotl', 'rotr', 'clz', 'ctz', 'popcount', 'abs', 'bswap', 'bitreverse'}:
            if any(value.state == 'poison' for value in args):
                return Value(output, 'poison'), set()
            a = args[0].data
            mask = (1 << width) - 1
            if action in {'rotl', 'rotr'}:
                shift = args[1].data % width
                if action == 'rotr':
                    shift = (-shift) % width
                result = ((a << shift) | (a >> ((width - shift) % width))) & mask
            elif action in {'clz', 'ctz'}:
                if a == 0 and operation['zero_is_poison']:
                    return Value(output, 'poison'), set()
                result = (width - a.bit_length() if action == 'clz' else
                          (a & -a).bit_length() - 1 if a else width)
            elif action == 'popcount':
                result = a.bit_count()
            elif action == 'abs':
                if a == 1 << (width - 1) and operation['zero_is_poison']:
                    return Value(output, 'poison'), set()
                result = abs(signed(a, width)) & mask
            elif action == 'bswap':
                result = int.from_bytes(a.to_bytes(width // 8, 'little'), 'big')
            else:
                result = int(f'{a:0{width}b}'[::-1], 2)
            return Value(output, 'concrete', result), set()
        try:
            value = integer('icmp' if name == 'icmp' else action, width, *converted,
                            flags=operation.get('flags', ()), predicate=operation.get('predicate'))
        except Trap as error:
            raise GuestFault(error.code, True) from error
        if value.kind == 'poison':
            return Value(output, 'poison'), set()
        return Value(output, 'concrete', value.bits), set()
    if name in {'trunc', 'zext', 'sext'}:
        if args[0].state == 'poison':
            return Value(output, 'poison'), set()
        bits = signed(args[0].data, source['bits']) if name == 'sext' else args[0].data
        return Value(output, 'concrete', bits & ((1 << types.width(output)) - 1)), set()
    if name in {'ptrtoint', 'ptrtoaddr', 'inttoptr'}:
        if (source['kind'] == 'code_address' or types.get(output)['kind'] == 'code_address' or
                (getattr(machine, '_source_runtime', None) is not None and
                 (source['kind'] == 'code_ptr' or types.get(output)['kind'] == 'code_ptr'))):
            # The old Machine's local code map is not the process-wide registry.
            # A scalar/vector partial iteration must not publish legacy exposure.
            raise GuestFault('code_address_unavailable', False)
        if args[0].state == 'poison':
            return Value(output, 'poison'), set()
        if name == 'inttoptr':
            domain = 'code' if types.get(output)['kind'] == 'code_ptr' else 'data'
            bits = args[0].data & ((1 << 64) - 1)
            pointer = machine.memory.integer_pointer(bits, domain)
            if domain == 'code' and bits in machine.exposed_code and bits in machine.code_pointers:
                pointer = machine.code_pointers[bits][0]
            return Value(output, 'concrete', pointer), set()
        pointer = args[0].data
        if pointer.access_range is not None:
            raise GuestFault('ub_inrange_address_conversion', True)
        if name == 'ptrtoint':
            if pointer.domain == 'code':
                entry = machine.code_pointers.get(pointer.address)
                if entry is not None and entry[0] == pointer and pointer.origin is not None:
                    machine.exposed_code.add(pointer.address)
            else:
                machine.memory.expose(pointer)
        return Value(output, 'concrete', pointer.address & ((1 << types.width(output)) - 1)), set()
    if name == 'ptr_offset':
        if any(value.state == 'poison' for value in args):
            return Value(output, 'poison'), set()
        pointer = machine.memory.offset(args[0].data, signed(args[1].data, 64), operation['inbounds'],
                                        operation['nuw'], operation['nusw'], optional(operation['inrange']),
                                        check_base=operation['check_base'])
        return Value(output, 'poison' if pointer is None else 'concrete', pointer), set()
    if name.startswith('fp_') or name in {'fcmp', 'sitofp', 'uitofp', 'fptosi', 'fptoui',
                                         'fptosi_sat', 'fptoui_sat', 'fpconvert'}:
        if any(value.state == 'poison' for value in args):
            return Value(output, 'poison'), set()
        mode = operation['mode']
        rounding = 'nearest_even' if mode['environment'] == 'default' else (
            machine.environment['rounding'] if mode['rounding'] == 'dynamic' else mode['rounding'])
        if name == 'fcmp':
            bits, raised = fp.compare(operation['predicate'], operation['signaling'], source['format'],
                                      args[0].data, args[1].data)
        else:
            destination = types.get(output)
            destination = destination.get('format', destination.get('bits'))
            sources = [types.get(value.type).get('format', types.get(value.type).get('bits')) for value in args]
            bits, raised = fp.scalar(name.removeprefix('fp_'), destination, sources,
                                     [value.data for value in args], rounding)
            if name.endswith('_sat'):
                raised = set()
        return Value(output, 'poison' if bits is None else 'concrete', bits), raised
    raise GuestFault('reference_operation_unhandled:' + name)
