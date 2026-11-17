"""Restricted prepublication constant evaluation (S074/INT018 draft).

Inputs are trusted, selected runtime reservations, never file-issued authority.
The runtime owner performs association/TLS/lease checks and commits complete
transactions. This evaluator returns private bytes/shadow/exposure only.
"""
from copy import deepcopy
from dataclasses import dataclass

from common import require
from candidate import pure
from candidate.context import RootContext
from candidate.memory import Memory
from candidate.raw import Raw
from candidate.type_system import HANDLES, key
from candidate.values import Pointer, Value, validate

OPERATIONS = frozenset({'constant', 'copy', 'freeze', 'i_add', 'i_sub', 'i_xor', 'i_mul', 'icmp', 'select',
    'extract', 'insert', 'extract_element', 'insert_element', 'shuffle', 'trunc',
    'zext', 'sext', 'bitcast', 'ptrtoint', 'ptrtoaddr', 'inttoptr', 'ptr_offset', 'address_of'})


@dataclass(frozen=True)
class InitializerResult:
    value: Value
    bytes: tuple[Raw, ...]
    data_exposed: frozenset[object]
    code_exposed: frozenset[int]


class _PureState:
    def __init__(self, types, memory, code_pointers, exposed_code):
        self.types, self.memory = types, memory
        self.code_pointers, self.exposed_code = code_pointers, set(exposed_code)

    def fp_commit(self, mode, flags):
        require(not flags and mode is None, 'initializer_no_fenv')


def evaluate_initializer(context, function, layout, *, memory, symbols, code_pointers,
                         exposed_code=frozenset(), max_operations=65536, max_bytes=1048576):
    require(isinstance(context, RootContext) and context.abi_checked
            and context.execution_checked is not None, 'initializer_context')
    require(function['module']['kind'] == layout['module']['kind'] == 'self', 'initializer_self')
    require(type(max_operations) is int and max_operations >= 0 and type(max_bytes) is int
            and max_bytes >= 0, 'initializer_budget')
    context.assert_snapshot()
    admitted = context.verify_execution()  # Recheck actual records, not a producer flag.
    body = context.function(function)
    signature = admitted.types.get(body['signature'])
    require(body['abi_signature'] is None and signature['cc'] == 'portable' and not signature['variadic']
            and signature['params'] == [] and body['params'] == [] and len(signature['results']) == 1
            and signature['result_noundef'] == [False] and body['escape'] == 'propagate'
            and body['no_return'] is False, 'initializer_signature')
    require(len(body['blocks']) == 1, 'initializer_block')
    block = body['blocks'][0]
    require(block['phis'] == [] and block['term']['op'] == 'return'
            and len(block['term']['values']) == 1, 'initializer_control')
    exceptions = next((entry for entry in admitted.exceptions_root['functions']
                       if entry['function'] == function['id']), None)
    require(exceptions is None or not exceptions['actions'] and not exceptions['regions'], 'initializer_eh')
    require(len(block['ops']) <= max_operations, 'initializer_resource_operations')
    require(all(op['op'] in OPERATIONS for op in block['ops']), 'initializer_operation')
    value_types = signature['results'] + [result['type'] for op in block['ops'] for result in op['results']]
    require(not any(admitted.types.contains_value_kind(typ, HANDLES | {'fenv'}) for typ in value_types),
            'initializer_opaque')
    require(key(layout) in admitted.dependencies.layouts, 'initializer_layout')
    physical = admitted.dependencies.layouts[key(layout)]
    require(admitted.types.equal(physical['type'], signature['results'][0])
            and physical['access_bytes'] > 0, 'initializer_layout_extent')
    require(physical['access_bytes'] <= max_bytes, 'initializer_resource_output')
    require(isinstance(memory, Memory) and type(symbols) is dict and type(code_pointers) is dict
            and type(exposed_code) in {set, frozenset}, 'initializer_reservations')
    # max_bytes bounds cumulative staged object bytes + every SSA value's logical
    # storage + output, including dead/poison/zero results. Count nodes separately
    # so zero-width aggregates cannot bypass the budget. Saturating comparisons
    # avoid fixed-width overflow in independent ports of this preflight.
    working_bytes = physical['access_bytes']
    nodes = len(memory.objects) + len(symbols) + len(code_pointers)
    for item in memory.objects.values():
        require(0 <= item['size'] <= max_bytes - working_bytes, 'initializer_resource_memory')
        working_bytes += item['size']
    for typ in value_types[1:]:  # Result signature aliases an SSA value; charge each definition once.
        width = (admitted.types.width(typ) + 7) // 8
        cost = admitted.types.value_costs[key(typ)]
        require(width <= max_bytes - working_bytes, 'initializer_resource_values')
        require(cost <= 100000 - nodes, 'initializer_resource_nodes')
        working_bytes += width
        nodes += cost
    require(nodes <= 100000, 'initializer_resource_nodes')
    # Clone facts and shadow only after every cumulative quota check.
    private = Memory(admitted.types, admitted.dependencies, max_bytes)
    private.objects = deepcopy(memory.objects)
    private.next_address, private.sequence = memory.next_address, memory.sequence
    private.exposed = set(memory.exposed)
    state = _PureState(admitted.types, private, deepcopy(code_pointers), exposed_code)
    values = {}
    for operation in block['ops']:
        if operation['op'] == 'address_of':
            identity = key(operation['symbol'])
            require(identity in symbols, 'initializer_symbol_reservation')
            pointer = symbols[identity]
            output = operation['results'][0]['type']
            kind = admitted.types.get(output)['kind']
            if not isinstance(pointer, Pointer):
                from candidate.bindings import runtime_package_module
                weak_type = runtime_package_module('reservations').WeakNull
                require(isinstance(pointer, weak_type), 'initializer_pointer')
                domain = pointer.issuer.verify_weak(pointer, context, operation['symbol'])
                require(domain == ('data' if kind == 'data_ptr' else 'code'), 'initializer_weak_domain')
                pointer = Pointer(0, None, 0, domain)
            elif kind == 'data_ptr':
                item = private.objects.get(pointer.origin)
                require(pointer.domain == 'data' and item is not None and item['live']
                        and pointer.generation == item['generation']
                        and item['address'] <= pointer.address <= item['address'] + item['size'],
                        'initializer_object_reservation')
            else:
                actual = admitted.dependencies.symbols[identity]
                entry = state.code_pointers.get(pointer.address)
                require(not actual.get('native_only', False) and pointer.domain == 'code'
                        and entry is not None and entry[0] == pointer and type(entry[1]) is dict
                        and entry[1].get('kind') in {'direct', 'import'}
                        and admitted.types.equal(entry[1]['signature'], admitted.types.get(output)['signature']),
                        'initializer_code_reservation')
            results = [Value(output, 'concrete', pointer)]
        else:
            results = pure.execute(state, operation, [values[identifier] for identifier in operation['operands']])
        require(len(results) == len(operation['results']), 'initializer_result_arity')
        for declaration, value in zip(operation['results'], results):
            require(admitted.types.equal(declaration['type'], value.type), 'initializer_result_type')
            validate(admitted.types, value)
            values[declaration['id']] = value
    value = values[block['term']['values'][0]]
    serialized = tuple(private.storage_bytes(value, layout))
    require(len(serialized) == physical['access_bytes'], 'initializer_serialization')
    context.assert_snapshot()
    return InitializerResult(value, serialized, frozenset(private.exposed), frozenset(state.exposed_code))
