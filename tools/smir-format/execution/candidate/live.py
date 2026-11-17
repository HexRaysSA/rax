"""Typed live-value validation against independently issued runtime registries.

No entry is created, made live or granted permission by parsing this data.
Pointer tombstones can be preserved; dereference/call checks remain separate.
The returned dict is not an admission token. Restoring executable state also
requires the runtime's private handoff ticket/digest over the complete snapshot;
registry membership alone cannot authenticate a changed pointer range/value.
"""
from dataclasses import dataclass, field

from common import bit_pattern, require
from candidate.fenv import pack
from candidate.operations import optional
from candidate.type_system import HANDLES
from candidate.wire import encode


@dataclass
class Registry:
    # Keys (domain,object,generation) include retained tombstones. Entries contain
    # domain and generation plus any runtime-owned range/lease data. The key is
    # looked up, never registered from a snapshot's own numerical claims.
    pointers: dict = field(default_factory=dict)
    # Keys (kind,identity,generation); entries require live/thread and, for
    # activation-bound values, activation. Exception leases may transfer only
    # through independently admitted owner-thread transfer, before this check.
    handles: dict = field(default_factory=dict)


def absolute_range(value):
    if value is None:
        return None
    value = optional(value)
    if value['empty']:
        require(value['lower'] == value['upper'] == 0 and not value['upper_is_limit'], 'live_range_empty_encoding')
        from candidate.ranges import EMPTY
        return EMPTY
    require(not value['upper_is_limit'] or value['upper'] == 0, 'live_range_limit_encoding')
    upper = 2**64 if value['upper_is_limit'] else value['upper']
    require(value['lower'] <= upper, 'live_range_order')
    return value['lower'], upper


def validate(value, types, registry, thread, activation=None):
    encode('execution_live_value', value)
    require(isinstance(registry, Registry), 'live_registry_required')
    pending, visited = [value], 0
    unsupported_permit = False

    def pointer(payload, allowed):
        nonlocal unsupported_permit
        require(payload['domain'] in allowed, 'live_pointer_domain')
        permit = optional(payload['binding_permit'])
        if permit is not None:
            require(permit > 0 and payload['domain'] == 'code', 'live_binding_permit')
            unsupported_permit = True
        identity = optional(payload['object'])
        absolute_range(payload['range'])
        if identity is None:
            require(payload['generation'] == 0, 'live_unprovenanced_generation')
        elif permit is None:
            require((payload['domain'], identity, payload['generation']) in registry.pointers,
                    'live_pointer_registry')

    while pending:
        current = pending.pop()
        visited += 1
        require(visited <= 100000, 'reference_resource', 'live value nodes')
        typ = types.get(current['type'])
        payload, kind = current['payload'], current['payload']['kind']
        require(typ['kind'] != 'function', 'live_function_not_value')
        if kind in {'poison', 'undef'}:
            continue
        children = types.components(current['type'])
        if children is not None:
            require(kind == 'aggregate' and len(payload['elements']) == len(children), 'live_component_arity')
            require(all(types.equal(expected, actual['type']) for expected, actual in zip(children, payload['elements'])),
                    'live_component_type')
            pending.extend(payload['elements'])
        elif typ['kind'] in {'int', 'float'}:
            require(kind == 'scalar', 'live_scalar_payload')
            bit_pattern(payload['bits'], types.width(current['type']))
        elif typ['kind'] == 'raw':
            require(kind == 'raw', 'live_raw_payload')
            width = typ['bits']
            bits, poison, undef = [bit_pattern(payload[field], width) for field in ['bits', 'poison', 'undef']]
            require(not poison & undef, 'live_raw_state_overlap')
            previous = 0
            for span in payload['origins']:
                require(previous <= span['offset'] and 0 < span['length'] <= 64
                        and span['offset'] + span['length'] <= width
                        and span['source_bit'] + span['length'] <= 64, 'live_origin_extent')
                pointer({'domain': span['domain'], 'object': span['object'],
                         'generation': span['generation'], 'range': span['range'],
                         'binding_permit': span['binding_permit']}, {'data', 'code', 'label', 'code_address'})
                mask = (1 << span['length']) - 1
                require(not ((poison | undef) >> span['offset']) & mask
                        and (bits >> span['offset']) & mask == (span['pointer_bits'] >> span['source_bit']) & mask,
                        'live_origin_bits')
                previous = span['offset'] + span['length']
        elif typ['kind'] in {'data_ptr', 'code_ptr', 'code_address'}:
            require(kind == 'pointer', 'live_pointer_payload')
            pointer(payload, {'data'} if typ['kind'] == 'data_ptr' else
                    {'code_address'} if typ['kind'] == 'code_address' else {'code', 'label'})
        elif typ['kind'] == 'fenv':
            require(kind == 'fenv', 'live_fenv_payload')
            pack({name: payload[name] for name in ['rounding', 'flags', 'traps']})
        else:
            require(typ['kind'] in HANDLES and kind == 'handle' and payload['kind_name'] == typ['kind'], 'live_handle_kind')
            identity = payload['kind_name'], payload['identity'], payload['generation']
            require(identity in registry.handles, 'live_handle_registry')
            entry = registry.handles[identity]
            require(entry['live'] and entry['thread'] == thread, 'live_handle_owner')
            if typ['kind'] in {'stack_mark', 'va_list', 'journal'}:
                require(activation is not None and entry['activation'] == activation, 'live_handle_activation')
    if unsupported_permit:
        from candidate.memory import GuestFault
        raise GuestFault('code_address_unavailable', False)
    return value
