"""Exact symbolic binary records for proposed section 1/3 payloads.

This format is a draft independent of envelope revision 0.1. Decoding records
does not verify a module and grants no execution capability.
"""
import struct

from common import Budget, Limits, SCHEMA, TOKEN, check_shape, fields, require


def encode(record_type, value, limits=Limits()):
    check_shape(record_type, value, limits)
    output = bytearray()

    def append(data):
        require(len(output) + len(data) <= limits.max_bytes, 'limit', 'payload bytes')
        output.extend(data)

    def emit(kind, item):
        if kind.startswith('vec:'):
            append(struct.pack('<I', len(item)))
            for element in item:
                emit(kind[4:], element)
        elif kind in {'u32', 'u64'}:
            append(item.to_bytes(int(kind[1:]) // 8, 'little'))
        elif kind == 'hex':
            raw = bytes.fromhex(item)
            append(struct.pack('<I', len(raw)))
            append(raw)
        elif kind == 'token':
            raw = item.encode('ascii')
            append(bytes([len(raw)]))
            append(raw)
        else:
            layout, discriminator = fields(kind, item)
            if discriminator:
                emit('token', item[discriminator])
            for name, field_type in layout:
                emit(field_type, item[name])

    emit(record_type, value)
    return bytes(output)


def decode(record_type, payload, limits=Limits()):
    require(len(payload) <= limits.max_bytes, 'limit', 'payload bytes')
    cursor = 0
    budget = Budget(limits)

    def take(size):
        nonlocal cursor
        require(size <= len(payload) - cursor, 'truncated', 'record field')
        result = payload[cursor:cursor + size]
        cursor += size
        return result

    def number():
        return int.from_bytes(take(4), 'little')

    def read(kind, depth=0):
        budget.visit(depth)
        if kind.startswith('vec:'):
            count = number()
            require(count <= limits.max_list and count <= limits.max_nodes - budget.nodes,
                    'limit', 'vector length')
            return [read(kind[4:], depth + 1) for _ in range(count)]
        if kind in {'u32', 'u64'}:
            return int.from_bytes(take(int(kind[1:]) // 8), 'little')
        if kind == 'hex':
            return take(number()).hex()
        if kind == 'token':
            size = take(1)[0]
            require(1 <= size <= 63, 'shape', 'token length')
            raw = take(size)
            require(all(byte < 128 for byte in raw), 'shape', 'ASCII token')
            token = raw.decode('ascii')
            require(TOKEN.fullmatch(token) is not None, 'shape', 'token syntax')
            return token
        record = SCHEMA['records'][kind]
        item = {}
        if 'variants' in record:
            tag = read('token', depth + 1)
            require(tag in record['variants'], 'shape', f'unknown {kind} tag')
            item[record['discriminator']] = tag
            layout = record['variants'][tag]
        else:
            layout = record['fields']
        for name, field_type in layout:
            item[name] = read(field_type, depth + 1)
        return item

    value = read(record_type)
    require(cursor == len(payload), 'trailing', 'record payload')
    check_shape(record_type, value, limits)
    return value


def encode_sections(module, limits=Limits()):
    check_shape('module', module, limits)
    require(module['revision'] == 'integer_core_draft_v1', 'revision')
    return (encode('vec:type', module['types'], limits),
            encode('vec:function', module['functions'], limits))


def decode_sections(types, functions, limits=Limits()):
    module = {'revision': 'integer_core_draft_v1',
              'types': decode('vec:type', types, limits),
              'functions': decode('vec:function', functions, limits)}
    check_shape('module', module, limits)
    return module
