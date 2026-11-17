"""INT-008 candidate primitives and exact record parsing, separate from legacy."""
import json
from pathlib import Path
import re

from common import Budget, Limits, Reject, require

SCHEMA_PATH = Path(__file__).resolve().parents[4] / 'docs/specifications/smir/portable/schema/execution/candidate.json'
SCHEMA = json.loads(SCHEMA_PATH.read_text())
TOKEN = re.compile(r'[a-z][a-z0-9_]{0,62}\Z', re.ASCII)
HEX = re.compile(r'(?:[0-9a-f]{2})*\Z', re.ASCII)
INTEGERS = {f'{sign}{bits}': (bits // 8, sign == 'i')
            for sign in ['u', 'i'] for bits in [8, 16, 32, 64]}


def encode(kind, value, limits=Limits(), records=None):
    records = SCHEMA['records'] if records is None else records
    output = bytearray()
    budget = Budget(limits)

    def append(raw):
        require(len(output) + len(raw) <= limits.max_bytes, 'limit', 'candidate bytes')
        output.extend(raw)

    def visit(name, item, depth=0):
        budget.visit(depth)
        if name.startswith('vec:'):
            require(type(item) is list and len(item) <= limits.max_list, 'shape', name)
            append(len(item).to_bytes(4, 'little'))
            for child in item:
                visit(name[4:], child, depth + 1)
        elif name.startswith('opt:'):
            append(bytes([int(item is not None)]))
            if item is not None:
                require(type(item) is dict and set(item) == {'some'}, 'shape', 'option wrapper')
                visit(name[4:], item['some'], depth + 1)
        elif name in INTEGERS:
            size, signed = INTEGERS[name]
            minimum = -(1 << (8 * size - 1)) if signed else 0
            maximum = (1 << (8 * size - int(signed))) - 1
            require(type(item) is int and minimum <= item <= maximum, 'shape', name)
            append(item.to_bytes(size, 'little', signed=signed))
        elif name == 'bool':
            require(type(item) is bool, 'shape', name)
            append(bytes([int(item)]))
        elif name in {'bytes', 'hex', 'digest32'}:
            if name == 'bytes':
                require(type(item) is bytes, 'shape', name)
                raw = item
            else:
                require(isinstance(item, str) and HEX.fullmatch(item) is not None, 'shape', name)
                raw = bytes.fromhex(item)
            if name == 'digest32':
                require(len(item) == 64, 'shape', name)
            else:
                require(len(raw) <= limits.max_bytes, 'limit', name)
                append(len(raw).to_bytes(4, 'little'))
            append(raw)
        elif name in {'token', 'utf8'}:
            require(isinstance(item, str), 'shape', name)
            try:
                raw = item.encode('utf-8', errors='strict')
            except UnicodeEncodeError as error:
                raise Reject('shape', 'surrogate in UTF8') from error
            if name == 'token':
                require(TOKEN.fullmatch(item) is not None, 'shape', name)
                append(bytes([len(raw)]))
            else:
                require(len(raw) <= limits.max_bytes, 'limit', name)
                append(len(raw).to_bytes(4, 'little'))
            append(raw)
        else:
            require(name in records and isinstance(item, dict), 'shape', name)
            record = records[name]
            discriminator = record.get('discriminator')
            if discriminator:
                tag = item.get(discriminator)
                require(isinstance(tag, str) and tag in record['variants'], 'shape', name)
                layout = record['variants'][tag]
                visit('token', tag, depth + 1)
            else:
                layout = record['fields']
            expected = {field for field, _ in layout} | ({discriminator} if discriminator else set())
            require(set(item) == expected, 'shape', f'{name} exact fields')
            for field, field_type in layout:
                visit(field_type, item[field], depth + 1)

    visit(kind, value)
    return bytes(output)


def decode(kind, payload, limits=Limits(), records=None):
    records = SCHEMA['records'] if records is None else records
    require(len(payload) <= limits.max_bytes, 'limit', 'candidate bytes')
    cursor = 0
    budget = Budget(limits)

    def take(size):
        nonlocal cursor
        require(size <= len(payload) - cursor, 'truncated', 'candidate field')
        raw = payload[cursor:cursor + size]
        cursor += size
        return raw

    def visit(name, depth=0):
        budget.visit(depth)
        if name.startswith('vec:'):
            count = int.from_bytes(take(4), 'little')
            require(count <= limits.max_list and count <= limits.max_nodes - budget.nodes, 'limit', 'vector')
            return [visit(name[4:], depth + 1) for _ in range(count)]
        if name.startswith('opt:'):
            present = take(1)[0]
            require(present in {0, 1}, 'shape', 'option tag')
            return {'some': visit(name[4:], depth + 1)} if present else None
        if name in INTEGERS:
            size, signed = INTEGERS[name]
            return int.from_bytes(take(size), 'little', signed=signed)
        if name == 'bool':
            value = take(1)[0]
            require(value in {0, 1}, 'shape', 'bool')
            return bool(value)
        if name in {'bytes', 'hex', 'digest32'}:
            raw = take(32 if name == 'digest32' else int.from_bytes(take(4), 'little'))
            return raw if name == 'bytes' else raw.hex()
        if name in {'token', 'utf8'}:
            size = take(1)[0] if name == 'token' else int.from_bytes(take(4), 'little')
            if name == 'token':
                require(1 <= size <= 63, 'shape', 'token extent')
            try:
                text = take(size).decode('utf-8', errors='strict')
            except UnicodeDecodeError as error:
                raise Reject('shape', 'non-shortest/surrogate/invalid UTF8') from error
            require(name != 'token' or TOKEN.fullmatch(text) is not None, 'shape', 'token')
            return text
        record = records[name]
        result = {}
        discriminator = record.get('discriminator')
        if discriminator:
            tag = visit('token', depth + 1)
            require(tag in record['variants'], 'shape', f'{name} variant')
            result[discriminator] = tag
            layout = record['variants'][tag]
        else:
            layout = record['fields']
        for field, field_type in layout:
            result[field] = visit(field_type, depth + 1)
        return result

    result = visit(kind)
    require(cursor == len(payload), 'trailing', 'candidate root')
    return result
