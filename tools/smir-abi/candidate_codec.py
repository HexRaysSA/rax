"""INT-008 ordered ABI record codec; candidate reference only, no engine admission."""

import json
from pathlib import Path
import re
import struct

from layout import ABIError, require

SCHEMA_PATH = Path(__file__).resolve().parents[2] / 'docs/specifications/smir/portable/schema/abi/candidate.json'
SCHEMA = json.loads(SCHEMA_PATH.read_text())
RECORDS = SCHEMA['records']
MAX_BYTES = 8 * 1024 * 1024
MAX_COUNT = 10000
MAX_NODES = 200000
MAX_DEPTH = 128
TOKEN = re.compile(r'[a-z][a-z0-9_]{0,62}\Z', re.ASCII)
INTEGER = re.compile(r'([ui])(8|16|32|64)\Z')


def fields(kind, value):
    record = RECORDS[kind]
    if 'variants' in record:
        require(isinstance(value, dict) and value.get('kind') in record['variants'], 'ABI_WIRE_VARIANT')
        return record['variants'][value['kind']], 'kind'
    return record['fields'], None


def encode(kind, value):
    if kind == 'abi_contract':
        require(value.get('payload_revision') == 3, 'ABI_CC_REVISION')
    output = bytearray()
    nodes = 0

    def append(payload):
        require(len(output) + len(payload) <= MAX_BYTES, 'ABI_WIRE_LIMIT')
        output.extend(payload)

    def emit(kind, value, depth):
        nonlocal nodes
        nodes += 1
        require(depth <= MAX_DEPTH and nodes <= MAX_NODES, 'ABI_WIRE_LIMIT')
        match = INTEGER.fullmatch(kind)
        if match:
            bits = int(match[2])
            signed = match[1] == 'i'
            low = -(1 << (bits - 1)) if signed else 0
            high = (1 << (bits - int(signed))) - 1
            require(type(value) is int and low <= value <= high, 'ABI_WIRE_INTEGER')
            append(value.to_bytes(bits // 8, 'little', signed=signed))
            return
        if kind == 'bool':
            require(type(value) is bool, 'ABI_WIRE_BOOL')
            append(bytes([int(value)]))
            return
        if kind.startswith('opt:'):
            append(b'\0' if value is None else b'\1')
            if value is not None:
                require(isinstance(value, dict) and set(value) == {'some'}, 'ABI_WIRE_OPTION')
                emit(kind[4:], value['some'], depth + 1)
            return
        if kind.startswith('vec:'):
            require(isinstance(value, list) and len(value) <= MAX_COUNT, 'ABI_WIRE_COUNT')
            append(struct.pack('<I', len(value)))
            for item in value:
                emit(kind[4:], item, depth + 1)
            return
        if kind in ('bytes', 'hex', 'digest32'):
            if kind == 'bytes':
                require(isinstance(value, bytes), 'ABI_WIRE_BYTES')
                payload = value
            else:
                require(isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{2})*', value), 'ABI_WIRE_HEX')
                payload = bytes.fromhex(value)
            if kind == 'digest32':
                require(len(payload) == 32, 'ABI_WIRE_DIGEST')
            else:
                append(struct.pack('<I', len(payload)))
            append(payload)
            return
        if kind in ('utf8', 'token'):
            require(isinstance(value, str), 'ABI_WIRE_TEXT')
            try:
                payload = value.encode('utf8')
            except UnicodeError as error:
                raise ABIError('ABI_WIRE_UTF8') from error
            if kind == 'token':
                require(TOKEN.fullmatch(value) is not None, 'ABI_WIRE_TOKEN')
                append(bytes([len(payload)]))
            else:
                append(struct.pack('<I', len(payload)))
            append(payload)
            return
        require(kind in RECORDS and isinstance(value, dict), 'ABI_WIRE_RECORD')
        layout, discriminator = fields(kind, value)
        require(set(value) == {name for name, _ in layout} | ({discriminator} if discriminator else set()),
                'ABI_WIRE_FIELDS')
        if discriminator:
            emit('token', value[discriminator], depth + 1)
        for name, child in layout:
            emit(child, value[name], depth + 1)

    emit(kind, value, 0)
    return bytes(output)


def decode(kind, payload):
    require(isinstance(payload, bytes) and len(payload) <= MAX_BYTES, 'ABI_WIRE_LIMIT')
    if kind == 'abi_contract':
        require(len(payload) >= 4, 'ABI_WIRE_TRUNCATED')
        require(int.from_bytes(payload[:4], 'little') == 3, 'ABI_CC_REVISION')
    position = 0
    nodes = 0

    def take(count):
        nonlocal position
        require(0 <= count <= len(payload) - position, 'ABI_WIRE_TRUNCATED')
        result = payload[position:position + count]
        position += count
        return result

    def read(kind, depth):
        nonlocal nodes
        nodes += 1
        require(depth <= MAX_DEPTH and nodes <= MAX_NODES, 'ABI_WIRE_LIMIT')
        match = INTEGER.fullmatch(kind)
        if match:
            return int.from_bytes(take(int(match[2]) // 8), 'little', signed=match[1] == 'i')
        if kind == 'bool':
            value = take(1)[0]
            require(value in (0, 1), 'ABI_WIRE_BOOL')
            return bool(value)
        if kind.startswith('opt:'):
            tag = take(1)[0]
            require(tag in (0, 1), 'ABI_WIRE_OPTION')
            return {'some': read(kind[4:], depth + 1)} if tag else None
        if kind.startswith('vec:'):
            count = int.from_bytes(take(4), 'little')
            require(count <= MAX_COUNT, 'ABI_WIRE_COUNT')
            return [read(kind[4:], depth + 1) for _ in range(count)]
        if kind in ('digest32', 'bytes', 'hex'):
            count = 32 if kind == 'digest32' else int.from_bytes(take(4), 'little')
            value = take(count)
            return value if kind == 'bytes' else value.hex()
        if kind in ('utf8', 'token'):
            count = take(1)[0] if kind == 'token' else int.from_bytes(take(4), 'little')
            try:
                result = take(count).decode('utf8')
            except UnicodeError as error:
                raise ABIError('ABI_WIRE_UTF8') from error
            require(kind != 'token' or TOKEN.fullmatch(result) is not None, 'ABI_WIRE_TOKEN')
            return result
        require(kind in RECORDS, 'ABI_WIRE_RECORD')
        record = RECORDS[kind]
        result = {}
        if 'variants' in record:
            tag = read('token', depth + 1)
            require(tag in record['variants'], 'ABI_WIRE_VARIANT')
            result[record['discriminator']] = tag
            layout = record['variants'][tag]
        else:
            layout = record['fields']
        for name, child in layout:
            result[name] = read(child, depth + 1)
        return result

    result = read(kind, 0)
    require(position == len(payload), 'ABI_WIRE_TRAILING')
    return result
