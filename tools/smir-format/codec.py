#!/usr/bin/env python3
"""Independent draft SMIR envelope codec; no executable admission."""
import argparse
import json
from pathlib import Path
import struct

MAGIC = b'SMIR\r\n\x1a\n'
HEADER = struct.Struct('<8sHHHHIIQQII')
RECORD = struct.Struct('<HHIQQ')
NO_ENTRY = 0xffffffff


class DecodeError(ValueError):
    def __init__(self, number):
        super().__init__(f'SMIR-E{number:03}')


def decode(data, max_bytes=1 << 30, max_sections=1024):
    """Validate framing in O(bytes + sections) time, retaining payload bytes."""
    if len(data) > max_bytes:
        raise DecodeError(5)
    if len(data) < HEADER.size:
        raise DecodeError(1)
    magic, major, minor, kind, flags, profile, count, size, directory, entry, reserved = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise DecodeError(2)
    if (major, minor) != (0, 1):
        raise DecodeError(3)
    if kind not in (1, 2) or flags or profile != 1 or size != len(data) or directory != 48 or reserved or (kind == 1 and entry != NO_ENTRY):
        raise DecodeError(4)
    if count > max_sections:
        raise DecodeError(5)
    cursor = 48 + count * 24
    if cursor > len(data):
        raise DecodeError(6)
    previous = 0
    sections = []
    for index in range(count):
        tag, attributes, reserved, offset, length = RECORD.unpack_from(data, 48 + index * 24)
        if tag <= previous or attributes > 1 or reserved:
            raise DecodeError(6)
        known = 1 <= tag <= 9 or 0x8000 <= tag <= 0x8002
        if (not known and (tag < 0x8000 or attributes)) or (tag < 0x8000 and attributes != 1) or (tag >= 0x8000 and attributes):
            raise DecodeError(8)
        start = (cursor + 7) // 8 * 8
        end = offset + length
        if offset != start or end > len(data):
            raise DecodeError(7)
        if any(data[cursor:start]):
            raise DecodeError(9)
        sections.append({'kind': tag, 'required': bool(attributes), 'hex': data[offset:end].hex()})
        previous = tag
        cursor = end
    if cursor != len(data):
        raise DecodeError(9)
    return {'kind': kind, 'entry': entry, 'sections': sections}


def encode(module):
    """Emit canonical framing; input payloads remain semantically opaque."""
    sections = sorted(module['sections'], key=lambda section: section['kind'])
    cursor = 48 + len(sections) * 24
    directory = bytearray()
    body = bytearray()
    for section in sections:
        start = (cursor + 7) // 8 * 8
        payload = bytes.fromhex(section['hex'])
        directory.extend(RECORD.pack(section['kind'], int(section['required']), 0, start, len(payload)))
        body.extend(bytes(start - cursor))
        body.extend(payload)
        cursor = start + len(payload)
    result = HEADER.pack(MAGIC, 0, 1, module['kind'], 0, 1, len(sections), cursor, 48, module.get('entry', NO_ENTRY), 0) + directory + body
    decode(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('encode', 'inspect'))
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'encode':
            if args.output is None:
                parser.error('encode requires --output')
            args.output.write_bytes(encode(json.loads(args.input.read_text())))
        else:
            print(json.dumps(decode(args.input.read_bytes()), indent=2))
    except (ValueError, KeyError, struct.error) as error:
        parser.exit(2, f'{error}\n')


if __name__ == '__main__':
    main()
