"""Bounded file-based draft ELF64/Mach-O64/PE32+ payload discovery.

Never maps executable memory. Thin little-endian x86-64/AArch64 wrappers only.
Malformed native metadata rejects even if an opaque SMIR envelope is embedded.
"""
import struct

from package import decode_locator
from schema import require


class Reader:
    def __init__(self, data):
        self.data = data

    def take(self, offset, size):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset,
                'CARRIER_BOUNDS')
        return self.data[offset:offset + size]

    def integer(self, offset, width):
        return int.from_bytes(self.take(offset, width), 'little')


def _elf(reader):
    require(reader.take(0, 7) == b'\x7fELF\x02\x01\x01', 'ELF_PROFILE')
    require(reader.integer(16, 2) in {2, 3} and reader.integer(18, 2) in {62, 183},
            'ELF_MACHINE')
    require(reader.integer(52, 2) == 64 and reader.integer(54, 2) == 56, 'ELF_HEADER')
    count = reader.integer(56, 2)
    require(count != 0xffff and count <= 4096, 'ELF_HEADER_COUNT')
    offset = reader.integer(32, 8)
    reader.take(offset, count * 56)
    candidates = []
    regions = []
    for index in range(count):
        at = offset + index * 56
        kind = reader.integer(at, 4)
        flags = reader.integer(at + 4, 4)
        start = reader.integer(at + 8, 8)
        size = reader.integer(at + 32, 8)
        reader.take(start, size)
        if kind == 1:
            regions.append((start, start + size, flags == 4))
        if kind != 4:
            continue
        require(flags == 4, 'CARRIER_PERMISSIONS')
        cursor = start
        while cursor < start + size:
            require(start + size - cursor >= 12, 'ELF_NOTE_HEADER')
            namesz = reader.integer(cursor, 4)
            descsz = reader.integer(cursor + 4, 4)
            note_type = reader.integer(cursor + 8, 4)
            name_at = cursor + 12
            desc_at = (name_at + namesz + 3) & ~3
            end = (desc_at + descsz + 3) & ~3
            require(end <= start + size, 'ELF_NOTE_BOUNDS')
            name = reader.take(name_at, namesz)
            require(not any(reader.take(name_at + namesz, desc_at - name_at - namesz)),
                    'ELF_NOTE_PADDING')
            require(not any(reader.take(desc_at + descsz, end - desc_at - descsz)),
                    'ELF_NOTE_PADDING')
            if name == b'RAXSMIR\0':
                require(note_type == 1 and descsz == 64, 'ELF_NOTE_TYPE')
                candidates.append(desc_at)
            cursor = end
    return candidates, regions


def _macho(reader):
    require(reader.integer(0, 4) == 0xfeedfacf, 'MACHO_PROFILE')
    require(reader.integer(4, 4) in {0x01000007, 0x0100000c} and
            reader.integer(12, 4) in {2, 6}, 'MACHO_MACHINE')
    count = reader.integer(16, 4)
    command_bytes = reader.integer(20, 4)
    require(count <= 4096, 'MACHO_COMMAND_COUNT')
    reader.take(32, command_bytes)
    cursor = 32
    candidates = []
    regions = []
    for _ in range(count):
        kind = reader.integer(cursor, 4)
        size = reader.integer(cursor + 4, 4)
        require(size >= 8 and size % 8 == 0 and cursor + size <= 32 + command_bytes,
                'MACHO_COMMAND_SIZE')
        if kind == 0x19:
            require(size >= 72, 'MACHO_SEGMENT_SIZE')
            section_count = reader.integer(cursor + 64, 4)
            require(size == 72 + 80 * section_count, 'MACHO_SECTION_COUNT')
            file_offset = reader.integer(cursor + 40, 8)
            file_size = reader.integer(cursor + 48, 8)
            reader.take(file_offset, file_size)
            maxprot = reader.integer(cursor + 56, 4)
            initprot = reader.integer(cursor + 60, 4)
            readonly = maxprot == initprot == 1
            regions.append((file_offset, file_offset + file_size, readonly))
            for index in range(section_count):
                at = cursor + 72 + index * 80
                name = reader.take(at, 16).rstrip(b'\0')
                segment = reader.take(at + 16, 16).rstrip(b'\0')
                if name == b'__module' and segment == b'__SMIR':
                    require(reader.take(cursor + 8, 16).rstrip(b'\0') == b'__SMIR',
                            'MACHO_SEGMENT_NAME')
                    start = reader.integer(at + 48, 4)
                    length = reader.integer(at + 40, 8)
                    require(file_offset <= start and start + length <= file_offset + file_size,
                            'MACHO_SECTION_BOUNDS')
                    require(length >= 64 and reader.integer(at + 64, 4) == 0,
                            'MACHO_SECTION_FLAGS')
                    require(readonly, 'CARRIER_PERMISSIONS')
                    candidates.append(start)
        cursor += size
    require(cursor == 32 + command_bytes, 'MACHO_COMMAND_END')
    return candidates, regions


def _pe(reader):
    require(reader.take(0, 2) == b'MZ', 'PE_PROFILE')
    pe = reader.integer(60, 4)
    require(reader.take(pe, 4) == b'PE\0\0', 'PE_SIGNATURE')
    require(reader.integer(pe + 4, 2) in {0x8664, 0xaa64}, 'PE_MACHINE')
    count = reader.integer(pe + 6, 2)
    optional_size = reader.integer(pe + 20, 2)
    require(count <= 4096 and optional_size >= 112, 'PE_HEADER')
    reader.take(pe + 24, optional_size)
    require(reader.integer(pe + 24, 2) == 0x20b, 'PE_OPTIONAL_HEADER')
    start = pe + 24 + optional_size
    reader.take(start, count * 40)
    candidates = []
    regions = []
    for index in range(count):
        at = start + index * 40
        name = reader.take(at, 8).rstrip(b'\0')
        size = reader.integer(at + 16, 4)
        offset = reader.integer(at + 20, 4)
        flags = reader.integer(at + 36, 4)
        reader.take(offset, size)
        readonly = bool(flags & 0x40000000) and flags & 0xa2000000 == 0
        regions.append((offset, offset + size, readonly))
        if name == b'.smir':
            require(size >= 64 and readonly and flags & 0x40 != 0, 'CARRIER_PERMISSIONS')
            candidates.append(offset)
    return candidates, regions


def inspect(data, carrier):
    reader = Reader(data)
    require(carrier in {'elf', 'macho', 'pe'}, 'CARRIER_KIND')
    candidates, regions = {'elf': _elf, 'macho': _macho, 'pe': _pe}[carrier](reader)
    require(len(candidates) == 1, 'LOCATOR_AMBIGUOUS')
    at = candidates[0]
    record = reader.take(at, 64)
    # Refuse overlap of payload with ANY writable/executable load region.
    offset, length = struct.unpack_from('<QQ', record, 16)
    end = offset + length
    require(any(a <= offset and end <= b and readonly for a, b, readonly in regions),
            'PAYLOAD_NOT_READONLY')
    require(all(end <= a or b <= offset or readonly for a, b, readonly in regions),
            'PAYLOAD_ALIAS_PERMISSIONS')
    payload = decode_locator(record, data, (at, at + 64))
    return {'payload': payload, 'offset': offset, 'length': length, 'sha256': record[32:64].hex()}


def extract(data, carrier):
    return inspect(data, carrier)['payload']
