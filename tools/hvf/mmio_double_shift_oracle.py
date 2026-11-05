#!/usr/bin/env python3
"""Independent KVM SHLD/SHRD memory effects, including CL/source aliasing.

Defined-result cases use Intel SDM086 Vol.2B4-636/637 and4-639/640.
Masked16-bit counts17..31 have undefined data/flags and belong to separate
admission/footprint controls, not fixed-value reference comparisons.
"""
import struct

import mmio_shift_oracle as shared


def corpus(exhaustive=False):
    cases = bytearray()
    for right in [False, True]:
        for size in [2, 4, 8]:
            bits = size * 8
            mask = (1 << bits) - 1
            counts = range(256) if exhaustive else [
                0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255
            ]
            patterns = [0, 1, 1 << (bits - 1), mask,
                        0xa55aa55aa55aa55a, 0x5aa55aa55aa55aa5]
            for form in ['immediate', 'cl']:
                for count in counts:
                    effective = count & (63 if size == 8 else 31)
                    if effective > bits:
                        continue
                    for source in [0, 1, 8, 15]:
                        prefix = [0x66] if size == 2 else []
                        rex = (8 if size == 8 else 0) | (4 if source >= 8 else 0)
                        if rex:
                            prefix.append(0x40 | rex)
                        opcode = (0xac if right else 0xa4) + (form == 'cl')
                        code = bytes(prefix + [0x0f, opcode, ((source & 7) << 3) | 7]
                                     + ([count] if form == 'immediate' else []))
                        undefined = ((0x10 if effective else 0)
                                     | (0x800 if effective > 1 else 0))
                        for old in patterns:
                            for source_value in [0, mask, 0x39c65aa5f00fc33c]:
                                for flags in [2, 0x8d7]:
                                    registers = [0x123456789abcdef0 ^ (i * 0x0101010101010101)
                                                 for i in range(16)]
                                    registers[4], registers[7] = 0x400000, 0x200000
                                    registers[source] = source_value
                                    if form == 'cl':
                                        registers[1] = (registers[1] & ~255) | count
                                    cases.extend(struct.pack(
                                        '<16QQQI16siI', *registers, old, flags,
                                        len(code), code, 0, 0xffffffff ^ undefined))
    return bytes(cases)


def validate_records(cases, records):
    """Check raw native data against SDM formulas without linking RAX code."""
    count = len(cases) // 172
    assert len(cases) == count * 172 and len(records) == 20 + count * 168
    assert records[:8] == b'RAXRM001' and records[-8:] == b'RM_DONE!'
    assert struct.unpack_from('<I', records, 8)[0] == count
    for index in range(count):
        row = struct.unpack_from('<16QQQI16siI', cases, index * 172)
        registers, old, before = row[:16], row[16], row[17]
        code = row[19][:row[18]]
        position = int(code[0] == 0x66)
        size = 2 if position else 4
        rex = 0
        if 0x40 <= code[position] <= 0x4f:
            rex = code[position]
            position += 1
        if rex & 8:
            size = 8
        assert code[position] == 0x0f
        opcode, modrm = code[position + 1:position + 3]
        assert opcode in [0xa4, 0xa5, 0xac, 0xad] and modrm & 0xc7 == 7
        source = ((modrm >> 3) & 7) + (8 if rex & 4 else 0)
        raw_count = registers[1] & 255 if opcode & 1 else code[position + 3]
        width = size * 8
        effective = raw_count & (63 if size == 8 else 31)
        assert effective <= width, 'undefined results require separate controls'
        mask = (1 << width) - 1
        dest, src = old & mask, registers[source] & mask
        result, flags = dest, before
        if effective:
            right = bool(opcode & 8)
            if right:
                result = ((dest >> effective) | (src << (width - effective))) & mask
                carry = (dest >> (effective - 1)) & 1
            else:
                result = ((dest << effective) | (src >> (width - effective))) & mask
                carry = (dest >> (width - effective)) & 1
            flags &= ~0xc5
            flags |= carry | (0x80 if result >> (width - 1) else 0)
            flags |= (0x40 if result == 0 else 0)
            flags |= (4 if (result & 255).bit_count() % 2 == 0 else 0)
            if effective == 1:
                flags = (flags & ~0x800) | (0x800 if (dest ^ result) >> (width - 1) else 0)
        actual = struct.unpack_from('<21Q', records, 12 + index * 168)
        assert tuple(actual[:16]) == tuple(registers), (index, 'registers')
        assert tuple(actual[16:19]) == (old, (old & ~mask) | result, old), (index, 'memory')
        assert actual[19] == before, (index, 'input flags')
        assert (actual[20] ^ flags) & row[21] == 0, (index, 'defined flags')


def main():
    shared.main(
        corpus_fn=corpus, fixture_name='mmio-double-shifts-v1',
        scope=('Physical Linux x86-64 KVM SHLD/SHRD RAM instructions; no RAX code linked. '
               'All16GPRs,24memory bytes,defined/unaffected flags checked against SDM086. '
               'No HVF exits, device ordering or fixed-value claim for undefined16-bit counts.'),
        extra_sources={'tools/hvf/mmio_double_shift_oracle.py': shared.sha(__file__)},
        validate_records=validate_records, description=__doc__)


if __name__ == '__main__':
    main()
