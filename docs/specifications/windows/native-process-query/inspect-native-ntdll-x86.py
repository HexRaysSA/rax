"""Inspect retained byte signatures from an installed x86 NTDLL (no execution)."""
import hashlib
from pathlib import Path
import struct
import sys

image = Path(sys.argv[1]).read_bytes()
print('bytes', len(image), 'sha256', hashlib.sha256(image).hexdigest())
u16 = lambda at: struct.unpack_from('<H', image, at)[0]
u32 = lambda at: struct.unpack_from('<I', image, at)[0]
pe = u32(0x3C)
assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\x00\x00'
optional = pe + 24
assert u16(pe + 4) == 0x14C and u16(optional) == 0x10B
base = u32(optional + 28)
section_table = optional + u16(pe + 20)
sections = []
for index in range(u16(pe + 6)):
    at = section_table + index * 40
    sections.append((u32(at + 12), u32(at + 16), u32(at + 20)))

def offset(rva):
    for start, size, raw in sections:
        if start <= rva < start + size:
            return raw + rva - start
    raise ValueError(f'unbacked RVA {rva:#x}')

exports = offset(u32(optional + 96))
functions = offset(u32(exports + 28))
names = offset(u32(exports + 32))
ordinals = offset(u32(exports + 36))
selected = {'NtQueryInformationProcess', 'NtClose', 'NtQuerySystemInformation',
            'Wow64Transition', 'RtlEncodePointer', 'RtlDecodePointer'}
for index in range(u32(exports + 24)):
    at = offset(u32(names + index * 4))
    name = image[at:image.index(0, at)].decode('ascii')
    if name in selected:
        ordinal = u16(ordinals + index * 2)
        rva = u32(functions + ordinal * 4)
        raw = offset(rva)
        print(name, 'preferred', hex(base + rva), 'rva', hex(rva),
              'bytes', image[raw:raw + 64].hex(' '))
