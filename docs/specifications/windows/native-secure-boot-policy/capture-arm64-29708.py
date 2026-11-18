from ctypes import byref, c_int32, c_uint32, c_void_p, addressof, create_string_buffer, WinDLL
from pathlib import Path
import hashlib
import json
import os
import platform
import sys

version = list(sys.getwindowsversion()[:3])
machine = platform.machine().upper()
assert version == [10, 0, 29708] and machine == 'ARM64'
ntdll_path = Path(os.environ['SystemRoot']) / 'System32' / 'ntdll.dll'
ntdll_sha256 = hashlib.sha256(ntdll_path.read_bytes()).hexdigest()
assert ntdll_sha256 == 'ef1c9034813e18e5fb7cf6dc44802c15952d27dcecec46813ba883adda572f44'
query = WinDLL(str(ntdll_path)).NtQuerySystemInformation
query.argtypes = [c_uint32, c_void_p, c_uint32, c_void_p]
query.restype = c_int32
rows = []
for length in [0, 1, 8, 16, 23, 24, 25, 32, 64, 128]:
    for output_kind in ['null', 'aligned', 'misaligned']:
        for with_return in [False, True]:
            for poison in [0xA5, 0x5A]:
                out = create_string_buffer(bytes([poison]) * 160, 160)
                original = bytes(out)
                returned = c_uint32(0xDEADBEEF)
                ptr = (addressof(out) + (output_kind == 'misaligned')) if output_kind != 'null' else None
                assert ptr is None or ptr % 4 == (output_kind == 'misaligned')
                status = query(143, ptr, length, byref(returned) if with_return else None) & 0xFFFFFFFF
                data = bytes(out)
                offsets = [i for i, (before, after) in enumerate(zip(original, data)) if before != after]
                rows.append(dict(length=length, output=output_kind, with_return=with_return,
                                 poison=poison, status=status, returned=returned.value,
                                 changed_offsets=offsets,
                                 output_sha256=hashlib.sha256(data).hexdigest() if offsets else None))

aliases = []
for length in [0, 1, 23, 24, 25, 40]:
    for delta in [-4, 0, 4, 8, 20, 24, 28]:
        out = create_string_buffer(bytes([0xA5]) * 96, 96)
        ptr = addressof(out) + 16
        status = query(143, ptr, length, None) & 0xFFFFFFFF
        reference = bytes(out)
        for poison in [0xA5, 0x5A]:
            out = create_string_buffer(bytes([poison]) * 96, 96)
            ptr = addressof(out) + 16
            alias = ptr + delta
            aliased_status = query(143, ptr, length, alias) & 0xFFFFFFFF
            assert aliased_status == status
            expected = bytearray([poison] * 96)
            if status == 0:
                expected[16:40] = reference[16:40]
            expected[16+delta:20+delta] = (24).to_bytes(4, 'little')
            aliases.append(dict(length=length, delta=delta, poison=poison, status=status,
                                copy_then_length=bytes(out)==expected))
print(json.dumps(dict(version=version, machine=machine, ntdll_sha256=ntdll_sha256, cases=rows, aliases=aliases)), flush=True)
