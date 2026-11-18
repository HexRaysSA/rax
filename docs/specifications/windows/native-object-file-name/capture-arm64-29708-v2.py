from ctypes import *
from ctypes.wintypes import DWORD, HANDLE, LPCWSTR, LPWSTR
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
nsha = hashlib.sha256(ntdll_path.read_bytes()).hexdigest()
assert nsha == 'ef1c9034813e18e5fb7cf6dc44802c15952d27dcecec46813ba883adda572f44'
query = WinDLL(str(ntdll_path)).NtQueryObject
query.argtypes = [HANDLE, DWORD, c_void_p, DWORD, c_void_p]
query.restype = c_int32
api = WinDLL('kernel32')
create = api.CreateFileW
create.argtypes = [LPCWSTR, DWORD, DWORD, c_void_p, DWORD, DWORD, HANDLE]
create.restype = HANDLE
get = api.GetFinalPathNameByHandleW
get.argtypes = [HANDLE, LPWSTR, DWORD, DWORD]
get.restype = DWORD
close = api.CloseHandle
close.argtypes = [HANDLE]
close.restype = c_int
home = Path(sys.argv[1]).resolve(strict=True)
assert home.is_dir()
folder = home / '.native-owned-object-file-name-29708-v2'
folder.mkdir()
(folder/'.owner').write_text('native-owned-object-file-name-29708-v2\n')
file = folder / 'Owned Fixture \u03b1.txt'
file.write_text('rax local query fixture\n', encoding='utf-8')
handle = create(str(file), 0x80000000, 7, None, 3, 0x80, None)
assert handle and handle != c_void_p(-1).value
invalid = create(str(file), 0x80000000, 7, None, 3, 0x80, None)
assert invalid and invalid != c_void_p(-1).value and close(invalid)

def invoke(subject, data, align, length, returned):
    dst = None if align is None else addressof(data) + align
    rc = query(subject, 1, dst, length, returned) & 0xffffffff
    return rc, dst

try:
    data = create_string_buffer(1024)
    needed = c_uint32(0xffffffff)
    rc, dst = invoke(handle, data, 0, 1024, byref(needed))
    assert rc == 0
    reference = bytes(data)
    namelen = int.from_bytes(reference[:2], 'little')
    maximum = int.from_bytes(reference[2:4], 'little')
    addr = int.from_bytes(reference[8:16], 'little')
    assert 16 <= addr - dst <= needed.value < 1024
    assert namelen + 2 == maximum and b'\x00\x00' == reference[addr-dst+namelen:addr-dst+maximum]
    path = reference[addr-dst:addr-dst+namelen].decode('utf-16-le')
    nt = create_unicode_buffer(1024)
    size = get(handle, nt, 1024, 10)
    assert 0 < size < 1024
    assert path.startswith('\\Device\\') and path.endswith('\\'+file.name)
    def projected(current, align, poison):
        if align is None:
            return None
        raw = bytes(current)[align:align+16]
        address = int.from_bytes(raw[8:16], 'little')
        offset = address-(addressof(current)+align)
        return dict(length=int.from_bytes(raw[:2], 'little'), max=int.from_bytes(raw[2:4], 'little'),
                    padding=raw[4:8].hex(), pointer_offset=offset if -1024 <= offset <= 1024 else None,
                    header_written=[i for i,val in enumerate(raw) if val!=poison])

    thresholds = []
    for length in range(12, needed.value + 9):
        row = dict(length=length)
        for out_align in (0,4):
            buf = create_string_buffer(bytes([0xA5]) * 1024, 1024)
            ret = c_uint32(0xDEADBEEF)
            status, _ = invoke(handle, buf, out_align, length, byref(ret))
            rec = projected(buf, out_align, 0xA5)
            row[str(out_align)] = dict(status=status, returned=ret.value,
                length=rec['length'] if rec['pointer_offset'] is not None else None,
                maximum=rec['max'] if rec['pointer_offset'] is not None else None,
                pad_unchanged=rec['padding']=='a5a5a5a5')
        thresholds.append(row)
    aliases = []
    for length in [0, 15, 16, 30, 60, needed.value-1, needed.value, needed.value+1, 500]:
        for delta in [-4, 0, 4, 8, 16, 20, needed.value-2, needed.value]:
            for poison in (0xA5,0x5A):
                probe = create_string_buffer(bytes([poison])*1024,1024)
                separate = c_uint32(0xDEADBEEF)
                status, ptr = invoke(handle,probe,32,length,byref(separate))
                expected = bytearray(bytes(probe))
                raw_ptr = int.from_bytes(expected[40:48],'little')
                buffer_fixup = raw_ptr == ptr + 16
                probe2 = create_string_buffer(bytes([poison])*1024,1024)
                addr2 = addressof(probe2)+32
                status2, _ = invoke(handle,probe2,32,length,addr2+delta)
                assert status2==status
                if buffer_fixup:
                    expected[40:48]=(addr2+16).to_bytes(8,'little')
                expected[32+delta:36+delta]=separate.value.to_bytes(4,'little')
                aliases.append(dict(length=length,delta=delta,poison=poison,status=status,
                    after_payload=bytes(probe2)==expected))
    print(json.dumps(dict(version=version,machine=machine,ntdll_sha256=nsha,name_bytes=namelen,
         maximum_bytes=maximum,needed=needed.value,record_buffer_offset=addr-dst,
         opened_name_matches=path==nt.value,thresholds=thresholds,aliases=aliases)),flush=True)

finally:
    assert close(handle)
