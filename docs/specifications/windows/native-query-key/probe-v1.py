"""Read-only native NtQueryKey survey; no registry mutation or privilege changes."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import struct
import sys

n = c.WinDLL('ntdll', use_last_error=True)
k = c.WinDLL('kernel32', use_last_error=True)
a = c.WinDLL('advapi32', use_last_error=True)
class US(c.Structure):
    _fields_ = [('Length', w.USHORT), ('MaximumLength', w.USHORT), ('Buffer', c.c_void_p)]
class OA(c.Structure):
    _fields_ = [('Length', w.ULONG), ('RootDirectory', w.HANDLE), ('ObjectName', c.POINTER(US)), ('Attributes', w.ULONG), ('SecurityDescriptor', c.c_void_p), ('SecurityQualityOfService', c.c_void_p)]
n.NtOpenKey.argtypes = [c.POINTER(w.HANDLE), w.ULONG, c.POINTER(OA)]
n.NtOpenKey.restype = c.c_long
n.NtQueryKey.argtypes = [w.HANDLE, w.ULONG, c.c_void_p, w.ULONG, c.c_void_p]
n.NtQueryKey.restype = c.c_long
n.NtClose.argtypes = [w.HANDLE]
n.NtClose.restype = c.c_long
k.GetCurrentProcess.restype = w.HANDLE
k.DuplicateHandle.argtypes = [w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
k.DuplicateHandle.restype = w.BOOL
k.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
k.CreateEventW.restype = w.HANDLE
k.IsWow64Process2.argtypes = [w.HANDLE, c.POINTER(w.USHORT), c.POINTER(w.USHORT)]
k.IsWow64Process2.restype = w.BOOL
pm, nm = w.USHORT(), w.USHORT()
assert k.IsWow64Process2(k.GetCurrentProcess(), c.byref(pm), c.byref(nm))
result = dict(source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), pointer_bytes=c.sizeof(c.c_void_p), kernel=list(sys.getwindowsversion()), native_machine=nm.value, process_machine=pm.value, rows=[])
handles = []
def open_key(path, access):
    text = c.create_unicode_buffer(path)
    us = US(len(path.encode('utf-16-le')), len(path.encode('utf-16-le')) + 2, c.cast(text, c.c_void_p))
    oa = OA(c.sizeof(OA), None, c.pointer(us), 0x240, None, None)
    h = w.HANDLE()
    status = n.NtOpenKey(c.byref(h), access, c.byref(oa)) & 0xffffffff
    result['rows'].append(dict(kind='open', path=path, access=access, status=status, handle=h.value))
    assert status == 0
    handles.append(h.value)
    return h.value

def query(label, h, cls, length, out_offset=0, result_offset=0, null_out=False, null_result=False):
    out = (c.c_ubyte * 8192)(*([0xa5] * 8192))
    ret = (c.c_ubyte * 16)(*([0xa5] * 16))
    op = None if null_out else c.addressof(out) + out_offset
    rp = None if null_result else c.addressof(ret) + result_offset
    c.set_last_error(0x12345678)
    status = n.NtQueryKey(h, cls, op, length, rp) & 0xffffffff
    result['rows'].append(dict(kind='query', label=label, handle=h, cls=cls, length=length, out_offset=out_offset, result_offset=result_offset, null_out=null_out, null_result=null_result, status=status, last_error=c.get_last_error(), returned_bytes=bytes(ret).hex(), output=bytes(out[:min(512, max(length + 8, 32))]).hex()))

try:
    paths = [r'\Registry\User\.DEFAULT', r'\Registry\Machine\System\CurrentControlSet\Control\Nls\CodePage']
    for path in paths:
        h = open_key(path, 0x20019)
        for cls in range(12):
            for length in [0, 1, 3, 4, 8, 16, 32, 64, 4096]:
                query(path, h, cls, length)
        for access in [0, 1, 8, 0x10, 0x20000]:
            d = w.HANDLE()
            assert k.DuplicateHandle(k.GetCurrentProcess(), h, k.GetCurrentProcess(), c.byref(d), access, False, 0)
            handles.append(d.value)
            for cls in [0, 1, 2, 3, 4, 6, 7, 8, 9]:
                query('duplicate-access-' + hex(access), d.value, cls, 4096)
        for tag in range(4):
            query('handle-low-bits-' + str(tag), h | tag, 7, 4)
        for cls in [0, 3, 7, 10]:
            for label, current in [('valid', h), ('null', 0), ('invalid', 0xdeadbee0), ('process', -1), ('thread', -2)]:
                for length in [0, 3, 4, 64]:
                    query(label, current, cls, length)
                    query(label + '-null-output', current, cls, length, null_out=True)
                    query(label + '-null-result', current, cls, length, null_result=True)
            for offset in [1, 2, 3]:
                query('unaligned-output', h, cls, 64, out_offset=offset)
                query('unaligned-result', h, cls, 64, result_offset=offset)
    event = k.CreateEventW(None, True, False, None)
    assert event
    handles.append(event)
    for cls in range(12):
        query('event', event, cls, 4096)
finally:
    for h in reversed(handles):
        assert n.NtClose(h) == 0
print(json.dumps(result))
