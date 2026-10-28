"""Native64 exact pseudo-handle boundary in this disposable Python process."""

import ctypes
from ctypes import wintypes as w
import json
import os

k = ctypes.WinDLL("kernel32", use_last_error=True)
n = ctypes.WinDLL("ntdll")
k.VirtualAlloc.argtypes = [w.LPVOID, ctypes.c_size_t, w.DWORD, w.DWORD]
k.VirtualAlloc.restype = w.LPVOID
k.VirtualProtect.argtypes = [
    w.LPVOID,
    ctypes.c_size_t,
    w.DWORD,
    ctypes.POINTER(w.DWORD),
]
k.VirtualFree.argtypes = [w.LPVOID, ctypes.c_size_t, w.DWORD]
n.NtQueryInformationProcess.argtypes = [
    w.HANDLE,
    w.ULONG,
    w.LPVOID,
    w.ULONG,
    ctypes.POINTER(w.ULONG),
]
n.NtQueryInformationProcess.restype = w.LONG
n.NtSetInformationProcess.argtypes = [w.HANDLE, w.ULONG, w.LPVOID, w.ULONG]
n.NtSetInformationProcess.restype = w.LONG


def policy():
    flags = w.ULONG()
    returned = w.ULONG()
    assert (
        n.NtQueryInformationProcess(
            w.HANDLE(-1), 34, ctypes.byref(flags), 4, ctypes.byref(returned)
        )
        == 0
    )
    assert returned.value == 4
    return flags.value


assert ctypes.sizeof(w.HANDLE) == 8 and policy() == 13
rows = []
for handle in (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0x1FFFFFFFF, 0xFFFFFFFF00000000):
    for guard in (False, True):
        memory = k.VirtualAlloc(None, 4096, 0x3000, 4)
        assert memory
        w.ULONG.from_address(memory).value = 10
        old = w.DWORD()
        try:
            if guard:
                assert k.VirtualProtect(memory, 4096, 0x104, ctypes.byref(old))
            status = (
                n.NtSetInformationProcess(w.HANDLE(handle), 34, memory, 4) & 0xFFFFFFFF
            )
            assert k.VirtualProtect(memory, 4096, 4, ctypes.byref(old))
            rows.append(
                {
                    "handle": handle,
                    "guard": guard,
                    "status": status,
                    "remaining_protection": old.value,
                    "input": w.ULONG.from_address(memory).value,
                    "policy_after": policy(),
                }
            )
        finally:
            assert k.VirtualFree(memory, 0, 0x8000)
assert policy() == 13
print(json.dumps({"pid": os.getpid(), "pointer_bytes": 8, "rows": rows}))
