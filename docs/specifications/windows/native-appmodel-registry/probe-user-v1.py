"""Fixed query-only next-frontier controls; no keys or settings are written."""

import ctypes, json, platform, sys
from ctypes import wintypes as w


class Unicode(ctypes.Structure):
    _fields_ = [("length", w.USHORT), ("maximum", w.USHORT), ("buffer", w.LPWSTR)]


class Attributes(ctypes.Structure):
    _fields_ = [
        ("length", w.ULONG),
        ("root", w.HANDLE),
        ("name", ctypes.POINTER(Unicode)),
        ("flags", w.ULONG),
        ("security", w.LPVOID),
        ("qos", w.LPVOID),
    ]


class Version(ctypes.Structure):
    _fields_ = [
        ("size", w.DWORD),
        ("major", w.DWORD),
        ("minor", w.DWORD),
        ("build", w.DWORD),
        ("platform", w.DWORD),
        ("csd", w.WCHAR * 128),
    ]


n = ctypes.WinDLL("ntdll")
a = ctypes.WinDLL("advapi32")
k = ctypes.WinDLL("kernel32")
n.NtOpenKey.argtypes = [ctypes.POINTER(w.HANDLE), w.ULONG, ctypes.POINTER(Attributes)]
n.NtOpenKey.restype = w.LONG
n.NtClose.argtypes = [w.HANDLE]
n.NtClose.restype = w.LONG
n.RtlGetVersion.argtypes = [ctypes.POINTER(Version)]
n.RtlGetVersion.restype = w.LONG
k.GetCurrentProcess.restype = w.HANDLE
k.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
k.IsWow64Process2.argtypes = [
    w.HANDLE,
    ctypes.POINTER(w.USHORT),
    ctypes.POINTER(w.USHORT),
]
a.RegOpenKeyExW.argtypes = [
    w.HANDLE,
    w.LPCWSTR,
    w.DWORD,
    w.DWORD,
    ctypes.POINTER(w.HANDLE),
]
a.RegOpenKeyExW.restype = w.LONG
a.RegCloseKey.argtypes = [w.HANDLE]
a.RegCloseKey.restype = w.LONG
v = Version()
v.size = ctypes.sizeof(v)
assert n.RtlGetVersion(ctypes.byref(v)) == 0
process = w.USHORT()
native = w.USHORT()
assert k.IsWow64Process2(
    k.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native)
)
assert native.value == 0xAA64 and process.value == 0 and ctypes.sizeof(Attributes) == 48
before = w.DWORD()
assert k.GetProcessHandleCount(k.GetCurrentProcess(), ctypes.byref(before))
rows = []
for leaf in ["machine", "user"]:
    path = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\AppModel\\Lookaside\\" + leaf
    for view in [0, 0x100, 0x200, 0x300]:
        text = ctypes.create_unicode_buffer(path)
        u = Unicode(
            len(path.encode("utf-16-le")),
            ctypes.sizeof(text),
            ctypes.cast(text, w.LPWSTR),
        )
        attrs = Attributes(
            ctypes.sizeof(Attributes), None, ctypes.pointer(u), 0x40, None, None
        )
        h = w.HANDLE()
        status = (
            n.NtOpenKey(ctypes.byref(h), 0x80000000 | view, ctypes.byref(attrs))
            & 0xFFFFFFFF
        )
        if status == 0:
            assert h.value and n.NtClose(h) == 0
        rows.append({"leaf": leaf, "api": "NtOpenKey", "view": view, "status": status})
    for view in [0, 0x100, 0x200]:
        h = w.HANDLE()
        status = a.RegOpenKeyExW(
            w.HANDLE(-2147483646),
            path[len("\\Registry\\Machine\\") :],
            0,
            9 | view,
            ctypes.byref(h),
        )
        if status == 0:
            assert h.value and a.RegCloseKey(h) == 0
        rows.append(
            {"leaf": leaf, "api": "RegOpenKeyExW", "view": view, "status": status}
        )
after = w.DWORD()
assert k.GetProcessHandleCount(k.GetCurrentProcess(), ctypes.byref(after))
assert before.value == after.value
print(
    json.dumps(
        {
            "kernel": [v.major, v.minor, v.build],
            "native_machine": native.value,
            "process_machine": process.value,
            "pointer_bytes": ctypes.sizeof(w.HANDLE),
            "handles_before": before.value,
            "handles_after": after.value,
            "rows": rows,
        }
    )
)
