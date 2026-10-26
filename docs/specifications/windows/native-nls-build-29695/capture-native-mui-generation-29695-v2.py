"""Measure the fixed shared language counter alongside query-only MUI data."""

from pathlib import Path
import ctypes
import hashlib
import json

R = Path("C:/Windows/Temp/assist-native-rax-20261010/src-display-candidate1")
OUT = R / "target/native-nls-29695-wow64-v1/generation"
assert not OUT.exists()
OUT.mkdir()
kernel = ctypes.WinDLL("kernel32")
read = kernel.ReadProcessMemory
read.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
]
read.restype = ctypes.c_int32
query = ctypes.WinDLL("ntdll").NtGetMUIRegistryInfo
query.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
query.restype = ctypes.c_int32


def generation():
    value = ctypes.c_uint32()
    got = ctypes.c_size_t()
    assert read(
        ctypes.c_void_p(-1), 0x7FFE03A4, ctypes.byref(value), 4, ctypes.byref(got)
    )
    assert got.value == 4
    return value.value


rows = []
for _ in range(3):
    before = generation()
    size = ctypes.c_uint32()
    assert query(0, ctypes.byref(size), None) == 0
    assert 16 <= size.value <= 1048576
    data = (ctypes.c_ubyte * size.value)()
    capacity = size.value
    assert query(0, ctypes.byref(size), ctypes.addressof(data)) == 0
    assert size.value == capacity
    raw = bytes(data)
    rows.append(
        {
            "shared-before": before,
            "payload-generation": int.from_bytes(raw[12:16], "little"),
            "shared-after": generation(),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
record = {
    "state": "finished",
    "kernel": list(__import__("sys").getwindowsversion()),
    "pid": __import__("os").getpid(),
    "scope": "Fixed readonly shared-page location plus query flags0; no cache mutation.",
    "rows": rows,
}
(OUT / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record))
