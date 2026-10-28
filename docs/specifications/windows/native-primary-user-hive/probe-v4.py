from pathlib import Path
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
import struct
import sys
import traceback

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path)
parser.add_argument('--require-native-machine', type=lambda value: int(value, 0))
args = parser.parse_args()
ROOT = Path(__file__).resolve().parents[4]
OUT = (args.output or ROOT / 'target/native-primary-user-hive-v4').resolve()
assert OUT.is_relative_to(ROOT) and OUT != ROOT
OUT.mkdir(parents=True, exist_ok=False)
state = {"pid": os.getpid(), "state": "starting", "rows": []}
def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save():
    (OUT / "receipt.json").write_text(json.dumps(state, indent=2))

try:
    state.update(source_sha256=digest(__file__), python_sha256=digest(sys.executable),
                 kernel=list(sys.getwindowsversion()), pointer_bytes=c.sizeof(c.c_void_p))
    assert c.sizeof(c.c_void_p) == 8 and c.sizeof(c.c_wchar) == 2
    n = c.WinDLL("ntdll", use_last_error=True)
    k = c.WinDLL("kernel32", use_last_error=True)
    a = c.WinDLL("advapi32", use_last_error=True)
    class US(c.Structure):
        _fields_ = [("Length", w.USHORT), ("MaximumLength", w.USHORT), ("Buffer", c.c_void_p)]
    class OA(c.Structure):
        _fields_ = [("Length", w.ULONG), ("RootDirectory", w.HANDLE),
                    ("ObjectName", c.POINTER(US)), ("Attributes", w.ULONG),
                    ("SecurityDescriptor", c.c_void_p), ("SecurityQualityOfService", c.c_void_p)]
    assert c.sizeof(US) == 16 and c.sizeof(OA) == 48
    n.NtOpenKey.argtypes = [c.POINTER(w.HANDLE), w.ULONG, c.POINTER(OA)]
    n.NtOpenKey.restype = c.c_long
    n.NtQueryKey.argtypes = [w.HANDLE, w.ULONG, c.c_void_p, w.ULONG, c.POINTER(w.ULONG)]
    n.NtQueryKey.restype = c.c_long
    n.NtQueryObject.argtypes = n.NtQueryKey.argtypes
    n.NtQueryObject.restype = c.c_long
    n.NtClose.argtypes = [w.HANDLE]
    n.NtClose.restype = c.c_long
    k.GetCurrentProcess.restype = w.HANDLE
    k.IsWow64Process2.argtypes = [w.HANDLE, c.POINTER(w.USHORT), c.POINTER(w.USHORT)]
    k.IsWow64Process2.restype = w.BOOL
    process_machine, native_machine = w.USHORT(), w.USHORT()
    assert k.IsWow64Process2(k.GetCurrentProcess(), c.byref(process_machine), c.byref(native_machine))
    state.update(process_machine=process_machine.value, native_machine=native_machine.value,
                 python_version=sys.version)
    assert process_machine.value == 0 and native_machine.value in [0x8664, 0xAA64]
    if args.require_native_machine is not None:
        assert native_machine.value == args.require_native_machine
    class OSV(c.Structure):
        _fields_ = [("size", w.DWORD), ("major", w.DWORD), ("minor", w.DWORD),
                    ("build", w.DWORD), ("platform", w.DWORD), ("service_pack", c.c_wchar * 128)]
    version = OSV()
    version.size = c.sizeof(OSV)
    n.RtlGetVersion.argtypes = [c.POINTER(OSV)]
    n.RtlGetVersion.restype = c.c_long
    assert n.RtlGetVersion(c.byref(version)) == 0
    state["rtl_version"] = {field: getattr(version, field) for field in ["major", "minor", "build", "platform", "service_pack"]}
    k.CloseHandle.argtypes = [w.HANDLE]
    k.CloseHandle.restype = w.BOOL
    k.GetModuleFileNameW.argtypes = [w.HMODULE, w.LPWSTR, w.DWORD]
    k.GetModuleFileNameW.restype = w.DWORD
    path = c.create_unicode_buffer(32768)
    used = k.GetModuleFileNameW(n._handle, path, len(path))
    assert 0 < used < len(path)
    state.update(ntdll_path=path.value, ntdll_sha256=digest(path.value))
    a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    a.OpenProcessToken.restype = w.BOOL
    a.GetTokenInformation.argtypes = [w.HANDLE, w.ULONG, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    a.GetTokenInformation.restype = w.BOOL
    a.GetLengthSid.argtypes = [c.c_void_p]
    a.GetLengthSid.restype = w.DWORD
    token = w.HANDLE()
    assert a.OpenProcessToken(k.GetCurrentProcess(), 8, c.byref(token))
    try:
        length = w.DWORD()
        a.GetTokenInformation(token, 1, None, 0, c.byref(length))
        assert 0 < length.value <= 65536
        user = c.create_string_buffer(length.value)
        assert a.GetTokenInformation(token, 1, user, len(user), c.byref(length))
        sid_pointer = c.c_void_p.from_buffer(user).value
        sid = c.string_at(sid_pointer, a.GetLengthSid(sid_pointer))
    finally:
        assert k.CloseHandle(token)
    assert sid[0] == 1 and len(sid) == 8 + 4 * sid[1]
    authority = int.from_bytes(sid[2:8], "big")
    sid_text = "S-1-" + str(authority)
    for offset in range(8, len(sid), 4):
        sid_text += "-" + str(int.from_bytes(sid[offset:offset + 4], "little"))
    state.update(primary_sid=sid_text, primary_sid_hex=sid.hex())
    def query(fn, handle, info_class, capacity=65536):
        data = c.create_string_buffer(b"\xa5" * capacity, capacity)
        assert len(data) == capacity
        result = w.ULONG(0xCCCCCCCC)
        status = fn(handle, info_class, data, len(data), c.byref(result)) & 0xFFFFFFFF
        value = {"status": status, "result_length": result.value, "buffer_length": len(data)}
        if status == 0:
            assert result.value <= len(data)
            value["bytes_hex"] = data.raw[:result.value].hex()
        return value
    paths = ["\\REGISTRY\\USER\\" + sid_text, "\\REGISTRY\\USER\\.DEFAULT", "\\REGISTRY\\USER"]
    missing = "\\REGISTRY\\USER\\S-1-0-4275878552"
    paths += [missing, missing + "\\", missing + "\\child", missing + "\\child\\leaf"]
    state["win32_absence"] = []
    a.RegOpenKeyExW.argtypes = [w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD, c.POINTER(w.HANDLE)]
    a.RegOpenKeyExW.restype = w.LONG
    a.RegCloseKey.argtypes = [w.HANDLE]
    a.RegCloseKey.restype = w.LONG
    for full in paths[3:]:
        suffix = full[len("\\REGISTRY\\USER\\"):]
        handle = w.HANDLE(0xCCCCCCCC)
        status = a.RegOpenKeyExW(c.c_void_p(-2147483645), suffix, 0, 1, c.byref(handle))
        state["win32_absence"].append(dict(path=full, status=status, output_handle=handle.value))
        if status == 0:
            assert a.RegCloseKey(handle) == 0
    for name in paths:
        for attributes in [0x640, 0x40]:
            for access in [0x02000000, 0x20019, 1, 0]:
                text = c.create_unicode_buffer(name)
                encoded = name.encode("utf-16-le")
                us = US(len(encoded), len(encoded) + 2, c.addressof(text))
                oa = OA(c.sizeof(OA), None, c.pointer(us), attributes, None, None)
                handle = w.HANDLE(0xCCCCCCCC)
                status = n.NtOpenKey(c.byref(handle), access, c.byref(oa)) & 0xFFFFFFFF
                row = {"path": name, "attributes": attributes, "access": access,
                       "status": status, "output_handle": handle.value}
                if status == 0:
                    try:
                        row["object_basic"] = query(n.NtQueryObject, handle, 0, 56)
                        row["key_basic"] = query(n.NtQueryKey, handle, 0)
                        row["key_full"] = query(n.NtQueryKey, handle, 2)
                        row["key_name"] = query(n.NtQueryKey, handle, 3)
                        raw = row["object_basic"].get("bytes_hex")
                        if raw:
                            row["granted_access"] = int.from_bytes(bytes.fromhex(raw)[4:8], "little")
                        raw = row["key_name"].get("bytes_hex")
                        if raw:
                            data = bytes.fromhex(raw)
                            count = int.from_bytes(data[:4], "little")
                            assert count <= len(data) - 4 and count % 2 == 0
                            row["canonical_name"] = data[4:4 + count].decode("utf-16-le")
                    finally:
                        row["close_status"] = n.NtClose(handle) & 0xFFFFFFFF
                state["rows"].append(row)
                save()
    assert digest(__file__) == state["source_sha256"]
    state.update(state="finished", exit_code=0, inputs_unchanged=True)
except BaseException:
    state.update(state="failed", exit_code=1, error=traceback.format_exc())
save()
print(json.dumps({k: state[k] for k in ["state", "exit_code", "pid"]}))
raise SystemExit(state["exit_code"])
