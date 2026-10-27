"""Read-only native evidence for the current primary-token Windows directory."""

import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import struct
import sys

FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[3]


def file_identity(path):
    path = Path(path).resolve()
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
        stream.seek(0)
        header = stream.read(64)
        machine = None
        if len(header) == 64 and header[:2] == b"MZ":
            offset = struct.unpack_from("<I", header, 60)[0]
            if not 64 <= offset <= min(path.stat().st_size - 6, 1048576):
                raise ValueError("PE header outside bounds")
            stream.seek(offset)
            signature = stream.read(6)
            if signature[:4] != b"PE\0\0":
                raise ValueError("PE signature differs")
            machine = struct.unpack_from("<H", signature, 4)[0]
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": h.hexdigest(),
        "pe_machine": machine,
    }


def capture():
    if sys.platform != "win32":
        raise RuntimeError("native Windows host required")
    from ctypes import wintypes as w

    class Unicode(c.Structure):
        _fields_ = [("length", w.USHORT), ("maximum", w.USHORT), ("buffer", c.c_void_p)]

    class Attributes(c.Structure):
        _fields_ = [
            ("length", w.ULONG),
            ("root", w.HANDLE),
            ("name", c.POINTER(Unicode)),
            ("flags", w.ULONG),
            ("security", c.c_void_p),
            ("qos", c.c_void_p),
        ]

    nt = c.WinDLL("ntdll", use_last_error=True)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    advapi = c.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.GetModuleFileNameW.argtypes = [w.HMODULE, w.LPWSTR, w.DWORD]
    kernel.GetModuleFileNameW.restype = w.DWORD
    kernel.GetProcessHandleCount.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    kernel.IsWow64Process2.argtypes = [
        w.HANDLE,
        c.POINTER(w.USHORT),
        c.POINTER(w.USHORT),
    ]
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        w.HANDLE,
        c.c_int,
        c.c_void_p,
        w.DWORD,
        c.POINTER(w.DWORD),
    ]
    nt.NtClose.argtypes = [w.HANDLE]
    nt.NtClose.restype = w.LONG
    nt.NtCompareObjects.argtypes = [w.HANDLE, w.HANDLE]
    nt.NtCompareObjects.restype = w.LONG
    nt.NtQueryObject.argtypes = [
        w.HANDLE,
        w.ULONG,
        c.c_void_p,
        w.ULONG,
        c.POINTER(w.ULONG),
    ]
    nt.NtQueryObject.restype = w.LONG
    for name in ("NtOpenDirectoryObject", "NtOpenSection"):
        function = getattr(nt, name)
        function.argtypes = [c.POINTER(w.HANDLE), w.ULONG, c.POINTER(Attributes)]
        function.restype = w.LONG

    def module_path(handle):
        buffer = c.create_unicode_buffer(32768)
        length = kernel.GetModuleFileNameW(handle, buffer, len(buffer))
        if not 0 < length < len(buffer):
            raise RuntimeError("module path outside bounds")
        return buffer.value

    sources = {
        "observer": Path(__file__),
        "python": Path(sys.executable),
        "python_dll": Path(module_path(sys.dllhandle)),
        "ntdll": Path(module_path(nt._handle)),
    }
    before_files = {name: file_identity(path) for name, path in sources.items()}
    handles = []

    def close(handle):
        if nt.NtClose(handle) != 0:
            raise RuntimeError("owned handle close failed")

    def open_object(kind, path, flags, access):
        raw = path.encode("utf-16-le")
        buffer = c.create_unicode_buffer(path)
        name = Unicode(len(raw), len(raw), c.cast(buffer, c.c_void_p))
        attributes = Attributes(
            c.sizeof(Attributes), None, c.pointer(name), flags, None, None
        )
        handle = w.HANDLE()
        status = (
            getattr(nt, "NtOpen" + kind)(c.byref(handle), access, c.byref(attributes))
            & 0xFFFFFFFF
        )
        if status == 0:
            if not handle.value:
                raise RuntimeError("successful open has no handle")
            handles.append(handle)
        elif handle.value:
            raise RuntimeError("failed open published an unexpected handle")
        return status, handle

    def text(buffer, returned, descriptor):
        first = c.addressof(buffer)
        pointer = descriptor.buffer or 0
        if (
            descriptor.length % 2
            or descriptor.length > descriptor.maximum
            or pointer < first
            or pointer - first > returned
            or descriptor.length > returned - (pointer - first)
        ):
            raise RuntimeError("native counted string leaves its output buffer")
        raw = c.string_at(pointer, descriptor.length)
        return {
            "units": list(struct.unpack("<" + "H" * (len(raw) // 2), raw)),
            "text": raw.decode("utf-16-le", errors="strict"),
        }

    def information(handle):
        result = {}
        for kind, label in [(1, "name"), (2, "type")]:
            buffer = c.create_string_buffer(65536)
            returned = w.ULONG()
            status = (
                nt.NtQueryObject(handle, kind, buffer, len(buffer), c.byref(returned))
                & 0xFFFFFFFF
            )
            if status != 0 or not c.sizeof(Unicode) <= returned.value <= len(buffer):
                raise RuntimeError(
                    f"object {label} query status={status:#010x}, returned={returned.value}"
                )
            result[label] = text(buffer, returned.value, Unicode.from_buffer(buffer))
        buffer = c.create_string_buffer(128)
        returned = w.ULONG()
        status = (
            nt.NtQueryObject(handle, 0, buffer, len(buffer), c.byref(returned))
            & 0xFFFFFFFF
        )
        if status != 0 or not 16 <= returned.value <= len(buffer):
            raise RuntimeError("object basic information outside bounds")
        result["granted_access"] = struct.unpack_from("<I", buffer.raw, 4)[0]
        return result

    def handle_count():
        count = w.DWORD()
        if not kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), c.byref(count)):
            raise c.WinError(c.get_last_error())
        return count.value

    token = w.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)):
        raise c.WinError(c.get_last_error())
    try:
        session = w.DWORD()
        returned = w.DWORD()
        if (
            not advapi.GetTokenInformation(
                token, 12, c.byref(session), c.sizeof(session), c.byref(returned)
            )
            or returned.value != 4
        ):
            raise RuntimeError("primary token session query failed")
    finally:
        close(token)
    process_machine, native_machine = w.USHORT(), w.USHORT()
    if not kernel.IsWow64Process2(
        kernel.GetCurrentProcess(), c.byref(process_machine), c.byref(native_machine)
    ):
        raise c.WinError(c.get_last_error())
    paths = {
        "directory": ["\\Windows", f"\\Sessions\\{session.value}\\Windows"],
        "section": [
            "\\Windows\\SharedSection",
            f"\\Sessions\\{session.value}\\Windows\\SharedSection",
        ],
    }
    baseline_count = handle_count()
    rows = []
    try:
        references = {}
        for kind, api, access in [
            ("directory", "DirectoryObject", 0x02000000),
            ("section", "Section", 4),
        ]:
            status, reference = open_object(api, paths[kind][0], 0x40, access)
            if status != 0:
                raise RuntimeError(
                    f"fixed {kind} reference unavailable: {status:#010x}"
                )
            references[kind] = reference
            for index, path in enumerate(paths[kind]):
                for altered in (False, True):
                    selected = path.swapcase() if altered else path
                    for flags in (0, 0x40, 0x1000, 0x1040):
                        status, handle = open_object(api, selected, flags, access)
                        row = {
                            "kind": kind,
                            "path_index": index,
                            "path": selected,
                            "altered_case": altered,
                            "flags": flags,
                            "requested_access": access,
                            "status": status,
                            "information": None,
                            "same_reference_status": None,
                        }
                        if status == 0:
                            row["information"] = information(handle)
                            row["same_reference_status"] = (
                                nt.NtCompareObjects(reference, handle) & 0xFFFFFFFF
                            )
                            close(handles.pop())
                        rows.append(row)
        # A fixed unlike-type control ensures identity is not inferred from names.
        distinct_status = (
            nt.NtCompareObjects(references["directory"], references["section"])
            & 0xFFFFFFFF
        )
    finally:
        while handles:
            close(handles.pop())
    final_count = handle_count()
    after_files = {name: file_identity(path) for name, path in sources.items()}
    if before_files != after_files or baseline_count != final_count:
        raise RuntimeError("source/runtime identity changed or owned handle leaked")
    return {
        "schema": "native-session-windows-directory-v1",
        "version": list(sys.getwindowsversion()),
        "pointer_bytes": c.sizeof(c.c_void_p),
        "attributes_bytes": c.sizeof(Attributes),
        "unicode_bytes": c.sizeof(Unicode),
        "process_machine": process_machine.value,
        "native_machine": native_machine.value,
        "session": session.value,
        "paths": paths,
        "rows": rows,
        "distinct_type_status": distinct_status,
        "handle_count_before": baseline_count,
        "handle_count_after": final_count,
        "files_before": before_files,
        "files_after": after_files,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", default="target/native-session-windows-directory-v1.json"
    )
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    target = (ROOT / "target").resolve()
    if (
        not target.is_relative_to(ROOT.resolve())
        or not output.is_relative_to(target)
        or output.exists()
    ):
        raise ValueError("output must be a new in-repository target path")
    result = capture()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=True)
        stream.write("\n")
    print(
        json.dumps(
            {
                "output": str(output),
                "session": result["session"],
                "rows": len(result["rows"]),
            }
        )
    )


if __name__ == "__main__":
    main()
