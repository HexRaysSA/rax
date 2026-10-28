"""Measure image-extension availability on owned native AMD64 image views."""

import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import sys
import traceback

ROOT = Path(__file__).resolve().parents[4]
OUTPUT = ROOT / "target/native-image-extension-amd64-v1.json"


def identity(path):
    path = Path(path).resolve()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest}


def observe():
    if sys.platform != "win32" or c.sizeof(c.c_void_p) != 8:
        raise RuntimeError("Native 64-bit Windows Python required")
    from ctypes import wintypes as w

    pointer = c.c_void_p
    size = c.c_size_t

    class Unicode(c.Structure):
        _fields_ = [("length", w.USHORT), ("maximum", w.USHORT), ("buffer", pointer)]

    class Attributes(c.Structure):
        _fields_ = [
            ("length", w.ULONG),
            ("root", pointer),
            ("name", c.POINTER(Unicode)),
            ("flags", w.ULONG),
            ("security", pointer),
            ("qos", pointer),
        ]

    class Basic(c.Structure):
        _fields_ = [("base", size), ("attributes", w.ULONG), ("size", c.c_int64)]

    class Region(c.Structure):
        _fields_ = [
            ("base", size),
            ("allocation", size),
            ("allocation_protection", w.ULONG),
            ("partition_padding", w.ULONG),
            ("size", size),
            ("state", w.ULONG),
            ("protection", w.ULONG),
            ("kind", w.ULONG),
        ]

    class Extended(c.Structure):
        _fields_ = [("kind", c.c_uint64), ("value", c.c_uint64)]

    if [c.sizeof(t) for t in (Unicode, Attributes, Basic, Region, Extended)] != [
        16,
        48,
        24,
        48,
        16,
    ]:
        raise RuntimeError("Native ABI layouts differ")

    nt = c.WinDLL("ntdll", use_last_error=True)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    prototypes = {
        "NtOpenSection": [c.POINTER(pointer), w.ULONG, c.POINTER(Attributes)],
        "NtCreateSection": [
            c.POINTER(pointer),
            w.ULONG,
            pointer,
            pointer,
            w.ULONG,
            w.ULONG,
            pointer,
        ],
        "NtQuerySection": [pointer, w.ULONG, pointer, size, c.POINTER(size)],
        "NtQueryVirtualMemory": [
            pointer,
            pointer,
            w.ULONG,
            pointer,
            size,
            c.POINTER(size),
        ],
        "NtMapViewOfSection": [
            pointer,
            pointer,
            c.POINTER(pointer),
            size,
            size,
            pointer,
            c.POINTER(size),
            w.ULONG,
            w.ULONG,
            w.ULONG,
        ],
        "NtMapViewOfSectionEx": [
            pointer,
            pointer,
            c.POINTER(pointer),
            pointer,
            c.POINTER(size),
            w.ULONG,
            w.ULONG,
            c.POINTER(Extended),
            w.ULONG,
        ],
        "NtUnmapViewOfSection": [pointer, pointer],
        "NtClose": [pointer],
    }
    for name, arguments in prototypes.items():
        function = getattr(nt, name)
        function.argtypes = arguments
        function.restype = w.LONG
    kernel.CreateFileW.argtypes = [
        w.LPCWSTR,
        w.DWORD,
        w.DWORD,
        pointer,
        w.DWORD,
        w.DWORD,
        pointer,
    ]
    kernel.CreateFileW.restype = pointer
    kernel.GetCurrentProcess.restype = pointer
    kernel.GetProcessHandleCount.argtypes = [pointer, c.POINTER(w.DWORD)]
    kernel.IsWow64Process2.argtypes = [
        pointer,
        c.POINTER(w.USHORT),
        c.POINTER(w.USHORT),
    ]
    kernel.VirtualQuery.argtypes = [pointer, c.POINTER(Region), size]
    kernel.VirtualQuery.restype = size
    current = kernel.GetCurrentProcess()
    process_machine, native_machine = w.USHORT(), w.USHORT()
    if not kernel.IsWow64Process2(
        current, c.byref(process_machine), c.byref(native_machine)
    ):
        raise c.WinError(c.get_last_error())
    if process_machine.value != 0 or native_machine.value != 0x8664:
        raise RuntimeError("Independent native AMD64 process and kernel required")

    def success(status, name):
        if status < 0:
            raise RuntimeError(f"{name}: {status & 0xffffffff:#010x}")

    def handles():
        result = w.DWORD()
        if not kernel.GetProcessHandleCount(current, c.byref(result)):
            raise c.WinError(c.get_last_error())
        return result.value

    def region(address):
        result = Region()
        if kernel.VirtualQuery(address, c.byref(result), c.sizeof(result)) != c.sizeof(
            result
        ):
            raise c.WinError(c.get_last_error())
        return {name: getattr(result, name) for name, _ in result._fields_}

    target = ROOT / "target"
    target.mkdir(exist_ok=True)
    if not target.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("Observation output escapes the worktree")
    windows = Path(os.environ["SystemRoot"])
    inputs = [Path(__file__), Path(sys.executable)]
    inputs += [windows / folder / "ntdll.dll" for folder in ("System32", "SysWOW64")]
    before = [identity(path) for path in inputs]
    record = {
        "schema": "native-image-extension-amd64-v1",
        "pid": os.getpid(),
        "kernel": list(sys.getwindowsversion()),
        "platform_machine": platform.machine(),
        "process_machine": process_machine.value,
        "native_machine": native_machine.value,
        "inputs": before,
        "state": "started",
        "samples": [],
    }
    with OUTPUT.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)

    def save():
        OUTPUT.write_text(json.dumps(record, indent=2), encoding="utf-8")

    try:
        record["handles_before"] = handles()
        for machine, folder, directory in (
            (0x8664, "System32", "KnownDlls"),
            (0x14C, "SysWOW64", "KnownDlls32"),
        ):
            for owner in ("named", "created"):
                section = pointer()
                if owner == "named":
                    text = "\\" + directory + "\\ntdll.dll"
                    storage = c.create_unicode_buffer(text)
                    length = len(text.encode("utf-16-le"))
                    name = Unicode(length, length, c.cast(storage, pointer))
                    attributes = Attributes(
                        c.sizeof(Attributes), None, c.pointer(name), 0x40, None, None
                    )
                    success(
                        nt.NtOpenSection(c.byref(section), 5, c.byref(attributes)),
                        "NtOpenSection",
                    )
                else:
                    file = kernel.CreateFileW(
                        str(windows / folder / "ntdll.dll"),
                        0x80000000,
                        7,
                        None,
                        3,
                        0,
                        None,
                    )
                    if file == c.c_void_p(-1).value:
                        raise c.WinError(c.get_last_error())
                    try:
                        success(
                            nt.NtCreateSection(
                                c.byref(section),
                                0x02000000,
                                None,
                                None,
                                2,
                                0x01000000,
                                file,
                            ),
                            "NtCreateSection",
                        )
                    finally:
                        success(nt.NtClose(file), "NtClose file")
                if not section.value:
                    raise RuntimeError("Section creation returned a NULL handle")
                try:
                    basic, returned = Basic(), size()
                    success(
                        nt.NtQuerySection(
                            section,
                            0,
                            c.byref(basic),
                            c.sizeof(basic),
                            c.byref(returned),
                        ),
                        "NtQuerySection",
                    )
                    if (
                        returned.value != 24
                        or not 4096 <= basic.size <= 64 * 1024 * 1024
                    ):
                        raise RuntimeError("Section extent or native ABI differs")
                    for mode in ("ordinary", "machine", "machine-rebase"):
                        base, extent = pointer(), size()
                        row = {
                            "machine": machine,
                            "owner": owner,
                            "mode": mode,
                            "section_size": basic.size,
                            "section_attributes": basic.attributes,
                        }
                        record["samples"].append(row)
                        if mode == "ordinary":
                            status = nt.NtMapViewOfSection(
                                section,
                                current,
                                c.byref(base),
                                0,
                                0,
                                None,
                                c.byref(extent),
                                2,
                                0,
                                2,
                            )
                        else:
                            parameter = Extended(6, machine)
                            flags = 0x00800000 if mode == "machine-rebase" else 0
                            status = nt.NtMapViewOfSectionEx(
                                section,
                                current,
                                c.byref(base),
                                None,
                                c.byref(extent),
                                flags,
                                2,
                                c.byref(parameter),
                                1,
                            )
                        row.update(
                            map_status=status & 0xFFFFFFFF,
                            base=base.value,
                            view_size=extent.value,
                        )
                        save()
                        if status < 0:
                            if base.value:
                                raise RuntimeError(
                                    "Failed map published an unexpected owned view"
                                )
                            continue
                        try:
                            if not base.value or extent.value != basic.size:
                                raise RuntimeError(
                                    "Successful map changed the image extent"
                                )
                            row["base_region"] = region(base.value)
                            image_information = (c.c_uint64 * 3)()
                            c.memset(image_information, 0xA5, 24)
                            returned = size(-1)
                            status = nt.NtQueryVirtualMemory(
                                current,
                                base,
                                6,
                                image_information,
                                24,
                                c.byref(returned),
                            )
                            row["image_information"] = {
                                "status": status & 0xFFFFFFFF,
                                "after": bytes(image_information).hex(),
                                "returned": returned.value,
                            }
                            row["queries"] = []
                            for kind, flags, length in (
                                (0, 0, 24),
                                (1, 0, 24),
                                (2, 0, 24),
                                (0, 1, 24),
                                (0, 0, 23),
                            ):
                                output = (c.c_uint64 * 3)()
                                c.memset(output, 0xA5, 24)
                                c.memmove(output, struct.pack("<II", kind, flags), 8)
                                returned = size(-1)
                                initial = bytes(output).hex()
                                status = nt.NtQueryVirtualMemory(
                                    current, base, 14, output, length, c.byref(returned)
                                )
                                row["queries"].append(
                                    {
                                        "kind": kind,
                                        "flags": flags,
                                        "length": length,
                                        "status": status & 0xFFFFFFFF,
                                        "before": initial,
                                        "after": bytes(output).hex(),
                                        "returned": returned.value,
                                    }
                                )
                            cursor = base.value + extent.value
                            row["tail_regions"] = []
                            for _ in range(8):
                                tail = region(cursor)
                                row["tail_regions"].append(tail)
                                if (
                                    tail["allocation"] != base.value
                                    or tail["state"] == 0x10000
                                ):
                                    break
                                if (
                                    not tail["base"]
                                    <= cursor
                                    < tail["base"] + tail["size"]
                                    or not 0 < tail["size"] <= 4 * 1024 * 1024
                                ):
                                    raise RuntimeError(
                                        "Owned image tail exceeds observation bounds"
                                    )
                                cursor = tail["base"] + tail["size"]
                            else:
                                raise RuntimeError(
                                    "Owned image tail exceeds region count"
                                )
                        finally:
                            success(
                                nt.NtUnmapViewOfSection(current, base),
                                "NtUnmapViewOfSection",
                            )
                        save()
                finally:
                    success(nt.NtClose(section), "NtClose section")
        record["handles_after"] = handles()
        if record["handles_before"] != record["handles_after"]:
            raise RuntimeError("Owned handles were not restored")
        if [identity(path) for path in inputs] != before:
            raise RuntimeError("Observation input identity changed")
        record["state"] = "complete"
        save()
        print(
            json.dumps(
                {
                    "state": record["state"],
                    "samples": len(record["samples"]),
                    "output": str(OUTPUT),
                }
            )
        )
    except BaseException:
        record["state"] = "failed"
        record["error"] = traceback.format_exc()
        save()
        raise


if __name__ == "__main__":
    observe()
