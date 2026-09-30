#!/usr/bin/env python3
"""Measure native Windows partial-section/placeholder behavior.

This diagnostic is deliberately independent of RAX's arena implementation.
Results are observations, not substitutes for the semantic regression tests.
All handles, mappings and temporary files are owned by this process.
"""
import ctypes as c
import json
import msvcrt
import tempfile


def bind(library, name, result, *arguments):
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


def main():
    kernel = c.WinDLL("kernelbase", use_last_error=True)
    ntdll = c.WinDLL("ntdll")
    pointer, size, uint = c.c_void_p, c.c_size_t, c.c_uint32
    alloc = bind(kernel, "VirtualAlloc2", pointer,
                 pointer, pointer, size, uint, uint, pointer, uint)
    free = bind(kernel, "VirtualFree", c.c_int, pointer, size, uint)
    create = bind(kernel, "CreateFileMappingW", pointer,
                  pointer, pointer, uint, uint, uint, pointer)
    close = bind(kernel, "CloseHandle", c.c_int, pointer)
    map3 = bind(kernel, "MapViewOfFile3", pointer,
                pointer, pointer, pointer, c.c_uint64, size, uint, uint,
                pointer, uint)
    unmap = bind(kernel, "UnmapViewOfFile", c.c_int, pointer)
    native = bind(ntdll, "NtMapViewOfSection", c.c_int32,
                  pointer, pointer, c.POINTER(pointer), size, size,
                  c.POINTER(c.c_int64), c.POINTER(size), uint, uint, uint)
    dos_error = bind(ntdll, "RtlNtStatusToDosError", uint, c.c_int32)
    process = pointer(-1)
    for length, file_offset in ((4096, 0), (4097, 0), (8192, 0), (266241, 262144)):
        with tempfile.TemporaryFile() as file:
            file.truncate(length)
            file.flush()
            section = create(msvcrt.get_osfhandle(file.fileno()), None,
                             4, 0, 0, None)
            if not section:
                raise c.WinError(c.get_last_error())
            try:
                for method in ("MapViewOfFile3", "NtMapViewOfSection"):
                    remaining = length - file_offset
                    for requested in (0, remaining, (remaining + 4095) & ~4095):
                        extent = (remaining + 4095) & ~4095
                        base = alloc(None, None, 65536, 0x42000, 1, None, 0)
                        if not base:
                            raise c.WinError(c.get_last_error())
                        if not free(base, extent, 0x8002):
                            error = c.get_last_error()
                            free(base, 0, 0x8000)
                            raise c.WinError(error)
                        mapped = None
                        try:
                            row = {"method": method, "file_bytes": length,
                                   "file_offset": file_offset,
                                   "placeholder_bytes": extent,
                                   "requested_bytes": requested}
                            if method == "MapViewOfFile3":
                                mapped = map3(section, process, base, file_offset,
                                              requested, 0x4000, 4, None, 0)
                                row["error"] = 0 if mapped else c.get_last_error()
                            else:
                                address = pointer(base)
                                offset = c.c_int64(file_offset)
                                count = size(requested)
                                status = native(section, process, c.byref(address),
                                                0, 0, c.byref(offset), c.byref(count),
                                                2, 0x4000, 4)
                                row["status"] = hex(status & 0xffffffff)
                                row["error"] = 0 if status >= 0 else dos_error(status)
                                row["mapped_bytes"] = count.value
                                if status >= 0:
                                    mapped = address.value
                            row["same_address"] = mapped == base
                            row["file_bytes_after"] = file.seek(0, 2)
                            print(json.dumps(row), flush=True)
                            if method == "MapViewOfFile3" and requested == remaining:
                                if not row["same_address"] or row["error"] != 0:
                                    raise RuntimeError("logical section view must replace the exact placeholder")
                                if row["file_bytes_after"] != length:
                                    raise RuntimeError("mapping must not change file length")
                        finally:
                            if mapped:
                                if not unmap(mapped):
                                    raise c.WinError(c.get_last_error())
                            elif not free(base, 0, 0x8000):
                                raise c.WinError(c.get_last_error())
                            if not free(base + extent, 0, 0x8000):
                                raise c.WinError(c.get_last_error())
            finally:
                close(section)


if __name__ == "__main__":
    main()
