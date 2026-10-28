#!/usr/bin/env python3
"""Qualify XCR0 checkpoint continuation through the actual exported library."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import struct


class Config(c.Structure):
    _fields_ = [("size", c.c_uint32), ("arch", c.c_int32), ("mode", c.c_uint32),
                ("backend", c.c_int32), ("mem_base", c.c_uint64), ("mem_size", c.c_uint64),
                ("mem_perms", c.c_uint32), ("flags", c.c_uint32), ("riscv_ext", c.c_uint64)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expect-parent", action="store_true")
    args = parser.parse_args()
    args.library = args.library.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    library_hash = hashlib.sha256(args.library.read_bytes()).hexdigest()
    lib = c.CDLL(str(args.library))

    def function(name, parameters, result=c.c_int32):
        value = getattr(lib, name)
        value.argtypes = parameters
        value.restype = result
        return value

    open_engine = function("rax_engine_open_config", [c.POINTER(Config), c.POINTER(c.c_void_p)])
    close = function("rax_engine_close", [c.c_void_p], None)
    write = function("rax_mem_write", [c.c_void_p, c.c_uint64, c.c_void_p, c.c_size_t])
    set_reg = function("rax_reg_write_u64", [c.c_void_p, c.c_int32, c.c_uint64])
    get_reg = function("rax_reg_read_u64", [c.c_void_p, c.c_int32, c.POINTER(c.c_uint64)])
    save = function("rax_context_save", [c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)])
    restore = function("rax_context_restore", [c.c_void_p, c.c_void_p, c.c_size_t])
    run = function("rax_emu_start", [c.c_void_p, c.c_uint64, c.c_uint64, c.c_uint64, c.c_uint64])
    map_memory = function("rax_mem_map", [c.c_void_p, c.c_uint64, c.c_uint64, c.c_uint32])
    unmap_memory = function("rax_mem_unmap", [c.c_void_p, c.c_uint64, c.c_uint64])
    icount = function("rax_emu_icount", [c.c_void_p], c.c_uint64)
    maximum = (1 << 64) - 1
    # XOR ECX,ECX; MOV EAX,3; XOR EDX,EDX; XSETBV; XGETBV; HLT.
    code = bytes.fromhex("31c9 b803000000 31d2 0f01d1 0f01d0 f4")
    (args.out / "guest.bin").write_bytes(code)
    rows = []

    def engine(mode):
        configuration = Config(c.sizeof(Config), 1, mode, 0, 0, 4096, 7, 0, 0)
        pointer = c.c_void_p()
        assert open_engine(c.byref(configuration), c.byref(pointer)) == 0
        return pointer

    def reg(engine, number):
        value = c.c_uint64()
        assert get_reg(engine, number, c.byref(value)) == 0
        return value.value

    for mode in [2, 4]:  # RAX_MODE_32 and RAX_MODE_64, defined in rax.h.
        source = engine(mode)
        target = engine(4 if mode == 2 else 2)
        try:
            assert write(source, 0x100, code, len(code)) == 0
            assert set_reg(source, 0x904, reg(source, 0x904) | (1 << 18)) == 0  # CR4.OSXSAVE
            assert run(source, 0x100, maximum, 0, 4) == 0
            assert reg(source, 0x10) == 0x10c  # RIP, before XGETBV.
            length = c.c_size_t()
            assert save(source, None, 0, c.byref(length)) == 0
            raw = c.create_string_buffer(length.value)
            assert save(source, raw, len(raw), c.byref(length)) == 0
            (args.out / f"mode-{mode}.context").write_bytes(raw.raw)
            assert restore(target, raw, len(raw)) == 0
            assert icount(target) == 0
            assert map_memory(target, 0x8000, 0x1000, 7) == 0
            assert unmap_memory(target, 0x8000, 0x1000) == 0
            assert run(source, 0x10c, maximum, 0, 1) == 0
            assert run(target, 0x10c, maximum, 0, 1) == 0
            row = dict(mode=mode, format=struct.unpack_from("<I", raw.raw, 4)[0],
                       source_xcr0=reg(source, 0x100), restored_xcr0=reg(target, 0x100),
                       source_pc=reg(source, 0x10), restored_pc=reg(target, 0x10),
                       restored_public_count=icount(target))
            rows.append(row)
            (args.out / "observations.json").write_text(json.dumps(rows, indent=2) + "\n")
            assert row["format"] == (2 if args.expect_parent else 7)
            assert row["source_xcr0"] == 3
            assert row["restored_xcr0"] == (1 if args.expect_parent else 3)
            assert row["source_pc"] == row["restored_pc"] == 0x10f
            assert row["restored_public_count"] == 1
        finally:
            close(source)
            close(target)
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == library_hash
    result = dict(code=0, library=str(args.library), library_sha256=library_hash,
                  guest_sha256=hashlib.sha256(code).hexdigest(), cases=rows,
                  negative_control=args.expect_parent)
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
