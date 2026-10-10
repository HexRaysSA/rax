#!/usr/bin/env python3
"""Check original Windows observations without importing the emulator."""
from pathlib import Path
import re
import struct

BASE = Path(__file__).resolve().parent
SUCCESS, AV, MISALIGN, GUARD = 0, 0xC0000005, 0x80000002, 0x80000001
LENGTH, CLASS, PARAM, HANDLE, TYPE = 0xC0000004, 0xC0000003, 0xC000000D, 0xC0000008, 0xC0000024
FREE, DENIED = 0xC0000141, 0xC0000022


def rows(path, prefix):
    result = []
    for line in path.read_text().splitlines():
        if line.startswith(prefix + " "):
            row = dict(re.findall(r"([\w-]+)=([\w]+)", line))
            for name in ("role", "target", "class", "length", "returned"):
                if name in row and name != "returned":
                    row[name] = int(row[name])
            row["status"] = int(row["status"], 16)
            assert int(row["exception"], 16) == 0, line
            row["bytes"] = bytes.fromhex(row["bytes"])
            result.append(row)
    return result


for arch in ("arm64", "x86", "x64"):
    wow = arch == "x86"
    width = 4 if wow else 8
    basic, image = (28, 12) if wow else (48, 24)
    query_path = BASE / f"native-vm-query-{arch}.log"
    boundary_path = BASE / f"native-vm-boundary-{arch}.log"
    header = next(x for x in query_path.read_text().splitlines() if x.startswith("pointer="))
    values = dict(re.findall(r"([\w-]+)=([\w]+)", header))
    assert int(values["pointer"]) == width
    bases = (int(values["ntdll"], 16), int(values["main"], 16))
    sizes = (int(values["ntdll-size"]), int(values["main-size"]))
    matrix = rows(query_path, "matrix")
    assert len(matrix) == 231
    for row in matrix:
        target, kind, length = row["target"], row["class"], row["length"]
        required = basic if kind == 0 else image
        expected = CLASS if kind == 0xFFFFFFFF else LENGTH if length < required else PARAM if target == 6 else FREE if kind == 6 and target in (4, 5) else SUCCESS
        assert row["status"] == expected, (arch, row)
        returned = int(row["returned"])
        if expected == SUCCESS:
            assert returned == required
            assert row["bytes"][required:] == b"\xA5" * (64 - required)
            if kind == 6:
                if target in (0, 1, 2):
                    index = 1 if target == 1 else 0
                    flags = 0 if index == 1 else 0x30 if wow else 0x70
                    fmt = "<III" if wow else "<QQI4x"
                    assert row["bytes"][:required] == struct.pack(fmt, bases[index], sizes[index], flags)
                else:
                    assert row["bytes"][:required] == bytes(required)
            elif target in (4, 5):
                fields = struct.unpack_from("<7I" if wow else "<QQI4xQIII", row["bytes"])
                assert fields[:3] == (0, 0, 0)
                assert fields[3] > 0 and fields[3] % 4096 == 0
                assert fields[4:] == (0x10000, 1, 0)
        elif expected == FREE and wow:
            assert returned == image
        else:
            assert returned == (1 << (width * 8)) - 1

    faults = rows(query_path, "fault")
    expected = ([0, 0, 0, AV, 0, 0, 0, HANDLE, TYPE, CLASS, CLASS, LENGTH, LENGTH, AV, 0, GUARD, 0, GUARD, HANDLE, 0, 0, 0, 0, AV, 0, LENGTH, 0, 0, PARAM, HANDLE]
                if wow else [0, 0, AV, MISALIGN, AV, MISALIGN, 0, HANDLE, TYPE, CLASS, CLASS, LENGTH, LENGTH, AV, AV, GUARD, GUARD, GUARD, AV, 0, 0, 0, 0, MISALIGN, 0, LENGTH, MISALIGN, 0, PARAM, AV])
    assert len(faults) == 30
    for row in faults:
        role = row["role"]
        assert row["status"] == expected[role], (arch, row)
        guards = "001" if role == 19 else "010" if role == 17 and not wow else "000"
        assert row["guards"] == guards, (arch, row)

    boundary = rows(boundary_path, "boundary")
    assert len(boundary) == 76
    for row in boundary:
        role, kind = row["role"], row["class"]
        expected = SUCCESS
        guards = "00"
        if wow:
            if role in (6, 14, 15, 27): expected = HANDLE
            elif role in (10, 11, 26): expected = PARAM
            elif role in (7, 12, 13, 25, 30) and kind == 6: expected = FREE
            elif role in (13, 23, 35): expected = AV
            elif role == 16: expected = LENGTH
            elif role in (17,): expected = GUARD
            if role in (4, 14, 16, 21): guards = "10"
            elif role == 27: guards = "01"
        else:
            if role in (1, 2, 13, 23, 35): expected = MISALIGN
            elif role in (3, 5, 6, 9, 12, 19, 24, 28, 29): expected = AV
            elif role in (4, 14, 15, 17, 25, 27, 36, 37): expected = GUARD
            elif role in (10, 11, 26): expected = PARAM
            elif role == 16: expected = LENGTH
            elif role in (7, 30) and kind == 6: expected = FREE
            if role in (21, 23, 24, 26, 27): guards = "10"
            elif role == 16: guards = "11"
            elif role == 17: guards = "01"
        assert row["status"] == expected, (arch, row)
        assert row["guards"] == guards, (arch, row)
    rights = rows(boundary_path, "rights")
    assert len(rights) == 12
    for row in rights:
        assert row["status"] == (SUCCESS if row["role"] & 0x1400 else DENIED), (arch, row)
    priority = rows(boundary_path, "priority")
    assert len(priority) == 18
    for row in priority:
        expected = CLASS if row["class"] == 0xFFFFFFFF else PARAM if row["role"] in (2, 3) else LENGTH
        assert row["status"] == expected, (arch, row)
        assert row["guards"] == ("00" if wow else "10"), (arch, row)
    assert len(rows(boundary_path, "class")) == 24
    alias_path = BASE / f"native-vm-alias-{arch}.log"
    aliases = []
    for line in alias_path.read_text().splitlines():
        if line.startswith("alias "):
            aliases.append(dict(re.findall(r"(\w+)=([^ ]*)", line)))
    assert len(aliases) == 24
    for row in aliases:
        role, kind = int(row["role"]), int(row["class"])
        expected = ([SUCCESS, SUCCESS, GUARD, GUARD, GUARD, HANDLE, FREE if kind == 6 else SUCCESS, LENGTH, SUCCESS, SUCCESS, GUARD, SUCCESS][role]
                    if wow else LENGTH if role == 7 else MISALIGN if role == 8 else GUARD)
        assert int(row["status"], 16) == expected, (arch, row)
        guards = "00" if wow else "01" if role == 3 else "10" if role in (7, 8) else "00"
        assert row["guards"] == guards, (arch, row)
        if wow and role in (0, 1, 8, 9, 11):
            # The guarded length probe disables publication, then the output
            # record is copied after its shared guard has been consumed.
            assert row["output"][:8] != "A5A5A5A5"
            if role != 1:
                assert row["returned"][:8] == "A5A5A5A5"
            else:
                assert row["returned"][:8] == row["output"][:8]
    print(f"{arch}: 231 matrix + 30 faults + 76 boundaries + 12 rights + 18 priorities + 24 class inventory rows counted")
print("1245 original queries: counts, defined layouts, statuses, untouched tails, and guards validated")
