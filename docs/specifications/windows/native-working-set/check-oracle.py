#!/usr/bin/env python3
"""Check original class4 observations without importing RAX or its fixtures."""
from pathlib import Path
import hashlib
import json
import re

BASE = Path(__file__).resolve().parent
OK, AV, MISALIGN, GUARD = 0, 0xC0000005, 0x80000002, 0x80000001
LENGTH, PARAM, HANDLE, TYPE = 0xC0000004, 0xC000000D, 0xC0000008, 0xC0000024
DENIED, NO_MEMORY = 0xC0000022, 0xC0000017
LENGTHS = (0, 1, 7, 8, 12, 15, 16, 17, 24, 31, 32, 64, 80, 128)


def fields(line):
    return dict(re.findall(r"([\w-]+)=([\w]*)", line))


def rows(path, prefix):
    result = []
    for line in path.read_text().splitlines():
        if not line.startswith(prefix + " "):
            continue
        row = fields(line)
        for key in ("role", "target", "length"):
            if key in row:
                row[key] = int(row[key])
        row["status"] = int(row["status"], 16)
        assert int(row["exception"], 16) == 0, line
        for key in ("bytes", "output"):
            if key in row:
                row[key] = bytes.fromhex(row[key])
        result.append(row)
    return result


def ptr(data, at, width):
    return int.from_bytes(data[at:at + width], "little")


for entry in json.loads((BASE / "sources.json").read_text()):
    assert hashlib.sha256((BASE / entry["file"]).read_bytes()).hexdigest() == entry["sha256"], entry["file"]

for arch in ("arm64", "x86", "x64"):
    wow = arch == "x86"
    width = 4 if wow else 8
    record = width * 2
    original = BASE / f"native-working-set-{arch}.log"
    header = fields(next(x for x in original.read_text().splitlines() if x.startswith("pointer=")))
    assert int(header["pointer"]) == width
    ntdll, code, private, reserve = (int(header[k], 16) for k in ("ntdll", "code", "private", "reserve"))
    maximum = (1 << (width * 8)) - 1
    addresses = (ntdll, code, private + 8192, private + 12288, private + 16384,
                 private + 20480, reserve, 0, 1, maximum, private + 24576, private + 8193)
    matrix = rows(original, "matrix")
    assert len(matrix) == 168
    assert {(r["target"], r["length"]) for r in matrix} == {(t, n) for t in range(12) for n in LENGTHS}
    for row in matrix:
        target, length = row["target"], row["length"]
        expected = OK if length >= record else LENGTH
        assert row["status"] == expected, (arch, row)
        assert row["guard"] == "1", (arch, row)
        assert int(row["returned"]) == (length // record * record if wow else length) if expected == OK else int(row["returned"]) == maximum
        written = length // record if expected == OK else 0
        for index in range(64 // record):
            address = ptr(row["bytes"], index * record, width)
            flags = ptr(row["bytes"], index * record + width, width)
            assert address == addresses[target], (arch, row, index)
            if index >= written:
                assert flags == maximum, (arch, row, index)
            elif target in (0, 1, 3):
                assert flags & 1, (arch, row, index)
                if target == 1:
                    assert (flags >> 4) & 0x7FF == 0x20, (arch, row)
                if target == 3:
                    assert (flags >> 4) & 0x7FF == 2 and flags & 0x800E == 0, (arch, row)
            elif target == 4:
                assert flags & 1 == 0 and (flags >> 22) & 3 == 1, (arch, row)
            else:
                assert flags == 0, (arch, row)

    faults = rows(original, "fault")
    assert len(faults) == 30 and {r["role"] for r in faults} == set(range(30))
    expected = ([OK, LENGTH, AV, AV, OK, OK, OK, OK, HANDLE, TYPE, PARAM, OK,
                 AV, GUARD, OK, OK, GUARD, OK, OK, OK, OK, OK, OK, LENGTH,
                 AV, LENGTH, NO_MEMORY, NO_MEMORY, OK, AV]
                if wow else [OK, LENGTH, AV, MISALIGN, MISALIGN, MISALIGN, AV, OK,
                             HANDLE, TYPE, PARAM, OK, AV, GUARD, AV, GUARD, GUARD,
                             GUARD, OK, AV, LENGTH, OK, LENGTH, LENGTH, AV, LENGTH,
                             AV, AV, OK, AV])
    for row in faults:
        role = row["role"]
        assert row["status"] == expected[role], (arch, row)
        guards = "10" if role == 23 and not wow else "01" if role == 16 and not wow else "00"
        assert row["guards"] == guards, (arch, row)

    rights = rows(original, "rights")
    assert len(rights) == 6
    assert {int(r["access"], 16) for r in rights} == {0x10, 0x400, 0x1000, 0x1010, 0x410, 0x1FFFFF}
    for row in rights:
        allowed = int(row["access"], 16) & 0x1400 != 0
        assert row["status"] == (OK if allowed else DENIED), (arch, row)
        assert int(row["returned"]) == (record if allowed else maximum), (arch, row)

    captures = rows(BASE / f"native-working-set-capture-{arch}.log", "capture")
    assert len(captures) == 24 and {r["role"] for r in captures} == set(range(24))
    expected = ([HANDLE, GUARD, AV, AV, AV, OK, OK, GUARD, OK, LENGTH, PARAM,
                 PARAM, LENGTH, HANDLE, LENGTH, AV, OK, OK, OK, OK, OK, OK, OK, OK]
                if wow else [AV, GUARD, AV, MISALIGN, AV, GUARD, GUARD, GUARD,
                             GUARD, LENGTH, PARAM, PARAM, LENGTH, MISALIGN, LENGTH,
                             AV, OK, AV, GUARD, AV, OK, OK, OK, OK])
    for row in captures:
        role = row["role"]
        assert row["status"] == expected[role], (arch, row)
        guards = ("001" if role == 22 else "100" if role == 10 else
                  "100" if role == 9 and wow else "110" if role == 9 else
                  "010" if role == 7 and not wow or role == 18 and wow else "000")
        assert row["guards"] == guards, (arch, row)
        if role in (5, 6) and wow:
            # Initial optional return probe consumes the shared guard and
            # suppresses publication. Output records, including aliases, win.
            assert ptr(row["output"], width, width) & 1, (arch, row)
            if role == 6:
                assert bytes.fromhex(row["returned"])[:width] == row["output"][:width], (arch, row)
        if role == 20:
            assert ptr(row["output"], width, width) == row["length"], (arch, row)
        if role == 22 or role == 23:
            flags = ptr(row["output"], width, width)
            assert flags & 1 == 0 and (flags >> 22) & 3 == 1, (arch, row)
    print(f"{arch}: 168 matrix + 30 fault + 6 rights + 24 capture queries verified")

print("684 original queries and all source hashes verified")
