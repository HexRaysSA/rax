#!/usr/bin/env python3
"""Replay original native class62 records without consulting the host."""
from pathlib import Path
import re

base = Path(__file__).resolve().parent
reported = 0
lengths = [0, 12, 43, 44, 45, 63, 64, 65, 80]
for profile, width in [("arm64", 8), ("x86", 4), ("x86-laa", 4), ("x64", 8)]:
    required = 44 if width == 4 else 64
    records = {}
    for line in (base / f"native-emulation-basic-{profile}.log").read_text().splitlines():
        match = re.fullmatch(r"class=(\d+) width=(\d+) len=(\d+) status=([0-9A-F]{8}) required=(\d+) bytes=([0-9a-f]{192})", line)
        assert match, (profile, line)
        cls, actual_width, length, status, returned, raw = match.groups()
        cls, length, returned = int(cls), int(length), int(returned)
        assert int(actual_width) == width
        data = bytes.fromhex(raw)
        assert (cls, length) not in records
        records[cls, length] = status, returned, data
        if width == 4 and cls == 114:
            assert (status, returned, data) == ("C0000003", 0xDEADBEEF, bytes([0xA5]) * 96)
        elif length != required:
            assert (status, returned, data) == ("C0000004", required, bytes([0xA5]) * 96)
        else:
            assert status == "00000000" and returned == required
            written = 41 if width == 4 else 64
            assert data[written:] == bytes([0xA5]) * (96 - written)
            assert int.from_bytes(data[8:12], "little") == 4096
            first = 28 if width == 4 else 32
            assert int.from_bytes(data[first:first + width], "little") == 0x10000
            if width == 4:
                maximum = 0xFFFEFFFF if profile == "x86-laa" else 0x7FFEFFFF
                assert int.from_bytes(data[32:36], "little") == maximum
        reported += 1
    assert set(records) == {(cls, length) for cls in [0, 62, 114] for length in lengths}
    for length in lengths:
        assert records[0, length] == records[62, length]
        if width == 8:
            assert records[0, length] == records[114, length]

    pointer_rows = {}
    for line in (base / f"native-emulation-basic-pointer-{profile}.log").read_text().splitlines():
        match = re.fullmatch(r"([a-z0-9-]+) width=(\d+) status=([0-9A-F]{8}) out=([0-9a-f]{32}) ret=([0-9a-f]{16})", line)
        assert match, (profile, line)
        name, size, status, out, returned = match.groups()
        assert int(size) == required and name not in pointer_rows
        pointer_rows[name] = status, bytes.fromhex(out), bytes.fromhex(returned)
        reported += 1
    expected = {"exact": "00000000", "short": "C0000004", "long": "C0000004",
                "nulloutput": "C0000005", "badoutput": "C0000005" if width == 4 else "80000002",
                "unaligned-short": "C0000004" if width == 4 else "80000002", "nulloutput-short": "C0000004",
                "badreturn": "C0000005", "unalignedout": "00000000" if width == 4 else "80000002",
                "aligned4out": "00000000", "unalignedret": "00000000", "nullret": "00000000",
                "invalidclass": "C0000003", "invalidclass-badret": "C0000003" if width == 4 else "C0000005"}
    assert set(pointer_rows) == set(expected)
    for name, status in expected.items():
        assert pointer_rows[name][0] == status, (profile, name)
    assert pointer_rows["badreturn"][1] == (records[62, required][2][:16] if width == 4 else bytes([0xA5]) * 16)
    assert int.from_bytes(pointer_rows["nulloutput"][2][:4], "little") == (0xFFFFFFEC if width == 4 else 0xA5A5A5A5)

    guard = (base / f"native-emulation-basic-guard-{profile}.log").read_text().splitlines()
    assert len(guard) == 4
    for which in [0, 1]:
        assert guard[2 * which] == f"returnguard={which} status=80000001 exception=00000000 protection=00000004"
        prefix = records[62, required][2][:8] if width == 4 and which else bytes([0xA5]) * 8
        assert guard[2 * which + 1] == f"output={prefix.hex()} returned=A5A5A5A5"
        reported += 1
    alias = (base / f"native-emulation-basic-alias-{profile}.log").read_text().splitlines()
    assert alias == [f"pointer_bytes={width} returned_offset={at} status=00000000 output_then_length=1" for at in [0, 1, 8, 24, 40, 60]]
    reported += len(alias)
assert reported == 196
print("PASS: 196 reported native queries plus four successful alias baseline queries across ARM64/x86/x86-LAA/x64")
print("Verified exact length/alias records, class0 equality, native ABI faults/guards/order/padding and x86 address limits; build29683 scope")
