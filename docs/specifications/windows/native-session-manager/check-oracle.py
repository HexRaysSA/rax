#!/usr/bin/env python3
"""Check original native fixed-key observations; no emulator imports."""
from pathlib import Path
import hashlib
import json
import re

BASE = Path(__file__).resolve().parent
PRESENT = {"GlobalFlag", "CriticalSectionTimeout", "HeapSegmentReserve", "HeapSegmentCommit", "HeapDeCommitTotalFreeThreshold", "HeapDeCommitFreeBlockThreshold"}
MISSING = {"LowMemoryHeapGrowthPercent", "SafeDllSearchMode", "CWDIllegalInDllSearch", "missing-rax-value"}
for entry in json.loads((BASE / "sources.json").read_text()):
    assert hashlib.sha256((BASE / entry["file"]).read_bytes()).hexdigest() == entry["sha256"], entry["file"]
canonical = {}
for arch in ("arm64", "x86", "x64"):
    lines = (BASE / f"native-session-manager-{arch}.log").read_text().splitlines()
    header = next(s for s in lines if s.startswith("pointer="))
    assert f"pointer={4 if arch == 'x86' else 8} open=00000000" in header, header
    rows = [dict(re.findall(r"([\w-]+)=([\w-]+)", s)) for s in lines if s.startswith("query ")]
    assert len(rows) == 50
    assert {(r["name"], int(r["length"])) for r in rows} == {(n, length) for n in PRESENT | MISSING for length in (0, 12, 16, 64, 512)}
    for row in rows:
        name, length = row["name"], int(row["length"])
        status, returned = int(row["status"], 16), int(row["returned"], 16)
        data = bytes.fromhex(row["bytes"])
        if name in MISSING:
            assert status == 0xC0000034 and returned == 0xA5A5A5A5 and data == bytes([0xA5]) * 64, (arch, row)
            continue
        assert returned == 16
        expected = 0xC0000023 if length < 12 else 0x80000005 if length < 16 else 0
        assert status == expected, (arch, row)
        if length >= 12:
            assert data[:12] == bytes.fromhex("000000000400000004000000"), (arch, row)
        if length >= 16:
            if name not in canonical:
                canonical[name] = data[12:16]
            assert data[12:16] == canonical[name], (arch, row)
        defined = 0 if length < 12 else min(length, 16)
        assert data[defined:] == bytes([0xA5]) * (64 - defined), (arch, row)
    print(f"{arch}: fixed read-only open and 50 value query observations verified")
assert int.from_bytes(canonical["CriticalSectionTimeout"], "little") == 2_592_000
assert all(canonical[name] == bytes(4) for name in PRESENT - {"CriticalSectionTimeout"})
print("153 native observations verified; captured values are build/profile observations, not guest defaults")
