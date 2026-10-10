#!/usr/bin/env python3
"""Independent replay of the retained original fixed-root opens."""
from pathlib import Path
import re

base = Path(__file__).resolve().parent
count = 0
for arch, width in [("arm64", 8), ("x86", 4), ("x64", 8)]:
    text = (base / f"native-segment-heap-{arch}.log").read_text()
    records = re.findall(r"^pointer=(\d+) view=([0-9A-F]{3}) native=([0-9A-F]{8}) win32=(\d+)$", text, re.M)
    assert len(records) == 3, (arch, records)
    assert [r[1] for r in records] == ["000", "100", "200"]
    for pointer, view, native, win32 in records:
        assert (int(pointer), native, int(win32)) == (width, "C0000034", 2)
        count += 1
assert count == 9
print("PASS: 9 ABI/view pairs, 18 native opens, all STATUS_OBJECT_NAME_NOT_FOUND / ERROR_FILE_NOT_FOUND")
print("Scope: Windows 10.0.29683.1000 ARM64 with native ARM64 and compatibility x86/x64; configured-present profiles unobserved")
