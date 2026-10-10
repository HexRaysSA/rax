"""Independent retained Windows native observations; no RAX dependency."""
from pathlib import Path
import re

base = Path(__file__).resolve().parent
expected = {
    "arm64": {0: 0, 1: 0, 2: 0xC000000D, 3: 0xC0000005, 4: 0xC0000005,
        5: 0, 6: 0, 7: 0xC0000005, 8: 0xC0000005, 9: 0xC0000005,
        10: 0x80000001, 11: 0x80000001, 12: 0xC0000005, 13: 0x80000001,
        14: 0xC000000D, 15: 0xC000000D, 16: 0xC0000005,
        17: 0xC000000D, 18: 0xC0000005, 19: 0, 20: 0,
        21: 0xC0000005, 22: 0xC0000005, 23: 0xC00000EF,
        24: 0xC00000EF, 25: 0xC0000034, 26: 0xC0000034, 27: 0xC0000034},
}
expected["x64"] = dict(expected["arm64"])
expected["x86"] = dict(expected["arm64"])
for role in (4, 9, 11, 21):
    expected["x86"][role] = 0
fingerprints = {}
for arch in ("arm64", "x86", "x64"):
    raw = (base / f"native-nls-{arch}.log").read_text().splitlines()
    matrices = [line for line in raw if line.startswith("matrix ")]
    assert len(matrices) == 126
    for line in matrices:
        match = re.search(r"type=(\d+) data=(\d+) status=([A-F0-9]+) exception=([A-F0-9]+)", line)
        kind, data, status, exception = (int(match[1]), int(match[2]), int(match[3], 16), int(match[4], 16))
        assert exception == 0
        predicted = (0 if data in (437, 1252) else 0xC0000034) if kind == 11 else (
            (0 if data == 1 else 0xC0000034) if kind == 12 else (0 if kind == 14 else 0xC00000EF))
        assert status == predicted, (arch, line)
        if status == 0:
            size = int(re.search(r" size=(\d+)", line)[1])
            region = int(re.search(r" region=(\d+)", line)[1])
            assert size == region and size % 4096 == 0
            assert "protect=00000002 memtype=00040000" in line
            fingerprint = (size, re.search(r" hash=([A-F0-9]+)", line)[1], line.split(" bytes=")[1].split(" path=")[0])
            key = (kind, data if kind != 14 else 0)
            if key in fingerprints:
                assert fingerprints[key] == fingerprint
            fingerprints[key] = fingerprint
    faults = [line for line in raw if line.startswith("fault ")]
    assert len(faults) == 28
    for line in faults:
        role, status = re.search(r"role=(\d+).*status=([A-F0-9]+)", line).groups()
        assert int(status, 16) == expected[arch][int(role)], (arch, line)
        assert "exception=00000000" in line
    extended = (base / f"native-nls-vm-capture-{arch}.log").read_text().splitlines()
    unmaps = [line for line in extended if line.startswith("unmap ")]
    assert len(unmaps) == 12
    for line in unmaps:
        role, status = re.search(r"role=(\d+).*first=([A-F0-9]+)", line).groups()
        role = int(role)
        status = int(status, 16)
        required = 0 if role <= 2 else 0xC0000019 if role in (3, 4, 11) else (
            0xC0000024 if role in (6, 9) else 0xC0000008)
        assert status == required and "distinct=1" in line and "cleanup=00000000" in line
    protect = [line for line in extended if line.startswith("ntprotect ")]
    assert len(protect) == 9
    for line in protect:
        desired, status, old = re.search(r"desired=([A-F0-9]+) status=([A-F0-9]+) old=([A-F0-9]+)", line).groups()
        assert (int(status, 16), int(old, 16)) == ((0, 2) if int(desired, 16) == 2 else (0xC0000045, 1))
    for line in extended:
        if line.startswith("ntfree "):
            assert "status=C000001B" in line
        if line.startswith("ntcommit desired="):
            desired, status = re.search(r"desired=([A-F0-9]+) status=([A-F0-9]+)", line).groups()
            assert int(status, 16) == (0xC0000021 if int(desired, 16) == 2 else 0xC0000045)
    status_lines = [line for line in (base / f"native-nls-status-{arch}.log").read_text().splitlines() if line.startswith("status=")]
    assert len(status_lines) == 4
    for line in status_lines:
        status, error = re.search(r"status=([A-F0-9]+) dos=(\d+)", line).groups()
        assert int(error) == {0xC0000019: 487, 0xC000001B: 87, 0xC0000021: 5, 0xC0000045: 87}[int(status, 16)]
    print(f"{arch}: 126 matrix, 28 pointer, 12 lifetime, 9 protection and 4 RTL status rows verified")
print("all defined mapping fingerprints agree across native ARM64 and compatibility x86/x64")
