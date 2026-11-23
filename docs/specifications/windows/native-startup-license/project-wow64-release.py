"""Project the recorded x86/native64 query matrices into a replay fixture."""

import hashlib
import itertools
import json
import sys
from pathlib import Path


PROFILES = {
    "windows-2022": (20348, 0x8664),
    "windows-2025": (26100, 0x8664),
    "windows-11-arm": (26200, 0xAA64),
}
NAMES = {
    "Kernel-OneCore-DeviceFamilyID": 4,
    "TerminalServices-RemoteConnectionManager-AllowAppServerMode": 4,
    "WindowsExcludedProcs": None,
    "Kernel-MUI-Number-Allowed": 4,
    "Kernel-MUI-Language-Allowed": 1,
    "Kernel-MUI-Language-Disallowed": 1,
    "Kernel-MUI-Language-SKU": 1,
}
CAPACITIES = [(0, True), (0, False), (3, False), (4, False), (12, False), (16, False),
              (770, False), (1024, False)]
GUARD = 8
ORIGINAL = bytes(ord("A") + index % 26 for index in range(1024 + 2 * GUARD))


def project(root, os, build, machine):
    folder = root / f"startup-policy-{os}"
    wow64 = (folder / "wow64.json").read_bytes()
    native64 = (folder / "native64.json").read_bytes()
    before = (folder / "inputs-before.txt").read_bytes()
    assert before == (folder / "inputs-after.txt").read_bytes(), os
    source = Path(__file__).with_name("probe-startup-matrix.rs").read_text(encoding="utf-8")
    checkout_hashes = [
        hashlib.sha256(source.replace("\n", newline).encode()).hexdigest()
        for newline in ["\n", "\r\n"]
    ]
    probe_hash, = (digest for digest in checkout_hashes if digest.upper().encode() in before)

    x86, native = (json.loads(raw) for raw in (wow64, native64))
    for raw, guest in [(x86, 0x14C), (native, 0)]:
        assert (raw["kernel"], raw["machine"], raw["guest"]) == ([10, 0, build], machine, guest)
    assert x86["rows"] == native["rows"], os

    lengths = {name: len(name.encode("utf-16-le")) for name in NAMES}
    values = {}
    for name, kind in NAMES.items():
        if kind is None:
            continue
        row, = (row for row in x86["rows"] if (
            row["name"] == name and row["maximum"] == lengths[name]
            and row["capacity"] == 1024 and row["has_type"]
        ))
        data = bytes.fromhex(row["changed"])
        assert row["offset"] == GUARD and len(data) == row["required"], row
        assert row["status"] == 0 and row["kind"] == kind, row
        assert (len(data) == 4 if kind == 4 else
                len(data) % 2 == 0 and data.endswith(b"\0\0")), row
        values[name] = data

    cases = (
        (name, spelling, extra, capacity, null_data, has_type)
        for name in NAMES
        for spelling, extra, (capacity, null_data), has_type in itertools.product(
            [name, name.lower()], [0, 2], CAPACITIES, [False, True])
    )
    for case, row in zip(cases, x86["rows"], strict=True):
        name, spelling, extra, capacity, null_data, has_type = case
        assert (row["name"], row["length"], row["maximum"]) == (
            spelling, lengths[name], lengths[name] + extra), row
        assert (row["capacity"], row["null_data"], row["has_type"]) == (
            capacity, null_data, has_type), row
        data = values.get(name) if spelling == name else None
        kind = 0xA5A5A5A5
        required = 0x5A5A5A5A
        status = 0xC0000034
        expected = bytearray(ORIGINAL)
        if data is not None:
            required = len(data)
            if has_type:
                kind = NAMES[name]
            status = 0xC0000023
            if capacity >= required:
                status = 0
                expected[GUARD:GUARD + required] = data
        actual = bytearray(ORIGINAL)
        changed = bytes.fromhex(row["changed"])
        offset = row["offset"]
        assert 0 <= offset <= offset + len(changed) <= len(actual), row
        actual[offset:offset + len(changed)] = changed
        assert (row["status"], row["kind"], row["required"]) == (status, kind, required), row
        assert actual == expected, row
    return {
        "build": build,
        "machine": machine,
        "rows": len(x86["rows"]),
        "wow64_sha256": hashlib.sha256(wow64).hexdigest(),
        "native64_sha256": hashlib.sha256(native64).hexdigest(),
        "probe_sha256": probe_hash,
        "input_identities_sha256": hashlib.sha256(before).hexdigest(),
        "values": {name: data.hex() for name, data in values.items()},
    }


if __name__ == "__main__":
    root = Path(sys.argv[1])
    captures = [project(root, os, build, machine) for os, (build, machine) in PROFILES.items()]
    print(json.dumps(captures, indent=2))
