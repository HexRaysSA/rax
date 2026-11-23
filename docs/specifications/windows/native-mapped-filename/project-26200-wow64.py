"""Project the three immutable local-volume sweep logs into replay ranges."""

import hashlib
import json
import sys
from pathlib import Path

POISON = 0xA5
MODES = ("default", "enabled", "disabled")


def rows(path):
    for line in path.read_text().splitlines():
        if line.startswith("row="):
            values = dict(field.split("=", 1) for field in line.split())
            for field in ("length", "clip", "required", "returned"):
                values[field] = int(values[field])
            for field in ("status", "protect"):
                values[field] = int(values[field], 16)
            values["data"] = bytes.fromhex(values["data"])
            yield values


def project_subject(record):
    data = list(record)
    full = next(row["data"] for row in data if row["case"] == "length"
                and row["length"] == row["required"] and row["status"] == 0)
    name = full[8:-4]
    assert full[:8] == (len(name).to_bytes(2, "little")
                        + (len(name) + 2).to_bytes(2, "little")
                        + b"\x08\x00\x00\x00")
    assert full[-4:] == b"\x00\x00\xa5\xa5"
    ranges = {}
    for case in ("length", "noaccess", "guard"):
        output = []
        edge = 0 if case == "length" else 1
        for row in (r for r in data if r["case"] == case):
            value = row["length"] if case == "length" else row["clip"]
            assert value == edge
            assert row["required"] == len(full) - 2
            assert row["clip" if case == "length" else "length"] == 512
            observed = row["data"]
            prefix = len(observed.rstrip(bytes([POISON])))
            pointer = row["pointer"]
            expected = full[:4] + (b"\xfe" * 4 if pointer == "temporary" else full[4:8]) + full[8:]
            assert observed == expected[:prefix] + bytes([POISON]) * (len(full) - prefix)
            assert (prefix >= 8) == (pointer != "untouched")
            result = [row["status"], row["returned"], row["protect"], prefix, pointer]
            if output and output[-1][2:] == result:
                output[-1][1] = value
            else:
                output.append([value, value, *result])
            edge += 1
        assert edge == len(full)
        ranges[case] = output
    return {"name_utf16le": name.hex(), "ranges": ranges}


def main():
    evidence, destination = map(Path, sys.argv[1:])
    receipt = json.loads((evidence / "sweep-receipt.json").read_text())
    corpora = []
    for mode in MODES:
        path = evidence / "sweep" / f"{mode}.log"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == receipt["logs_sha256"][mode]
        raw = list(rows(path))
        assert len(raw) == receipt["rows"][mode] == 4760
        tags = dict.fromkeys(row["row"] for row in raw)
        assert len(tags) == 8
        subjects = {tag: project_subject(r for r in raw if r["row"] == tag) for tag in tags}
        group = next((record for record in corpora if record["subjects"] == subjects), None)
        if group is None:
            group = {"modes": [], "subjects": subjects}
            corpora.append(group)
        group["modes"].append(mode)
    result = {
        "schema": 1,
        "native_kernel": [10, 0, 26200],
        "native_machine": 0xAA64,
        "guest_machine": 0x014C,
        "github_actions_run": 45164298123,
        "receipt": receipt,
        "corpora": corpora,
    }
    destination.write_text(json.dumps(result, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
