#!/usr/bin/env python3
"""Validate retained native evidence without executing probes or guest code."""
import argparse
import hashlib
import json
from pathlib import Path


def load(root, name):
    return json.loads((root / name).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def output(row):
    assert row["exit_code"] == 0 and row["stderr"] == "", row
    if "stdout" in row:
        decoded = [json.loads(line) for line in row["stdout"].splitlines()]
        assert decoded == row.get("records", decoded), row
    else:
        decoded = row["records"]
    return decoded[-1]


def verify(root):
    matrix_receipt = load(root, "timed-lock-receipt-v13.json")
    lifetime_receipt = load(root, "timed-lock-lifetime-receipt-v14.json")
    current = load(root, "current-native-v1.json")
    offset = load(root, "offset-native-v1.json")
    ranges = load(root, "range-errors-native-v1.json")
    fields = load(root, "field-precedence-native-v1.json")
    assert matrix_receipt["state"] == lifetime_receipt["state"] == "finished"
    assert matrix_receipt["exit_code"] == 0
    assert matrix_receipt["inputs_unchanged"] and lifetime_receipt["inputs_unchanged"]
    assert sha(root / "timed-lock-probe-v13.c") == matrix_receipt["producer_sha256"]
    for path, expected in lifetime_receipt["source_sha256"].items():
        assert sha(root / Path(path).name) == expected, path
    assert current["state"] == "qualified" and current["exit_code"] == 0
    assert current["source_unchanged"] and not current["original_jobs_restarted"]
    assert current["host"][0] == offset["host"][0] == "Darwin"
    assert current["host"][4] == offset["host"][4] == "arm64"
    assert len(current["commands"]) == 4
    for command in current["commands"]:
        assert command["exit_code"] == 0 and command["stderr"] == ""
    for name, expected in current["source_sha256"].items():
        assert sha(root / name) == expected, name
    assert sha(root / "offset-probe-v1.c") == offset["source_sha256"]
    assert set(current["architectures"]) == {"arm64", "x86_64"}
    retained = {row["architecture"]: row for row in matrix_receipt["architectures"]}
    for arch in ("arm64", "x86_64"):
        matrix_name = f"timed-lock-records-{arch}-v13.json"
        lifetime_name = f"timed-lock-lifetime-records-{arch}-v14.json"
        assert sha(root / matrix_name) == retained[arch]["records_sha256"]
        assert sha(root / lifetime_name) == lifetime_receipt["observations"][arch]["sha256"]
        for kind, name, count in (("matrix", matrix_name, 144), ("lifetime", lifetime_name, 8)):
            previous = load(root, name)
            fresh = current["architectures"][arch][kind]
            assert len(previous) == len(fresh) == count
            unique = 142 if kind == "matrix" else 8
            assert len({json.dumps(row["input"], sort_keys=True) for row in fresh}) == unique
            image_hash = current["architectures"][arch][kind + "_image_sha256"]
            assert len(image_hash) == 64 and int(image_hash, 16) >= 0
            for old, new in zip(previous, fresh):
                assert old["input"] == new["input"]
                assert Path(new["argv"][0]).name == kind + "-" + arch
                assert new["argv"][2:] == old["argv"][2:]
                before, after = output(old), output(new)
                if kind == "matrix":
                    keys = ("result", "errno", "flock_bytes", "request_bytes", "request_unchanged")
                    assert after["flock_bytes"] == 24 and after["request_bytes"] == 40
                    assert after["request_unchanged"] is True
                else:
                    keys = ("lock_done_before_unlock", "close_done_before_unlock", "flags",
                            "flags_errno", "lock_result", "lock_errno", "close_result", "close_errno")
                    assert after["state"] in (3, 4)
                    assert after["duplicate_fd"] > after["original_fd"]
                assert all(before[key] == after[key] for key in keys), (arch, new)
        matrix = current["architectures"][arch]["matrix"]
        assert sum(not row["input"]["confined"] for row in matrix) == 136
    assert len(offset["builds"]) == 2 and len(offset["cases"]) == 8
    assert {build["arch"] for build in offset["builds"]} == {"arm64", "x86_64"}
    cases = set()
    for row in offset["cases"]:
        observed = output(row)
        arch, command, whence = row["arch"], observed["command"], observed["whence"]
        cases.add((arch, command, whence))
        assert row["argv"][2:] == [str(command), str(whence)]
        assert observed["entry_state"] in (3, 4)
        assert observed["result"] == observed["errno"] == observed["request_start"] == 0
        assert observed["request_whence"] == whence
        assert (observed["original_lock_type"], observed["changed_lock_type"]) == (3, 2)
        expected = (16, 32) if whence == 1 else (64, 96)
        assert (observed["original_offset"], observed["changed_offset"]) == expected
    assert cases == {(arch, command, whence) for arch in ("arm64", "x86_64")
                     for command in (10, 93) for whence in (1, 2)}
    assert sha(root / "range-errors-probe-v1.c") == ranges["source_sha256"]
    assert ranges["host"] == offset["host"]
    assert len(ranges["builds"]) == 2 and len(ranges["cases"]) == 32
    cases = set()
    for row in ranges["cases"]:
        observed = output(row)
        arch, command, whence, start = (row["arch"], observed["command"],
                                        observed["whence"], observed["start"])
        cases.add((arch, command, whence, start))
        assert row["argv"][2:] == [str(command), str(whence), str(start)]
        assert observed["unchanged"]
        error = 84 if start == (1 << 63) - 1 else 22 if start + (16 if whence == 1 else 64) < 0 else 0
        assert (observed["result"], observed["errno"]) == ((-1, error) if error else (0, 0))
    assert cases == {(arch, command, whence, start) for arch in ("arm64", "x86_64")
                     for command in (10, 93) for whence in (1, 2)
                     for start in ((1 << 63) - 1, -(1 << 63), -17, -16)}
    assert sha(root / "field-precedence-probe-v1.c") == fields["source_sha256"]
    assert fields["host"] == offset["host"]
    assert len(fields["builds"]) == 2 and len(fields["cases"]) == 36
    cases = set()
    for row in fields["cases"]:
        observed = output(row)
        arch, command, pid, kind, whence, start = (
            row["arch"], observed["command"], observed["pid"], observed["type"],
            observed["whence"], observed["start"])
        cases.add((arch, command, pid, kind, whence, start))
        assert row["argv"][2:] == list(map(str, (command, pid, kind, whence, start)))
        assert observed["unchanged"]
        error = 0 if pid else 84 if whence == 1 else 22
        assert (observed["result"], observed["errno"]) == ((-1, error) if error else (0, 0))
    expected = set()
    for arch in ("arm64", "x86_64"):
        for command in (10, 93):
            expected.update((arch, command, pid, 3, 0, 0) for pid in (1, -1, (1 << 31) - 1))
            expected.update((arch, command, 0, kind, whence, (1 << 63) - 1)
                            for kind in (0, 4) for whence in (1, 2))
            expected.update(((arch, command, 0, 0, 3, 0),
                             (arch, command, 0, 1, 3, (1 << 63) - 1)))
    assert cases == expected
    linux = load(root, "linux-pid-native-v1.json")
    assert linux["exit_code"] == 0 and linux["stderr"] == ""
    linux_result = json.loads(linux["stdout"])
    assert linux_result["rows"] == [{"pid": 1, "result": -1, "errno": 22},
                                    {"pid": 0, "result": 0, "errno": 0}]
    return {"native_matrix": 288, "native_lifetime": 16, "native_offset": 8, "native_range": 32,
            "native_fields": 36, "linux_adapter_controls": 2,
            "model_matrix": 272, "model_lifetime": 16, "model_offset": 8, "model_range": 32, "model_fields": 36,
            "x86_64_execution": "Rosetta on ARM64; physical Intel execution unverified"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent)
    print(json.dumps(verify(parser.parse_args().directory), sort_keys=True))
