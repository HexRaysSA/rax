"""Verify the 29708 native archive and emit the class-2 replay corpus.

Usage: project-29708.py frozen-inputs-v1.json mapped708-native-results-v1.zip
Uses O(B) time and space in the size B of the manifest and native archive.
"""

import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import zipfile


ARCHITECTURES = ("arm64", "x64", "x86")
RANGES = {
    7: range(48),
    2: range(48, 66),
    3: range(66, 77),
    4: range(77, 96),
    5: range(96, 124),
    6: range(124, 133),
    8: range(133, 197),
    9: range(133, 389),
}
BASELINE_CASE = {5: 4142, 9: 36}
INPUT_DIGEST = "7bcddae2be2ffaf33e3c1134bbf85de856df9551a2d5e47581a5bf4844666513"
ARCHIVE_DIGEST = "853f715d33881779c3f4771b199fec9adeaeaf019805b416ecc15f06a3280b6f"
ROWS_DIGEST = "8140b2c9360a9262c7887c4a2cff1c9c3e601c322cd7be7bb939d75f8f266383"
COVERAGE = {
    "complete-baseline": 24,
    "complete-query": 1359,
    "paired-baseline": 12,
    "paired-query": 402,
}
PROVIDERS = {
    r"C:\WINDOWS\System32\ntdll.dll": "ef1c9034813e18e5fb7cf6dc44802c15952d27dcecec46813ba883adda572f44",
    r"C:\WINDOWS\SyChpe32\ntdll.dll": "b832015dd1fc0e5c3822b79223887f3f945ab66cebeb760526ce8e904389b0ef",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(stream):
    raw = base64.b64decode(stream["base64"], validate=True)
    assert len(raw) == stream["bytes"] and sha(raw) == stream["sha256"]
    return raw


def row_key(row):
    return row["location"], row["arch"], row["version"], row["case"]


def short_name(observation, location, arch):
    name = bytes.fromhex(observation["name_hex"])
    assert name and len(name) % 2 == 0
    assert observation["status"] == 0 and observation["buffer_offset"] == observation["header_size"]
    assert observation["header_size"] == (8 if arch == "x86" else 16)
    assert observation["returned"] == observation["header_size"] + len(name) + 2
    assert observation["name_length"] == len(name) and observation["maximum_length"] == len(name) + 2
    device = "\\Device\\Mup\\" if location == "network" else "\\Device\\HarddiskVolume3\\"
    assert name.decode("utf-16le").startswith(device), name.decode("utf-16le")
    return name.hex()


def project(input_path, archive_path):
    inputs = input_path.read_bytes()
    assert sha(inputs) == INPUT_DIGEST
    manifest = json.loads(inputs)
    assert manifest["coverage"] == COVERAGE
    assert manifest["new_native_kernel"] == [10, 0, 29708] and manifest["revision"] == 1003
    assert manifest["native_machine"] == 0xAA64
    archive = archive_path.read_bytes()
    assert sha(archive) == ARCHIVE_DIGEST
    with zipfile.ZipFile(archive_path) as bundle:
        assert bundle.namelist() == ["mapped708-receipt-v1.json", "mapped708-rows-v1.jsonl"]
        receipt = json.loads(bundle.read("mapped708-receipt-v1.json"))
        raw_rows = bundle.read("mapped708-rows-v1.jsonl")
    assert sha(raw_rows) == receipt["raw_rows_sha256"] == ROWS_DIGEST
    assert receipt["kernel"] == manifest["new_native_kernel"] and receipt["revision"] == 1003
    assert receipt["provider_sha256"] == PROVIDERS
    assert receipt["volume"] == {"root": "C:\\", "filesystem": "NTFS", "serial": 0x2853EDE7}
    assert receipt["inputs_unchanged"] and receipt["inputs_sha256"] == INPUT_DIGEST
    assert receipt["phase"] == "finished" and receipt["completed"] == receipt["requested"] == 1701
    assert receipt["failed"] == 0 and receipt["passed_roles"] == COVERAGE
    rows = [json.loads(line) for line in raw_rows.splitlines()]
    assert len(rows) == len(manifest["rows"]) == 1701
    seen_processes, coverage, by_role = set(), Counter(), {role: {} for role in COVERAGE}
    for sequence, (row, task) in enumerate(zip(rows, manifest["rows"])):
        assert all(row[field] == task[field] for field in task)
        assert row["sequence"] == sequence and row["qualified"] and row["actual_wait_exit"] == 0
        image = manifest["images"][row["image"]]
        assert row["arch"] == image["arch"] and row["version"] == image["version"]
        assert row["executable_sha256"] == image["sha256"]
        pid_time = row["pid"], row["creation_filetime"]
        assert min(pid_time) > 0 and pid_time not in seen_processes
        seen_processes.add(pid_time)
        stdout, stderr = decode(row["stdout"]), decode(row["stderr"])
        observed = json.loads(stdout)
        assert not stderr and observed == row["observation"]
        assert observed["raised"] == 0 and observed["case"] == row["case"]
        expected_header = 8 if row["arch"] == "x86" else 16
        assert observed["header_size"] == expected_header
        record = {
            "location": row["location"],
            "arch": row["arch"],
            "version": row["version"],
            "case": row["case"],
            "exit_code": row["actual_wait_exit"],
            "native_pid": row["pid"],
            "creation_filetime": row["creation_filetime"],
            "observation": observed,
        }
        for role in row["roles"]:
            index = by_role[role]
            key = row_key(row)
            assert key not in index
            index[key] = dict(record, kind=role.split("-")[1])
            coverage[role] += 1
    assert coverage == Counter(COVERAGE)
    assert set(by_role["complete-query"]) == {
        ("network", arch, version, case)
        for arch in ARCHITECTURES for version, cases in RANGES.items() for case in cases
    }
    assert set(by_role["complete-baseline"]) == {
        ("network", arch, version, BASELINE_CASE.get(version, 0))
        for arch in ARCHITECTURES for version in RANGES
    }
    assert set(by_role["paired-baseline"]) == {
        (location, arch, version, BASELINE_CASE.get(version, 0))
        for location in ("local", "network") for arch in ARCHITECTURES for version in (5, 7)
    }
    assert set(by_role["paired-query"]) == {
        (location, arch, version, case)
        for location in ("local", "network") for arch in ARCHITECTURES
        for version, cases in ((5, range(62, 128)), (7, (5,))) for case in cases
    }
    groups = []
    for version, cases in RANGES.items():
        names = {
            arch: short_name(by_role["complete-baseline"][
                "network", arch, version, BASELINE_CASE.get(version, 0)
            ]["observation"], "local" if version == 9 else "network", arch)
            for arch in ARCHITECTURES
        }
        groups.append({
            "source_version": version,
            "replay_version": 1 if version == 7 else version,
            "corpus": {
                "cases": [by_role["complete-query"]["network", arch, version, case]
                          for arch in ARCHITECTURES for case in cases],
                ("subject_names" if version == 9 else "executable_names"): names,
            },
        })
    for (location, arch, _, _), base in by_role["paired-baseline"].items():
        short_name(base["observation"], location, arch)
    return {
        "schema": "native-mapped-filename-29708-v1",
        "kernel": receipt["kernel"],
        "revision": receipt["revision"],
        "native_machine": manifest["native_machine"],
        "archive": {"bytes": len(archive), "sha256": ARCHIVE_DIGEST, "native_rows_sha256": ROWS_DIGEST},
        "inputs_sha256": INPUT_DIGEST,
        "provider_sha256": PROVIDERS,
        "volume": receipt["volume"],
        "images": manifest["images"],
        "coverage": COVERAGE,
        "groups": groups,
        "complete_baselines": list(by_role["complete-baseline"].values()),
        "paired": list(by_role["paired-baseline"].values()) + list(by_role["paired-query"].values()),
    }


if __name__ == "__main__":
    assert len(sys.argv) == 3, __doc__
    json.dump(project(Path(sys.argv[1]), Path(sys.argv[2])), sys.stdout, indent=2)
    print()
