"""Project native installed UI-language observations into one replay matrix."""

import hashlib
import json
import re
import sys
from pathlib import Path, PureWindowsPath


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_run(path, guest, machine, provider):
    header, *lines = path.read_text().splitlines()
    pattern = rf"profile guest={guest} native={machine} provider=(.*)"
    mapped = PureWindowsPath(re.fullmatch(pattern, header)[1])
    assert mapped.name.lower() == "ntdll.dll"
    assert mapped.parent.name.lower() == provider

    commits = []
    rows = []
    langid = None
    for line in lines:
        kind, *values = line.split()
        fields = dict(value.split("=", 1) for value in values)
        if kind == "commit":
            assert int(fields["index"]) == len(commits)
            assert int(fields["error"], 16) == 0x1234
            commits.append(int(fields["status"], 16))
        elif kind == "public":
            assert langid is None
            langid = int(fields["langid"], 16)
        else:
            assert kind == "query", fields
            row = {
                "case": fields["case"],
                "status": int(fields["status"], 16),
                "last_error": int(fields["error"], 16),
                "protection": int(fields["protection"], 16),
                "bytes": list(bytes.fromhex(fields["bytes"])),
            }
            assert row["last_error"] == 0x1234
            assert len(row["bytes"]) == 4
            rows.append(row)
    assert langid is not None and len(commits) == 3 and len(set(commits)) == 1
    assert [row["case"] for row in rows] == [
        "aligned", "unaligned", "null", "readonly", "cross-page",
        "write-guard", "write-guard-retry", "readonly-guard",
    ]
    low, high = langid.to_bytes(2, "little")
    assert rows[0]["bytes"] == [low, high, 0xa5, 0xa5]
    assert rows[1]["bytes"] == [0xa5, low, high, 0xa5]
    return {"langid": langid, "wow64_status": commits, "rows": rows}


def identity(before, after):
    records = json.loads(before.read_bytes())
    assert records == json.loads(after.read_bytes())
    return {
        str(PureWindowsPath(row["Path"])).lower(): row["Hash"].lower()
        for row in records
    }


def provider_hash(inputs, provider):
    hash_, = (value for path, value in inputs.items()
              if path.endswith(rf"\{provider}\ntdll.dll"))
    assert len(hash_) == 64
    return hash_


def source_hash(inputs):
    name = Path(__file__).with_name("probe-wow64-ui-languages.rs").name
    hash_, = (value for path, value in inputs.items()
              if PureWindowsPath(path).name == name)
    return hash_


def executable_hashes(folder):
    results = {}
    for line in (folder / "executables.sha256").read_text().splitlines():
        hash_, path = line.split(" *", 1)
        assert re.fullmatch(r"[0-9a-f]{64}", hash_)
        results[PureWindowsPath(path).name] = hash_
    assert set(results) == {"native64.exe", "wow64.exe"}
    return results


def main():
    root = Path(sys.argv[1])
    pure = Path(sys.argv[2])
    controls = []
    matrix = None
    for os, build, machine, provider in [
        ("windows-2022", 20348, 0x8664, "syswow64"),
        ("windows-2025", 26100, 0x8664, "syswow64"),
        ("windows-11-arm", 26200, 0xaa64, "sychpe32"),
    ]:
        folder = root / f"wow64-ui-language-{os}"
        wow64, native64 = (folder / file for file in ("wow64.log", "native64.log"))
        observed = read_run(wow64, 0x14c, machine, provider)
        assert observed == read_run(native64, 0, machine, "system32")
        if matrix is None:
            matrix = observed
        assert observed == matrix
        inputs = identity(folder / "inputs-before.json", folder / "inputs-after.json")
        # The original run used the stdout-only producer from 55ba2a829.
        producer = source_hash(inputs)
        assert producer == "cc9412340303f295f0fb3ee5594fa8460eb2acdaa117c77a454fb97bce0e013a"
        controls.append({
            "kernel": [10, 0, build],
            "native_machine": machine,
            "x86_provider": provider,
            "x86_provider_sha256": provider_hash(inputs, provider),
            "native_provider_sha256": provider_hash(inputs, "system32"),
            "source_sha256": producer,
            "executables_sha256": executable_hashes(folder),
            "wow64_log_sha256": digest(wow64),
            "native64_log_sha256": digest(native64),
            "input_identities_sha256": digest(folder / "inputs-before.json"),
        })
    inputs = identity(pure / "before.json", pure / "after.json")
    producer = source_hash(inputs)
    assert producer == digest(Path(__file__).with_name("probe-wow64-ui-languages.rs"))
    executables = {
        PureWindowsPath(row["Path"]).name: row["Hash"].lower()
        for row in json.loads((pure / "executables.json").read_bytes())
    }
    assert set(executables) == {"launcher.exe", "observe.exe"}
    for file, provider in [("disabled.log", "syswow64"), ("enabled.log", "sychpe32")]:
        assert read_run(pure / file, 0x14c, 0xaa64, provider) == matrix
    matrix["installed_controls"] = controls
    matrix["pure_arm64"] = {
        "kernel": [10, 0, 26200],
        "native_machine": 0xaa64,
        "x86_provider": "syswow64",
        "x86_provider_sha256": provider_hash(inputs, "syswow64"),
        "source_sha256": producer,
        "executables_sha256": executables,
        "x86_log_sha256": digest(pure / "disabled.log"),
        "translated_log_sha256": digest(pure / "enabled.log"),
        "input_identities_sha256": digest(pure / "before.json"),
    }
    print(json.dumps(matrix, indent=2))


if __name__ == "__main__":
    main()
