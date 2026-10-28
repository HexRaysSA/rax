"""Read-only native setter corpus, producer and reference provenance checks."""

import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text())


def digest(name):
    return hashlib.sha256((ROOT / name).read_bytes()).hexdigest()


def completed(v):
    assert v["state"] == "finished" and v["exit_code"] == 0 and v["inputs_unchanged"]
    assert all(r["exit_code"] == 0 for r in v["commands"])
    assert v["kernel"][:3] == [10, 0, 29695]


def main():
    data = read("local-29695-v1.json")
    assert len(data) == 9
    total = 0
    for profile in data:
        arch, family = profile["arch"], profile["family"]
        if family in ("default-v1", "default-v2"):
            name = f"raw-v{family[-1]}-{arch}.json"
            expected = 574 if family == "default-v1" else 594
        else:
            name = f"raw-family-v1-{family.removesuffix('-family-v1')}.json"
            expected = 594
        v = read(name)
        raw = base64.b64decode(v["stdout_base64"], validate=True)
        assert (
            len(raw) == v["stdout_bytes"]
            and hashlib.sha256(raw).hexdigest() == v["stdout_sha256"]
        )
        rows = [json.loads(x) for x in raw.splitlines()]
        assert rows == profile["rows"]
        cases = [r for r in rows if r["kind"] == "case"]
        assert len(cases) == expected
        assert rows[-1] == {"kind": "complete", "cases": expected}
        assert [r["ordinal"] for r in cases] == list(range(expected))
        assert rows[0]["build"] == 29695 and rows[0]["nx_compat"]
        assert rows[0]["pointer_bytes"] == (4 if arch == "x86" else 8)
        assert rows[0]["execute_flags"] == 13 and rows[0]["permanent"]
        assert all(
            r["before"] == r["after"] == 13 and r["exception"] == 0 for r in cases
        )
        total += expected
    assert total == 5286
    for ver in (1, 2):
        r = read(f"matrix-receipt-v{ver}.json")
        completed(r)
        assert digest(f"native-set-v{ver}.cpp") == r["source_sha256"]
        assert digest(f"matrix-controller-v{ver}.py") == r["driver_sha256"]
    r = read("family-receipt-v1.json")
    completed(r)
    files = {
        "child.cpp": "native-set-v2.cpp",
        "probe.cpp": "family-launcher-v2.cpp",
        "driver.py": "family-controller-v1.py",
    }
    for path, value in r["inputs_sha256"].items():
        name = PureWindowsPath(path).name
        if name in files:
            assert digest(files[name]) == value
    stopped = read("stopped-observer-v1.json")
    completed(stopped["receipt"])
    assert digest("stopped-observer-v1.rs") == stopped["receipt"]["source_sha256"]
    assert (
        digest("stopped-observer-controller-v1.py")
        == stopped["receipt"]["driver_sha256"]
    )
    output = base64.b64decode(stopped["logs"]["observe.log"], validate=True).decode()
    assert "NtSetInformationProcess class 34" in output
    assert "class=34" in output and "bytes=4" in output
    assert "DEPSET_OUTPUT Ok([10, 0, 0, 0])" in output
    bound = read("native-handle-boundary-v1.json")
    assert bound["exit_code"] == 0 and not bound["stderr"]
    assert digest("native-handle-boundary-v1.py") == bound["source_sha256"]
    extra = json.loads(bound["stdout"])
    assert len(extra["rows"]) == 8
    assert all(r["policy_after"] == 13 and r["input"] == 10 for r in extra["rows"])
    header = base64.b64decode(
        (ROOT / "references/phnt-ntmmapi.raw.b64").read_text(), validate=False
    )
    reference = read("references/ntmmapi-source.json")
    assert len(header) == reference["raw_bytes"]
    assert hashlib.sha256(header).hexdigest() == reference["raw_sha256"]
    assert (
        hashlib.sha1(f"blob {len(header)}\0".encode() + header).hexdigest()
        == reference["git_blob"]
    )
    print(
        f"verified {total} calls in nine views, eight native handle boundaries, original packet and pinned reference"
    )


if __name__ == "__main__":
    main()
