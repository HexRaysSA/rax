"""Read-only verification of native class26 capture identity and decoded rows."""

import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text())


def digest(name):
    return hashlib.sha256((ROOT / name).read_bytes()).hexdigest()


def raw(name):
    record = read(name)
    data = base64.b64decode(record["stdout_base64"], validate=True)
    assert len(data) == record["stdout_bytes"]
    assert hashlib.sha256(data).hexdigest() == record["stdout_sha256"]
    return data


def completed(receipt):
    assert receipt["state"] == "finished" and receipt["exit_code"] == 0
    assert receipt["inputs_unchanged"]
    assert all(row["exit_code"] == 0 for row in receipt["commands"])
    assert receipt["kernel"][:3] == [10, 0, 29695]


def main():
    profiles = read("local-29695-v1.json")
    assert len(profiles) == 6
    total = 0
    pebs = set()
    for profile in profiles:
        arch, family = profile["arch"], profile["family"]
        name = (
            f"raw-v1-{arch}.json"
            if family == "default-v1"
            else f"raw-family-v2-{family.removesuffix('-v2')}.json"
        )
        rows = [json.loads(line) for line in raw(name).splitlines()]
        assert rows == profile["rows"]
        cases = [row for row in rows if row["kind"] == "case"]
        expected = 433 if family != "default-v1" else 405 if arch == "x86" else 409
        assert len(cases) == expected
        assert [row["ordinal"] for row in cases] == list(range(expected))
        assert rows[-1] == {"kind": "complete", "cases": expected}
        assert rows[0]["build"] == 29695 and rows[0]["query_class"] == 26
        assert rows[0]["pointer_bytes"] == (4 if arch == "x86" else 8)
        assert all(row["query_class"] == 26 and row["exception"] == 0 for row in cases)
        identity = next(row for row in rows if row["kind"] == "identity")
        assert identity["basic_status"] == identity["wow64_status"] == 0
        assert identity["wow64_returned"] == rows[0]["pointer_bytes"]
        if arch == "x86":
            assert identity["wow64_information"] == identity["peb_from_basic"] != 0
            pebs.add(identity["peb_from_basic"])
        else:
            assert identity["wow64_information"] == 0
        total += expected
    assert total == 2522 and len(pebs) == 4

    matrix = read("matrix-receipt-v1.json")
    family = read("family-receipt-v2.json")
    observer = read("stopped-observer-receipt-v3.json")
    for receipt in (matrix, family, observer):
        completed(receipt)
    assert digest("native-query-v1.cpp") == matrix["source_sha256"]
    assert digest("matrix-controller-v1.py") == matrix["driver_sha256"]
    names = {
        "child.cpp": "native-query-v3.cpp",
        "probe.cpp": "native-family-launcher-v2.cpp",
        "driver.py": "family-controller-v2.py",
    }
    for path, value in family["inputs_sha256"].items():
        name = PureWindowsPath(path).name
        if name in names:
            assert digest(names[name]) == value
    assert digest("stopped-observer-v3.rs") == observer["source_sha256"]
    assert digest("stopped-observer-controller-v3.py") == observer["driver_sha256"]
    stopped = raw("stopped-observer-v3.json").decode()
    assert "NtQueryInformationProcess class 26" in stopped
    assert "peb=0x7ffdf000" in stopped
    assert "class=26" in stopped and "bytes=4 returned=0x0" in stopped
    print(
        f"verified {total} calls, {len(profiles)} views, {len(pebs)} distinct PEB32 identities"
    )


if __name__ == "__main__":
    main()
