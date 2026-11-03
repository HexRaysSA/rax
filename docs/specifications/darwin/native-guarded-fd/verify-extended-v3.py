"""Verify extended native acquisition records on Python 3.9+ on any host."""

import hashlib
import json
from pathlib import Path
import runpy


CAMPAIGNS = [("edge", 3, 296), ("fdinfo", 4, 32), ("spawn", 5, 32),
             ("inherit", 6, 8), ("devfd", 7, 198),
             ("devfd-directory", 8, 6), ("devfd-alias", 9, 48)]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    base = Path(__file__).resolve().parent
    root = base.parents[3]
    runpy.run_path(str(base / "verify-v2.py"), run_name="__main__")
    manifest = json.loads((base / "extended-payload-sha256-v3.json").read_text())
    for name, expected in manifest.items():
        path = base / name
        assert base in path.resolve().parents and not path.is_symlink(), name
        assert path.stat().st_size == expected["bytes"], name
        assert digest(path) == expected["sha256"], name
    total = 0
    for name, version, count in CAMPAIGNS:
        receipt = json.loads((base / (name + "-receipt-v" + str(version) + ".json")).read_text())
        assert receipt["state"] == "finished" and receipt["exit_code"] == 0
        source = base / (name + "-probe-v" + str(version) + ".c")
        if "inputs" in receipt:
            for relative, expected in receipt["inputs"].items():
                path = (root / relative).resolve()
                assert base in path.parents and digest(path) == expected, relative
        else:
            assert digest(source) == receipt["source_sha256"]
        assert [row["architecture"] for row in receipt["architectures"]] == ["arm64", "x86_64"]
        for identity in receipt["architectures"]:
            records_path = base / (name + "-records-" + identity["architecture"] + "-v" + str(version) + ".json")
            assert digest(records_path) == identity["records_sha256"]
            records = json.loads(records_path.read_text())
            assert len(records) == identity["cases"] == count
            assert len({tuple(case["argv"]) for case in records}) == count
            for case in records:
                assert case["exit_code"] in (0, -9), (name, case)
                rows = ([json.loads(line) for line in case["stdout"].splitlines()]
                        if "stdout" in case else case.get("records", [case.get("record")]))
                assert rows and all(isinstance(row, dict) and "kind" in row for row in rows)
                for row in rows:
                    if row["kind"] == "guard-exception":
                        assert case["exit_code"] == -9 and row["exception"] == 12 and row["count"] == 2
                        assert int(row["code"], 16) >> 61 == 2
                        assert row["subcode"] == "0x1122334455667788"
            total += len(records)
    assert total == 1240
    print(json.dumps({"verified_extended_payloads": len(manifest),
                      "native_extended_cases": total, "native_extended_abi_campaigns": 14,
                      "scope": "Frozen native controls; no emulator conformance claim."}))


if __name__ == "__main__":
    main()
