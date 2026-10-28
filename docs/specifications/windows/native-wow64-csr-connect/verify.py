"""Verify preserved producer identities and native CSR corpus projections.

Read-only, standard-library Python; O(B) time/storage for B captured bytes.
This verifies the evidence handoff, not a fresh native or shipping runtime.
"""

from pathlib import Path
import base64
import hashlib
import json

ROOT = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load(name):
    return json.loads((ROOT / name).read_bytes())


def fields(line):
    return dict(word.split("=", 1) for word in line.split()[1:] if "=" in word)


def stdout(raw, name):
    return base64.b64decode(raw["logs"][name], validate=True)


def terminal(raw):
    receipt = raw["receipt"]
    assert receipt["state"] == "finished" and receipt["exit_code"] == 0
    assert receipt["inputs_unchanged"] and receipt["kernel"][:3] == [10, 0, 29695]
    assert all(command["exit_code"] == 0 for command in receipt["commands"])
    return receipt


def main():
    identities = load("artifact-identities.json")
    for name, expected in identities.items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) == expected["bytes"] and digest(raw) == expected["sha256"], name

    original = load("initial-raw-v4.json")
    receipt = terminal(original)
    assert digest((ROOT / "initial-v4.cpp").read_bytes()) == receipt["source_sha256"]
    assert (
        digest((ROOT / "initial-driver-v4.py").read_bytes()) == receipt["driver_sha256"]
    )
    assert (
        "4a0f28a1fba11a97b7498f6bf5b231d32c124ce15d2bcb90084816e342c09544"
        in receipt["installed_ntdll_sha256"].values()
    )
    raw = stdout(original, "arm64-observe.log")
    assert digest(raw) == receipt["samples"][0]["stdout_sha256"]
    lines = raw.decode().splitlines()
    assert "rva=77490" in next(line for line in lines if line.startswith("INSTALLED "))
    assert fields(lines[-1])["exit"] == "0"

    cases = returns = 0
    for version in [8, 9]:
        raw = load(f"initial-raw-v{version}.json")
        receipt = terminal(raw)
        corpus = load(f"initial-29695-v{version}.json")
        assert corpus["source_sha256"] == receipt["inputs_sha256"]
        assert corpus["binary_sha256"] == receipt["binary_sha256"]
        assert corpus["compiler_sha256"] == receipt["compiler_sha256"]
        for original_name, expected in receipt["inputs_sha256"].items():
            name = original_name.replace("\\", "/").rsplit("/", 1)[-1]
            source = {
                "probe.cpp": f"initial-v{version}.cpp",
                "driver.py": f"initial-driver-v{version}.py",
                "child.cpp": "initial-child-v1.cpp",
            }.get(name)
            if source:
                assert digest((ROOT / source).read_bytes()) == expected
        total = 0
        for sample in corpus["samples"]:
            text = stdout(raw, sample["mode"] + ".log")
            assert digest(text) == sample["stdout_sha256"]
            lines = text.decode().splitlines()
            assert lines[-1] == sample["terminal"]
            assert fields(lines[-1])["exit"] == "70"
            observed = [fields(line) for line in lines if line.startswith("RETURN ")]
            deltas = [fields(line) for line in lines if line.startswith("PEB_DELTA ")]
            assert len(observed) == len(deltas) == len(sample["steps"])
            for result, delta, step in zip(observed, deltas, sample["steps"]):
                assert int(result["ordinal"]) == step["ordinal"]
                assert result["status"] == step["status"]
                assert list(map(int, delta["handles"].split(":"))) == [
                    step["handles_before"],
                    step["handles_after"],
                ]
                assert int(delta["changed64"]) == step["changed64"]
                assert int(delta["changed32"]) == step["changed32"]
            total += len(observed)
        assert len(corpus["samples"]) == corpus["case_count"]
        assert total == corpus["return_count"]
        cases += len(corpus["samples"])
        returns += total
    assert (cases, returns) == (31, 38)

    raw = load("family-raw-v2.json")
    receipt = terminal(raw)
    projections = []
    for sample in receipt["samples"]:
        text = stdout(raw, sample["mode"] + ".log")
        assert digest(text) == sample["stdout_sha256"]
        lines = text.decode().splitlines()
        assert lines[-1] == "DONE calls=112"
        rows = [fields(line) for line in lines if line.startswith("CASE ")]
        assert len(rows) == sample["rows"] == 112
        projections.append(rows)
    assert len(projections) == 3 and projections[0] == projections[1] == projections[2]

    volume = load("volume-control-v1.json")
    assert volume["exit_code"] == 0
    assert (
        digest((ROOT / "volume-control-v1.py").read_bytes()) == volume["source_sha256"]
    )
    observed = json.loads(volume["stdout"])
    assert (observed["status"], observed["information"], observed["position"]) == (
        0,
        8,
        7,
    )
    assert (observed["device"], observed["characteristics"]) == (7, 0x00220020)
    print(
        f"Verified {len(identities)} artifact identities; {cases} fresh/retry cases, {returns} returns; 336 repeated calls; original native exit0; separate volume flags 0x00220020."
    )


if __name__ == "__main__":
    main()
