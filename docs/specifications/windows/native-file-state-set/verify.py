#!/usr/bin/env python3
"""Verify immutable control identities, selection, native leaves and byte runs."""
from pathlib import Path
import hashlib
import json


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "manifest-v1.json").read_text())
    for name, identity in manifest["files"].items():
        data = (root / name).read_bytes()
        assert len(data) == identity["bytes"] and digest(data) == identity["sha256"], name
    corpus = json.loads((root / "observations-v1.json").read_text())
    assert corpus["schema"] == "rax-native-file-state-set-replay-v1"
    assert len(corpus["scalars"]) == manifest["scalar_replay_cases"] == 12720
    assert len(corpus["faults"]) == manifest["fault_replay_cases"] == 9555
    for key, receipt in corpus["native_receipts"].items():
        kind, arch = key.split("-")
        source = (root / receipt["source"]).read_bytes()
        assert digest(source) == receipt["source_sha256"], key
        source = json.loads(source)
        assert receipt["image_sha256"] == source["binary"]["sha256"]
        for item in source["files"].values():
            assert digest(item["text"].encode()) == item["sha256"]
        counts = receipt["counts"]
        assert counts["handles_before"] == counts["handles_after"]
        assert counts["rows"] == receipt["native_cases"] == (9540 if kind == "scalars" else 3185)
        assert receipt["exit_code"] == 0
        leaf = bytes.fromhex(receipt["header"]["set_leaf"])
        if arch == "arm64":
            assert leaf[:8] == bytes.fromhex("e10400d4c0035fd6")
        elif arch == "x64":
            assert leaf[:8] == bytes.fromhex("4c8bd1b827000000")
        else:
            assert leaf[:5] == bytes.fromhex("b827000000") and bytes.fromhex("c21400") in leaf
    scalar_keys = {(r["arch"], r["role"], r["class"], r["sequence"], r["step"], r["length"]) for r in corpus["scalars"]}
    fault_keys = {(r["arch"], r["role"], r["class"], r["case"], r["length"]) for r in corpus["faults"]}
    assert len(scalar_keys) == 12720 and len(fault_keys) == 9555
    for row in corpus["scalars"]:
        assert row["class"] in (14, 16, 41, 43) and row["status"] != 0x103
        assert row["sequence"] == 1 or row["length"] in (0, 4, 8)
        assert bytes.fromhex(row["input_after"]) == bytes.fromhex(row["value"]) + bytes([0xA5] * 8)
    for row in corpus["faults"]:
        assert row["exception"] == 0 and row["status"] != 0x103
        assert row["class"] in (0, 14, 16, 41, 43, 90, 0xFFFFFFFF)
        assert (row["case"] == 0 and 0 <= row["length"] <= 12) or (0 <= row["case"] <= 21 and row["length"] == 512)
        for key, size in (("io_base", 64), ("input_base", 160), ("io_tail", 48), ("input_tail", 64)):
            touched = set()
            for offset, encoded in row[key].items():
                data, begin = bytes.fromhex(encoded), int(offset)
                assert data and 0 <= begin < begin + len(data) <= size
                positions = set(range(begin, begin + len(data)))
                assert not touched & positions and 0xA5 not in data
                touched |= positions
    for source in json.loads((root / "primary-sources-v1.json").read_text()):
        assert digest((root / source["file"]).read_bytes()) == source["sha256"]
    print("verified 22275 native scalar/fault replays, six source/image bindings and three ABIs")


if __name__ == "__main__":
    main()
