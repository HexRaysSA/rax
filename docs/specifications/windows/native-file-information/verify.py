#!/usr/bin/env python3
"""Verify native-control identities, dimensions, leaves, and sparse bytes."""
from pathlib import Path
import hashlib
import json


def main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "manifest-v1.json").read_text())
    for name, identity in manifest["files"].items():
        data = (root / name).read_bytes()
        assert len(data) == identity["bytes"], name
        assert hashlib.sha256(data).hexdigest() == identity["sha256"], name
    corpus = json.loads((root / "observations-v1.json").read_text())
    assert corpus["schema"] == "rax-native-file-information-replay-v1"
    for name, digest in corpus["sources"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
    cases = corpus["cases"]
    assert len(cases) == manifest["replay_cases"] == 19776
    identities = {(r["arch"], r["role"], r["class"], r["length"], r["case"]) for r in cases}
    assert len(identities) == len(cases)
    classes = {0, 4, 5, 6, 7, 8, 14, 16, 17, 34, 35, 41, 43, 51, 90, 0xFFFFFFFF}
    roles = {"console.in", "null", "event", "invalid"}
    for arch in ("arm64", "x64", "x86"):
        receipt = corpus["native_receipts"][arch]
        counts = receipt["handle_counts"]
        assert counts["before_queries"] == counts["after_queries"]
        assert counts["before_queries"] - counts["handles_after"] == counts["owned_handles_closed"] == 7
        assert receipt["total_native_cases"] == 14420
        leaf = bytes.fromhex(receipt["header"]["query_entry"])
        if arch == "x86":
            assert leaf[:5] == bytes.fromhex("b811000000")
            assert bytes.fromhex("c21400") in leaf
        elif arch == "x64":
            assert leaf[:8] == bytes.fromhex("4c8bd1b811000000")
        else:
            assert leaf[:8] == bytes.fromhex("210200d4c0035fd6")
        for role in roles:
            for information_class in classes:
                selected = [r for r in cases if (r["arch"], r["role"], r["class"]) == (arch, role, information_class)]
                assert len(selected) == 103
    for row in cases:
        assert row["exception"] == 0 and row["status"] != 0x103
        assert row["class"] in classes and row["role"] in roles
        assert (row["case"] == 0 and (0 <= row["length"] <= 80 or row["length"] == 512)) or (1 <= row["case"] <= 21 and row["length"] == 512)
        for key, size in (("io_base", 64), ("data_base", 160), ("io_tail", 48), ("data_tail", 64)):
            touched = set()
            for offset, encoded in row[key].items():
                data = bytes.fromhex(encoded)
                begin = int(offset)
                assert data and 0 <= begin < begin + len(data) <= size
                positions = set(range(begin, begin + len(data)))
                assert not touched & positions
                touched |= positions
                assert 0xA5 not in data
    print(f"verified {len(cases)} independent native caller-memory cases and three installed leaves")


if __name__ == "__main__":
    main()
