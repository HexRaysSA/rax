#!/usr/bin/env python3
"""Validate retained independent CurrentVersion source/image/stdout identities."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    if not __debug__:
        raise SystemExit("Run this verifier without Python optimization (-O/-OO)")
    corpus = json.loads((ROOT / "controls-v1.json").read_text())
    assert corpus["schema"] == "rax-native-current-version-v1"
    assert corpus["native_cases"] == 1248
    assert [p["arch"] for p in corpus["profiles"]] == ["arm64", "x64", "x86"]
    assert len(corpus["bindings"]) == 9
    count = 0
    for profile in corpus["profiles"]:
        for family, expected in [("profile", [136, 48]), ("parents", [48, 48]), ("physical", [136])]:
            records = profile[family]
            assert [len(r["rows"]) for r in records] == expected
            assert all(r["handles_before"] == r["handles_after"] for r in records)
            binding, = [b for b in corpus["bindings"] if b["arch"] == profile["arch"] and b["kind"] == family]
            path = ROOT / binding["source_file"]
            assert path.resolve().is_relative_to(ROOT)
            data = path.read_bytes()
            assert sha(data) == binding["source_sha256"]
            source = json.loads(data)
            assert source["binary"]["sha256"] == binding["image_sha256"]
            for name, item in source["files"].items():
                raw = item["text"].encode()
                assert sha(raw) == item["sha256"], name
                if name.endswith((".c", ".h")):
                    assert (ROOT / Path(name).name).read_bytes() == raw, name
            stdout = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records)
            assert sha(stdout.encode()) == binding["stdout_sha256"]
            count += sum(expected)
    assert count == corpus["native_cases"]
    print(f"Verified {count} independent CurrentVersion cases and 9 source/image/stdout bindings")

if __name__ == "__main__":
    main()
