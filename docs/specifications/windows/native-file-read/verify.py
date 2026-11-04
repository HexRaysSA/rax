"""Verify frozen independent normal-call captures, not emulation equivalence."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = json.loads((ROOT / "manifest-v1.json").read_text())
    for name, expected in manifest["sha256"].items():
        assert (ROOT / name).is_file(), name
        assert sha(ROOT / name) == expected, name
    corpus = json.loads((ROOT / "observations-v1.json").read_text())
    assert corpus["observations"] == 1980
    assert len(corpus["captures"]) == 6
    calls = 0
    for capture in corpus["captures"]:
        arch, kind = capture["arch"], capture["kind"]
        expected = 540 if kind == "scalars" else 120
        assert arch in {"arm64", "x64", "x86"}
        source = ROOT / f"source-{kind}-{arch}-v1.json"
        bundle = json.loads(source.read_text())
        assert sha(source) == capture["source_sha256"]
        assert bundle["binary"]["sha256"] == capture["image_sha256"]
        for recorded in bundle["files"].values():
            assert hashlib.sha256(recorded["text"].encode()).hexdigest() == recorded["sha256"]
        assert capture["header"]["pointer_bytes"] == (4 if arch == "x86" else 8)
        assert len(bytes.fromhex(capture["header"]["read_leaf"])) == 64
        if arch == "x86":
            assert "c22400" in capture["header"]["read_leaf"]
        assert capture["summary"]["rows"] == expected
        assert capture["summary"]["handles_before"] == capture["summary"]["handles_after"]
        assert len(capture["cases"]) == expected
        assert all(row["last_error"] == 0x6A1B2C3D for row in capture["cases"])
        calls += expected
    assert calls == 1980
    print("qualified independent capture:1980 calls, six source/image bindings; replay is a separate gate")


if __name__ == "__main__":
    main()
