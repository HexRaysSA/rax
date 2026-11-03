"""Check native corpus bindings and shape; this does not authenticate execution."""
from pathlib import Path
import hashlib
import json
import sys

COUNTS = {"scalar": 492, "pointer": 367, "masks": 224,
          "identity": 24, "effects": 60, "existing-ea": 12, "mutating-pointer": 1101,
          "metadata-share": 36}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(directory):
    manifest = json.loads((directory / "manifest-v1.json").read_text())
    assert manifest["schema"] == "rax-native-file-create-oracles-v1"
    sources = manifest["sources"]
    assert len(sources) == 8
    for source, digest in sources.items():
        assert Path(source).name == source
        assert sha((directory / source).read_bytes()) == digest, source
    assert len(manifest["corpora"]) == 24
    total = 0
    for family, count in COUNTS.items():
        source = f"native-file-create-{family}-v{2 if family == 'scalar' else 1}.cpp"
        for arch in ("arm64", "x64", "x86"):
            name = f"{family}-{arch}-v1.json"
            binding = manifest["corpora"][name]
            raw = (directory / name).read_bytes()
            assert sha(raw) == binding["sha256"], name
            data = json.loads(raw)
            assert data["source_sha256"] == binding["source_sha256"] == sources[source]
            assert data["image_sha256"] == binding["image_sha256"]
            assert len(data["image_sha256"]) == 64
            profile, cases = data["profile"], data["cases"]
            assert profile["kind"] == "profile"
            assert profile["pointer_bytes"] == binding["pointer_bytes"] == (4 if arch == "x86" else 8)
            assert len(cases) == binding["cases"] == count, name
            assert [c["index"] for c in cases] == list(range(count)), name
            for case in cases:
                assert case["kind"] == "case" and case["exception"] == "0x00000000", name
                if family in ("pointer", "mutating-pointer"):
                    assert len(case["roles"]) == 8 and len(case["protections"]) == 16, name
                    for offset, encoded in case["changes"]:
                        assert 0 <= offset < 65536 and offset + len(bytes.fromhex(encoded)) <= 65536
            stdout = "".join(json.dumps(record, separators=(",", ":")) + "\n"
                             for record in [profile, *cases])
            assert sha(stdout.encode()) == data["stdout_sha256"] == binding["stdout_sha256"], name
            total += count
    assert total == 6948
    return {"corpora": 24, "sources": 8, "native_calls": total}


if __name__ == "__main__":
    directory = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    print(json.dumps(verify(directory), sort_keys=True))
