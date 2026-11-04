"""Verify independent native inputs and reconstruct byte-exact stdout frames.

O(B) time and O(B) scratch, bounded by the archived evidence size B.
No product code or product-generated expected values are consulted.
"""
from pathlib import Path
import hashlib
import json


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(directory=None):
    root = Path(directory) if directory else Path(__file__).resolve().parent
    manifest = json.loads((root / "manifest-v1.json").read_text())
    assert manifest["schema"] == "rax-native-file-data-section-oracles-v1"
    expected = {"scalar": 1134, "coherence": 45, "details": 1950,
                "transitions": 448, "query": 1584, "status": 6, "post-copy": 72, "share": 135}
    seen = set()
    total = 0
    for name, identity in {**manifest["sources"], **manifest["build_input_bundles"]}.items():
        data = (root / name).read_bytes()
        assert len(data) == identity["bytes"] and sha(data) == identity["sha256"], name
    for record in manifest["corpora"]:
        family, arch = record["family"], record["arch"]
        assert arch in ("arm64", "x64", "x86") and (family, arch) not in seen
        seen.add((family, arch))
        data = (root / record["path"]).read_bytes()
        assert len(data) == record["bytes"] and sha(data) == record["sha256"], record["path"]
        corpus = json.loads(data)
        rows = corpus["cases"]
        assert len(rows) == record["cases"] == expected[family]
        assert [row["index"] for row in rows] == list(range(len(rows)))
        assert corpus["profile"]["pointer_bytes"] == (4 if arch == "x86" else 8)
        raw = "\n".join(json.dumps(row, separators=(",", ":"))
                        for row in [corpus["profile"], *rows]) + "\n"
        assert sha(raw.encode()) == corpus["stdout_sha256"] == record["stdout_sha256"]
        assert corpus["image_sha256"] == record["image_sha256"]
        source = (root / record["source_path"]).read_bytes()
        assert sha(source) == corpus["source_sha256"] == record["source_bundle_sha256"]
        if record["source_path"].endswith(".json"):
            bundle = json.loads(source)
            inputs = bundle.get("inputs")
            if inputs is None:
                if isinstance(bundle["files"], dict):
                    inputs = {Path(name).name: {"utf8": entry["text"], "sha256": entry["sha256"]}
                              for name, entry in bundle["files"].items()}
                else:
                    inputs = {entry["name"]: entry for entry in bundle["files"]}
            image = bundle.get("image", bundle.get("binary"))
            assert image["sha256"] == corpus["image_sha256"]
            for name, entry in inputs.items():
                encoded = entry["utf8"].encode()
                assert sha(encoded) == entry["sha256"], name
                if name != "CMakeLists.txt" and not name.endswith(".cmake"):
                    assert encoded == (root / name).read_bytes(), name
            assert record["core_source_path"] in inputs
        else:
            assert record["source_path"] == record["core_source_path"]
        assert all(row.get("exception", "0x00000000") == "0x00000000" for row in rows)
        total += len(rows)
    assert seen == {(family, arch) for family in expected for arch in ("arm64", "x64", "x86")}
    assert total == manifest["total_cases"] == 16122
    return total


if __name__ == "__main__":
    print(f"Verified {verify()} independent native cases and their source/image/stdout bindings")
