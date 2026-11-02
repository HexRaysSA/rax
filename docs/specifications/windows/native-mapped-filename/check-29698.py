"""Verify frozen inputs; optionally verify the three retained native archives.

Python 3.9+, standard library. O(B) time, O(M) memory for total decoded bytes B
and largest archive payload M. This does not execute native or emulator code.
"""
from contextlib import ExitStack
from pathlib import Path
import hashlib
import json
import struct
import sys
import zipfile

FOLDER = Path(__file__).resolve().parent
PROJECTION_SHA = "a712a0585ce36a06de07fc6da0c2bcf8eec71d1bcafcd6ae6c8d5d8eadec1372"
ARCHIVES = (
    ("de828f8572fac50fa9a07f8884873fe869073b70282065cc4d36b8106b54e6f0", 3473),
    ("ecf26399764d454f9a707b60c55ed691dc4b33a7a25db16c496eee4d705f8cc0", 117),
    ("13b67c99ce22bcc4fda5a62986a593c34ec20c776e57924eb2dd6a95a865e4c2", 95),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive(stack, path, expected):
    digest, count = expected
    assert sha(path.read_bytes()) == digest, "native archive identity"
    bundle = stack.enter_context(zipfile.ZipFile(path))
    manifest = json.loads(bundle.read("archive-manifest.json"))
    assert len(manifest) == count and bundle.testzip() is None
    names = bundle.namelist()
    assert len(names) == len(set(names)) == count + 1
    assert set(names) == set(manifest) | {"archive-manifest.json"}
    for name, identity in manifest.items():
        raw = bundle.read(name)
        assert len(raw) == identity["bytes"] and sha(raw) == identity["sha256"], name
    return bundle


def main():
    raw = (FOLDER / "profile-29698-v1.json").read_bytes()
    assert sha(raw) == PROJECTION_SHA
    data = json.loads(raw)
    assert data["kernel"] == [10, 0, 29698] and data["native_machine"] == 0xAA64
    assert data["native_queries"] == 1359 and data["native_images"] == 24
    assert data["baseline_capture"]["native_queries"] == 24
    for name, identity in data["sources"].items():
        if name.startswith("probe-") and name.endswith(".c"):
            source = (FOLDER / name).read_bytes()
            assert len(source) == identity["bytes"] and sha(source) == identity["sha256"], name
    for name, digest in (
        ("probe.cpp", "8a44e8ceb4d1cae3a51faf53039fecf840afb24eeb8b6c41251d187924d3e932"),
        ("CMakeLists.txt", "fd40ee3808370bf420e0902f15244164c64b779f21c6c017b8017cdca379bf07"),
    ):
        assert sha((FOLDER / "memcpy-body-v1" / name).read_bytes()) == digest
    ranges = {7: range(48), 2: range(48, 66), 3: range(66, 77),
              4: range(77, 96), 5: range(96, 124), 6: range(124, 133),
              8: range(133, 197), 9: range(133, 389)}
    keys = set()
    for group in data["groups"]:
        version = group["source_version"]
        assert group["replay_version"] == (1 if version == 7 else version)
        names = group["corpus"]["subject_names" if version == 9 else "executable_names"]
        assert set(names) == {"arm64", "x64", "x86"}
        for name in names.values():
            units = bytes.fromhex(name)
            assert units and len(units) % 2 == 0
        for row in group["corpus"]["cases"]:
            key = (row["arch"], version, row["case"])
            assert key not in keys
            keys.add(key)
            assert row["exit_code"] == 0 and row["observation"]["raised"] == 0
    assert keys == {(arch, version, case) for arch in ("arm64", "x64", "x86")
                    for version, cases in ranges.items() for case in cases}
    baselines = data["baseline_capture"]["values"]
    assert len(baselines) == 24
    for row in baselines:
        observation = row["observation"]
        name = bytes.fromhex(observation["name_hex"])
        assert observation["status"] == observation["raised"] == 0
        assert observation["returned"] == observation["header_size"] + len(name) + 2
        assert observation["case"] == (4142 if row["version"] == 5 else 0)
        assert row["role"] == ("kernel32" if row["version"] == 9 else "executable")
    if len(sys.argv) == 1:
        print("Verified frozen sources, 1359 query rows and 24 independent names; raw archives not checked.")
        return
    assert len(sys.argv) == 4, "usage: check-29698.py [queries.zip baselines.zip body.zip]"
    with ExitStack() as stack:
        query, baseline, body = [archive(stack, Path(path), expected)
                                 for path, expected in zip(sys.argv[1:], ARCHIVES)]
        receipt = json.loads(query.read("native/receipt.json"))
        assert receipt["state"] == "finished" and receipt["inputs_unchanged"]
        assert receipt["sources"] == data["sources"] and receipt["images"] == data["images"]
        assert receipt["providers"] == data["providers"]
        for name, identity in receipt["sources"].items():
            raw = query.read("native/source/" + name)
            assert len(raw) == identity["bytes"] and sha(raw) == identity["sha256"]
        for arch, provider in receipt["providers"].items():
            assert sha(query.read("providers/" + arch + "-ntdll.dll")) == provider["before_sha256"] == provider["after_sha256"]
        for group in data["groups"]:
            for row in group["corpus"]["cases"]:
                label = "%s-v%d-case%03d" % (row["arch"], group["source_version"], row["case"])
                stdout = query.read("native/" + label + ".stdout")
                stderr = query.read("native/" + label + ".stderr")
                assert sha(stdout) == row["stdout_sha256"] and not stderr
                assert sha(stderr) == row["stderr_sha256"] and json.loads(stdout) == row["observation"]
        for image in data["images"]:
            relative = image["path"].replace("\\", "/").split("/native-mapped-filename-29698-v1/", 1)[1]
            payload = query.read("native/" + relative)
            assert len(payload) == image["bytes"] and sha(payload) == image["sha256"]
            pe = struct.unpack_from("<I", payload, 60)[0]
            assert payload[pe:pe + 4] == b"PE\0\0"
            assert struct.unpack_from("<H", payload, pe + 4)[0] == {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[image["arch"]]
        receipt = json.loads(baseline.read("native/receipt.json"))
        assert receipt["state"] == "finished" and receipt["inputs_unchanged"]
        assert receipt["baselines"] == baselines
        for row in baselines:
            raw = baseline.read("native/%s-v%d-baseline.log" % (row["arch"], row["version"]))
            assert sha(raw) == row["stdout_sha256"] and json.loads(raw) == row["observation"]
        receipt = json.loads(body.read("native/receipt.json"))
        assert receipt["state"] == "finished" and receipt["inputs_unchanged"]
        assert receipt["samples"] == data["memcpy_body_snapshot"]["samples"]
        for name, identity in receipt["sources"].items():
            raw = body.read("native/source/" + name)
            assert len(raw) == identity["bytes"] and sha(raw) == identity["sha256"]
        for sample in receipt["samples"]:
            raw = body.read("native/body-" + sample["label"] + ".bin")
            assert len(raw) == 2048 and sha(raw) == sample["sha256"]
    print("Verified 3685 archive payloads, 1359 query rows, 24 names and two compiled memcpy-body captures.")


if __name__ == "__main__":
    main()
