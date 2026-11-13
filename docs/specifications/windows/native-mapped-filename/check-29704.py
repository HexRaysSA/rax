"""Verify frozen 29704 inputs and, optionally, their retained native archive.

Python 3.9+, standard library. O(B) time for B input bytes and O(P + M + N)
memory for projection P, largest payload M and archive manifest N. This does
not execute either the native probes or the emulator.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys
import zipfile

FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[3]
PROJECTION_SHA = "064a26c925497bc045c51458863cb7ae2d4442b6ba540fa2ba15cbf6e05ddb35"
COMPILE_SHA = "3e4f6269658048d7f039654b992c399a8fe30d60e9f93486666f542e87a1b45e"
ARCHIVE_SHA = "af6bc9e687b02811167ee61a4cd87ea7bcda267a56d447ee68f2faf3c2b41d38"
PAIRED_SHA = "41bd761c479d79ae1012a1d1af6b773b50a6f3f6a1c0081b6df1fc60686525e3"
PAIRED_ARCHIVE_SHA = "e44c13d7d5f1c0f0f9168ee71f880a32b30e2cdf5608c17d3210e7cf8f68d3ef"
MACHINES = {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}
RANGES = {7: range(48), 2: range(48, 66), 3: range(66, 77),
          4: range(77, 96), 5: range(96, 124), 6: range(124, 133),
          8: range(133, 197), 9: range(133, 389)}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(raw, expected):
    assert len(raw) == expected["bytes"] and sha(raw) == expected["sha256"]


def pe_machine(raw):
    assert raw[:2] == b"MZ"
    pe = struct.unpack_from("<I", raw, 60)[0]
    assert raw[pe:pe + 4] == b"PE\0\0"
    return struct.unpack_from("<H", raw, pe + 4)[0]


def verify_projection():
    raw = (FOLDER / "profile-29704-v1.json").read_bytes()
    assert sha(raw) == PROJECTION_SHA, "immutable native projection identity"
    data = json.loads(raw)
    assert data["kernel"] == [10, 0, 29704] and data["native_machine"] == 0xAA64
    assert data["native_queries"] == 1359 and data["native_images"] == 24
    assert data["archive"]["sha256"] == ARCHIVE_SHA
    assert len(data["sources"]) == 10
    for name, expected in data["sources"].items():
        identity((ROOT / name).read_bytes(), expected)
    raw = (FOLDER / "compile-29704-v1.json").read_bytes()
    assert sha(raw) == data["compile_records_sha256"] == COMPILE_SHA
    compiles = json.loads(raw)
    assert len(compiles) == 24
    assert {(row["arch"], row["version"]) for row in compiles} == {
        (arch, version) for arch in MACHINES for version in RANGES}
    for row in compiles:
        record = row["record"]
        assert record["native_exit_code"] == record["popen_returncode"] == 0
        assert record["native_pid"] > 0 and record["creation_filetime"] > 0
        for stream in ("stdout", "stderr"):
            assert sha(row[stream].encode("utf-8")) == record[stream + "_sha256"]
    baselines = data["baseline_capture"]["values"]
    assert data["baseline_capture"]["native_queries"] == len(baselines) == 24
    assert {(row["arch"], row["version"]) for row in baselines} == {
        (arch, version) for arch in MACHINES for version in RANGES}
    baseline_names = {}
    for row in baselines:
        obs = row["observation"]
        name = bytes.fromhex(obs["name_hex"])
        assert name and len(name) % 2 == 0
        assert obs["status"] == obs["raised"] == 0
        assert obs["returned"] == obs["header_size"] + len(name) + 2
        assert row["case"] == (4142 if row["version"] == 5 else
                               36 if row["version"] == 9 else 0)
        baseline_names[row["arch"], row["version"]] = obs["name_hex"]
    keys, rows = set(), list(baselines)
    assert len(data["groups"]) == len(RANGES)
    for group in data["groups"]:
        version, corpus = group["source_version"], group["corpus"]
        assert group["replay_version"] == (1 if version == 7 else version)
        assert corpus["build"] == 29704 and corpus["state"] == "finished"
        names = corpus["subject_names" if version == 9 else "executable_names"]
        assert set(names) == set(MACHINES)
        assert all(names[arch] == baseline_names[arch, version] for arch in MACHINES)
        for row in corpus["cases"]:
            key = row["arch"], row["version"], row["case"]
            assert row["version"] == version and key not in keys
            keys.add(key)
            assert row["exit_code"] == row["native_exit_code"]
            rows.append(row)
    assert keys == {(arch, version, case) for arch in MACHINES
                    for version, cases in RANGES.items() for case in cases}
    assert len(rows) == 1383
    assert len({(row["native_pid"], row["creation_filetime"]) for row in rows}) == 1383
    for row in rows:
        assert row["native_exit_code"] == row["popen_returncode"] == 0
        assert row["native_pid"] > 0 and row["creation_filetime"] > 0
        assert row["observation"]["raised"] == 0
        assert row["stderr_sha256"] == sha(b"")
    assert len(data["images"]) == 24
    for image in data["images"]:
        corpus = next(group["corpus"] for group in data["groups"]
                      if group["source_version"] == image["version"])
        assert image["image"]["sha256"] == image["reused_frozen_image"]["sha256"]
        assert corpus["binaries"][image["arch"]] == image["image"]["sha256"]
        assert corpus["source_sha256"] == image["source"]["sha256"]
    return data, rows


def verify_archive(path, data, rows):
    assert path.stat().st_size == data["archive"]["bytes"] == 8604234
    assert file_sha(path) == ARCHIVE_SHA
    with zipfile.ZipFile(path) as bundle:
        names = bundle.namelist()
        assert len(names) == len(set(names)) and bundle.testzip() is None
        files = {name for name in names if not name.endswith("/")}
        manifest = json.loads(bundle.read("archive-manifest.json"))
        assert len(manifest) == 4226
        assert files == set(manifest) | {"archive-manifest.json"}
        for name, expected in manifest.items():
            identity(bundle.read(name), expected)
        for name, expected in data["sources"].items():
            identity(bundle.read("sources/" + name.rsplit("/", 1)[-1]), expected)
        for row in rows:
            relative = "%s/v%d/%s-%d" % (row["arch"], row["version"],
                                         row["kind"], row["case"])
            stdout, stderr = (bundle.read(relative + suffix)
                              for suffix in (".stdout", ".stderr"))
            assert sha(stdout) == row["stdout_sha256"]
            assert not stderr and sha(stderr) == row["stderr_sha256"]
            assert json.loads(stdout) == row["observation"]
            record = json.loads(bundle.read(relative + ".json"))
            for field in ("native_pid", "creation_filetime", "native_exit_code",
                          "stdout_sha256", "stderr_sha256"):
                assert record[field] == row[field]
        for image in data["images"]:
            raw = bundle.read("%s/v%d/probe.exe" % (image["arch"], image["version"]))
            identity(raw, image["image"])
            assert pe_machine(raw) == MACHINES[image["arch"]]
        for provider in data["providers"]:
            raw = bundle.read(provider["arch"] + "/physical-ntdll.dll")
            identity(raw, provider)
            # Physical x64 compatibility NTDLL on this ARM64 host is ARM64.
            assert pe_machine(raw) == provider["file_machine"] == (
                0x14C if provider["arch"] == "x86" else 0xAA64)
        body = data["memcpy_body_snapshot"]
        identity(bundle.read("arm64/memcpy-body.exe"), body["observer"])
        identity(bundle.read("arm64/memcpy-body-2048.bin"), body["body"])


def verify_paired(original, path=None):
    raw = (FOLDER / "paired-29704-v1.json").read_bytes()
    assert sha(raw) == PAIRED_SHA
    data = json.loads(raw)
    assert data["state"] == "finished" and data["kernel"] == [10, 0, 29704]
    assert data["native_machine"] == "ARM64" and data["row_count"] == 414
    rows = data["rows"]
    expected = {(location, arch, version, kind, case)
                for location in ("local", "network") for arch in MACHINES
                for version, kind, cases in ((7, "baseline", (0,)),
                                              (7, "query", (5,)),
                                              (5, "baseline", (4142,)),
                                              (5, "query", range(62, 128)))
                for case in cases}
    assert len(rows) == len(expected) == 414
    assert {(row["location"], row["arch"], row["version"], row["kind"], row["case"])
            for row in rows} == expected
    assert len({(row["native_pid"], row["creation_filetime"]) for row in rows}) == 414
    for row in rows:
        assert row["native_exit_code"] == row["popen_returncode"] == 0
        assert row["observation"]["raised"] == 0
        assert row["stderr_sha256"] == sha(b"")
        if row["kind"] == "baseline":
            obs = row["observation"]
            name = bytes.fromhex(obs["name_hex"])
            assert obs["status"] == 0 and name and len(name) % 2 == 0
            assert obs["returned"] == obs["header_size"] + len(name) + 2
            assert name.decode("utf-16le").startswith(
                "\\Device\\Mup\\" if row["location"] == "network" else
                "\\Device\\HarddiskVolume3\\")
    assert len(data["images"]) == 12
    for image in data["images"]:
        frozen = next(item for item in original["images"]
                      if item["arch"] == image["arch"] and item["version"] == image["version"])
        assert frozen["image"]["sha256"] == image["image"]["sha256"]
        assert frozen["source"] == image["source"]
    volume = json.loads((FOLDER / "paired-volume-29704-v1.json").read_bytes())
    assert volume["native_start"] == volume["native_end"][:2] == ["9204", "134390396779992941"]
    assert volume["native_end"][2] == "0" and not volume["observer_stderr"]
    assert sha(volume["source"].encode("utf-8")) == volume["source_sha256"]
    assert sha(volume["measurement_raw_utf8"].encode("utf-8")) == volume["measurement_sha256"]
    assert json.loads(volume["measurement_raw_utf8"]) == volume["measurement"]
    measurement = volume["measurement"]
    assert measurement["kernel"] == [10, 0, 29704]
    assert measurement["native_pid"] == 9204 and measurement["filesystem"] == "NTFS"
    assert measurement["volume_root"] == "C:\\"
    for provider in measurement["provider_identities"]:
        frozen = next(item for item in original["providers"] if item["arch"] == provider["arch"])
        assert provider["bytes"] == frozen["bytes"] and provider["sha256"] == frozen["sha256"]
    if path is None:
        return
    assert path.stat().st_size == 1334435 and file_sha(path) == PAIRED_ARCHIVE_SHA
    with zipfile.ZipFile(path) as bundle:
        names = bundle.namelist()
        manifest = json.loads(bundle.read("archive-manifest.json"))
        assert len(manifest) == 1259 and len(names) == len(set(names)) == 1260
        assert set(names) == set(manifest) | {"archive-manifest.json"}
        assert bundle.testzip() is None
        for name, expected in manifest.items():
            identity(bundle.read(name), expected)
        assert bundle.read("capture.json") == raw
        assert sha(bundle.read("sources/capture-v4.py")) == "402c919cc14b8a0bfd55972167558f2a61a2ed242b186062db74afc0732fe938"
        assert sha(bundle.read("sources/compile-29704-v1.json")) == COMPILE_SHA
        for version in (5, 7):
            name = "probe-v%d.c" % version
            assert bundle.read("sources/" + name) == (FOLDER / name).read_bytes()
        for row in rows:
            relative = "%s/%s/v%d/%s-%d" % (row["location"], row["arch"],
                                            row["version"], row["kind"], row["case"])
            stdout, stderr = (bundle.read(relative + suffix)
                              for suffix in (".stdout", ".stderr"))
            assert sha(stdout) == row["stdout_sha256"]
            assert not stderr and sha(stderr) == row["stderr_sha256"]
            assert json.loads(stdout) == row["observation"]
            record = json.loads(bundle.read(relative + ".json"))
            for field in ("native_pid", "creation_filetime", "native_exit_code",
                          "stdout_sha256", "stderr_sha256"):
                assert record[field] == row[field]
        for image in data["images"]:
            raw_image = bundle.read("%s/%s/v%d/probe.exe" % (
                image["location"], image["arch"], image["version"]))
            identity(raw_image, image["image"])
            assert pe_machine(raw_image) == MACHINES[image["arch"]]


def main():
    assert len(sys.argv) in (1, 2, 3), "usage: check-29704.py [native-artifacts-v3.zip [paired-native-artifacts-v1.zip]]"
    data, rows = verify_projection()
    verify_paired(data, Path(sys.argv[2]) if len(sys.argv) == 3 else None)
    if len(sys.argv) >= 2:
        verify_archive(Path(sys.argv[1]), data, rows)
        print("Verified 4226 primary archive payloads, 1359 query rows, 24 names/images and provider/body bytes.")
    else:
        print("Verified frozen sources/compiles, 1359 query rows and 24 names; raw archive not checked.")
    print("Verified 402 paired queries and 12 names; paired raw archive " +
          ("verified (1259 payloads)." if len(sys.argv) == 3 else "not checked."))


if __name__ == "__main__":
    main()
