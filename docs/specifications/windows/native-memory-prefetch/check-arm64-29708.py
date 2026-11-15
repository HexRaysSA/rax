#!/usr/bin/env python3
"""Verify the 29708 corpus; optionally bind every row to its primary archive."""

import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath
import struct
import zipfile


KERNEL = {
    "major": 10,
    "minor": 0,
    "build": 29708,
    "process_machine": 0,
    "native_machine": 0xAA64,
}
ARCHES = [("arm64", 0xAA64), ("x64", 0x8664), ("x86", 0x14C)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def lf(data):
    return data.replace(b"\r\n", b"\n")


def checked(data, expected, label):
    require(digest(data) == expected["sha256"], label + " SHA-256")
    if "bytes" in expected:
        require(len(data) == expected["bytes"], label + " size")


def native(proof, expected, label):
    require(proof["state"] == "finished", label + " terminal state")
    require(proof["native_exit_code"] == 0, label + " native exit")
    for field in ("native_pid", "creation_filetime"):
        require(proof[field] == expected[field] > 0, label + " " + field)
    require(
        proof["creation_filetime_after"] == proof["creation_filetime"],
        label + " birth held",
    )


def corpus_rows(data):
    require(data["state"] == "finished", "corpus terminal state")
    require(data["build"] == 29708 and data["native_machine"] == 0xAA64,
            "corpus native kernel")
    require(data["runner_process_machine"] == 0, "native ARM64 controller")
    require(data["native_kernel"] == {k: KERNEL[k] for k in ("major", "minor", "build")},
            "corpus exact version")
    require(len(data["cases"]) == 1026, "complete corpus")
    identities = set()
    frontiers = 0
    for index, row in enumerate(data["cases"]):
        arch = ARCHES[index // 342][0]
        case = index % 342
        label = f"{arch}/{case}"
        require(row["arch"] == arch and row["case"] == case, label + " order")
        require(row["exit_code"] == 0, label + " exit")
        identity = (row["native_pid"], row["creation_filetime"])
        require(identity not in identities and min(identity) > 0, label + " identity")
        identities.add(identity)
        observation = row["observation"]
        require(observation["id"] == case and observation["exception"] == 0,
                label + " observation")
        require(observation["pointer_bytes"] == (4 if arch == "x86" else 8),
                label + " pointer width")
        for field in ("range_snapshot", "info_snapshot"):
            require(len(bytes.fromhex(observation[field])) == 32, label + " " + field)
        frontiers += 1 <= observation["class"] <= 8
    require(frontiers == 204, "class 1 through 8 frontier count")
    require(len(identities) - frontiers == 822, "implemented replay row count")


def archive_rows(path, metadata, corpus):
    checked(path.read_bytes(), metadata["primary_archive"], "primary archive")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "unique archive members")
        require(archive.testzip() is None, "archive CRC")
        manifest = json.loads(archive.read("manifest.json"))
        require(len(manifest) == metadata["primary_archive"]["payloads"] == 3111,
                "archive payload count")
        require(len({item["member"] for item in manifest}) == len(manifest),
                "unique manifest members")
        require(set(names) == {item["member"] for item in manifest} | {"manifest.json"},
                "manifest covers every member")
        for item in manifest:
            checked(archive.read(item["member"]), item, item["member"])
        for item in metadata["producer_inputs"]:
            require(digest(lf(archive.read(item["archive_member"]))) == item["lf_sha256"],
                    item["file"] + " archived producer")
        acquisition = metadata["acquisition_controller"]
        checked(archive.read(acquisition["archive_member"]), acquisition, "controller source")
        raw_bytes = archive.read(metadata["raw_dataset"]["archive_member"])
        checked(raw_bytes, metadata["raw_dataset"], "raw dataset")
        raw = json.loads(raw_bytes)
        require(len(raw["cases"]) == 1026 and raw["state"] == "finished", "raw completeness")
        for field in ("pid", "build", "native_machine", "runner_process_machine",
                      "source_sha256", "binaries"):
            require(raw[field] == corpus[field], "raw corpus " + field)
        control = json.loads(archive.read("evidence/prefetch-controller-v1.json"))
        terminal = json.loads(archive.read("evidence/prefetch-native-controller-exit-v1.json"))
        require(control["host_before"] == control["host_after"] == KERNEL, "kernel held")
        require(control["state"] == "finished" and control["completed_cases"] == 1026,
                "controller completed every case")
        require(control["input_hashes_held"], "producer inputs held")
        require(control["dataset"]["sha256"] == digest(raw_bytes), "controller raw binding")
        require(terminal["state"] == "finished" and terminal["native_exit_code"] == 0,
                "controller actual native exit")
        for field in ("native_pid", "creation_filetime"):
            require(control[field] == terminal[field] == metadata["controller"][field],
                    "controller " + field)
        require(corpus["pid"] == control["native_pid"] and
                corpus["creation_filetime"] == control["creation_filetime"],
                "corpus controller identity")
        for item in metadata["producer_inputs"] + [acquisition]:
            member = item["archive_member"]
            suffix = member.removeprefix("inputs/") if member.startswith("inputs/") else \
                ".task-evidence/startup-29708-v1/" + member.removeprefix("evidence/")
            matches = [value for name, value in control["input_sha256_before"].items()
                       if name.replace("\\", "/").endswith("/" + suffix)]
            require(matches == [digest(archive.read(member))], "captured input " + member)
        for expected, (arch, machine) in zip(metadata["architectures"], ARCHES):
            require(expected["arch"] == arch and expected["pe_machine"] == machine,
                    arch + " metadata")
            prefix = "build/" + arch + "/"
            image = archive.read(prefix + "probe.exe")
            checked(image, {"sha256": expected["binary_sha256"],
                            "bytes": expected["binary_bytes"]}, arch + " image")
            require(image[:2] == b"MZ", arch + " DOS header")
            pe = struct.unpack_from("<I", image, 0x3C)[0]
            require(image[pe:pe + 4] == b"PE\0\0" and
                    struct.unpack_from("<H", image, pe + 4)[0] == machine, arch + " PE machine")
            require(raw["binaries"][arch] == digest(image), arch + " raw image binding")
            captured = control["architectures"][arch]
            require(captured["state"] == "finished" and captured["completed_cases"] == 342,
                    arch + " complete")
            require(captured["binary_sha256"] == digest(image) and
                    captured["compiler_sha256"] == expected["compiler_sha256"],
                    arch + " captured image and compiler")
            compiler = json.loads(archive.read(prefix + "compile.native.json"))
            native(compiler, {"native_pid": expected["compiler_native_pid"],
                              "creation_filetime": expected["compiler_creation_filetime"]},
                   arch + " compiler")
            for stream in ("stdout", "stderr"):
                checked(archive.read(prefix + "compile." + stream),
                        {"sha256": compiler[stream + "_sha256"],
                         "bytes": compiler[stream + "_bytes"]}, arch + " compiler " + stream)
        for row, observed in zip(raw["cases"], corpus["cases"]):
            require({k: v for k, v in row.items() if k not in ("stdout", "stderr")} == observed,
                    "lossless corpus projection")
            prefix = f"build/{row['arch']}/case-{row['case']:03}"
            proof = json.loads(archive.read(prefix + ".native.json"))
            native(proof, row, prefix)
            require(proof["timeout_seconds"] == 20 and proof["command"][-1] == str(row["case"]),
                    prefix + " original case and deadline")
            require(PureWindowsPath(proof["command"][0]).name == "probe.exe", prefix + " producer")
            for stream in ("stdout", "stderr"):
                payload = archive.read(prefix + "." + stream)
                checked(payload, {"sha256": proof[stream + "_sha256"],
                                  "bytes": proof[stream + "_bytes"]}, prefix + " " + stream)
                require(payload.decode("utf-8") == row[stream], prefix + " raw " + stream)
            require(not row["stderr"] and json.loads(row["stdout"]) == row["observation"],
                    prefix + " raw observation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="original prefetch-native-29708-v1.zip")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    root = directory.parents[3]
    metadata = json.loads((directory / "inputs-arm64-29708-v1.json").read_bytes())
    require(metadata["kernel"] == KERNEL and metadata["native_calls"] == 1026, "metadata identity")
    require(len(metadata["architectures"]) == 3, "all three ABI identities")
    require(metadata["controller"]["native_exit_code"] == 0, "metadata controller exit")
    require(metadata["implemented_class0_and_invalid_class_rows"] == 822 and
            metadata["declared_class1_through8_frontiers"] == 204, "metadata row counts")
    data = lf((directory / metadata["corpus"]["file"]).read_bytes())
    checked(data, metadata["corpus"], "LF corpus")
    corpus = json.loads(data)
    corpus_rows(corpus)
    for item in metadata["producer_inputs"]:
        require(digest(lf((root / item["file"]).read_bytes())) == item["lf_sha256"],
                item["file"] + " current producer")
    require(corpus["source_sha256"] == metadata["producer_inputs"][0]["lf_sha256"],
            "corpus producer binding")
    if args.archive:
        archive_rows(args.archive, metadata, corpus)
    print(json.dumps({"native_calls": 1026, "replayed_rows": 822, "frontier_rows": 204,
                      "archive_verified": bool(args.archive), "kernel": KERNEL}, sort_keys=True))


if __name__ == "__main__":
    main()
