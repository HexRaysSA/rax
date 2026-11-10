#!/usr/bin/env python3
"""Verify the bounded native selector observations and private capture archive."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fields(line):
    return dict(re.findall(r"([a-z-]+)=([^\s]+)", line))


def project(raw, receipt):
    require(receipt["phase"] == "finished", "Native capture did not finish")
    require(not receipt.get("error") and not receipt.get("producer_failed"), "Producer failure")
    require(receipt["native_kernel"] == "10.0.29704.0", "Native kernel mismatch")
    require(receipt["images_unchanged"], "Native DLL identity changed")
    require(len(receipt["installed_images"]) == 8, "Incomplete DLL identity")
    require(len(receipt["runs"]) == 1, "Unexpected producer count")
    run = receipt["runs"][0]
    require(run["exit_code"] == 0 and run["stderr_bytes"] == 0, "Producer verdict")
    require(base64.b64decode(run["stdout_base64"], validate=True) == raw, "Callback bytes differ")
    require(run["stdout_bytes"] == len(raw) and run["stdout_sha256"] == digest(raw), "Output identity")
    lines = raw.decode("ascii").splitlines()

    def one(prefix):
        rows = [line for line in lines if line.startswith(prefix)]
        require(len(rows) == 1, "Missing or duplicate observation: " + prefix)
        return fields(rows[0])

    kernel = one("KERNEL ")
    require([int(kernel[key]) for key in ("major", "minor", "build")] == [10, 0, 29704], "Kernel output")
    require(int(kernel["native-machine"], 16) == 0xAA64, "Native machine")
    require(kernel["pointer-bytes"] == "8", "Controller pointer width")
    require(one("GET ")["initial"] == "1", "Initial child context query failed")
    initial = one("CONTEXT label=child-before-user-entry ")
    live = one("LIVE ")
    selectors = ("cs", "ss", "ds", "es", "fs", "gs")
    initial_selectors = {key: int(initial[key], 16) for key in selectors}
    live_selectors = {key: int(live[key], 16) for key in selectors}
    require(initial_selectors == live_selectors, "Native initial and live selectors differ")
    fs = one("FSBASE ")
    require("value" in fs, "Native FS base instruction raised an exception")
    descriptors = []
    for line in lines:
        if line.startswith("LARLSL "):
            row = fields(line)
            require("exception" not in row, "Native descriptor instruction raised an exception")
            descriptors.append({
                "selector": int(row["selector"], 16),
                "lar_ok": bool(int(row["lar-ok"])),
                "access": int(row["access"], 16),
                "lsl_ok": bool(int(row["lsl-ok"])),
                "limit": int(row["limit"], 16),
            })
    require(len(descriptors) == 4, "Descriptor observation count")
    queries = [fields(line) for line in lines if line.startswith("DESCRIPTOR ")]
    require(len(queries) == 8, "Descriptor query count")
    require(all(int(row["status"], 16) == 0xC0000002 and row["returned"] == "0"
                and row["hex"] == "A5" * 8 for row in queries), "Unclassified descriptor query")
    require(one("RESUME ")["previous"] == "1", "Unexpected resume count")
    done = one("DONE ")
    require(done == {"wait": "0", "queried": "1", "exit": "0", "thread-closed": "1",
                     "process-closed": "1", "debugger": "0"}, "Child did not complete naturally")
    return {
        "initial_context_flags": int(initial["flags"], 16),
        "initial_selectors": initial_selectors,
        "live_selectors": live_selectors,
        "fs_base": int(fs["value"], 16),
        "descriptor_observations": descriptors,
        "descriptor_query_status": 0xC0000002,
        "descriptor_query_count": len(queries),
        "installed_images": receipt["installed_images"],
    }


def verify(profile_path, archive_path):
    profile = json.loads(profile_path.read_text())
    require(profile["schema"] == "rax-native-chpe-segments-profile-v1", "Profile schema")
    root = profile_path.parent
    for name, expected in profile["sources"].items():
        data = (root / name).read_bytes()
        require(len(data) == expected["bytes"] and digest(data) == expected["sha256"], "Public source changed")
    data = archive_path.read_bytes()
    require(len(data) == profile["archive"]["bytes"] and digest(data) == profile["archive"]["sha256"], "Archive identity")
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "Duplicate archive member")
        manifest = json.loads(archive.read("manifest-v1.json"))["files"]
        require(set(names) == set(manifest) | {"manifest-v1.json"}, "Archive membership")
        require(len(manifest) == profile["archive"]["payload_members"], "Archive payload count")
        for name, expected in manifest.items():
            raw = archive.read(name)
            require(len(raw) == expected["bytes"] and digest(raw) == expected["sha256"], "Archive member identity")
        for name in profile["sources"]:
            require(archive.read(name) == (root / name).read_bytes(), "Archived/public source mismatch")
        raw = archive.read("native-stdout-v1.txt")
        require(len(raw) == profile["stdout"]["bytes"] and digest(raw) == profile["stdout"]["sha256"], "Profile output identity")
        receipt = json.loads(archive.read("native-receipt-v1.json"))
        binding_bytes = archive.read("native-source-v1.json")
        require(receipt["source_sha256"] == digest(binding_bytes), "Native binding identity")
        binding = json.loads(binding_bytes)
        input_names = {"controller.cpp": "segments-v1.cpp"}
        for expected in binding["inputs"]:
            name = input_names.get(expected["package_name"], expected["package_name"])
            member = archive.read(name)
            require(len(member) == expected["bytes"] and digest(member) == expected["sha256"], "Native package input identity")
        for key, value in project(raw, receipt).items():
            require(profile[key] == value, "Projected profile mismatch: " + key)
        image = archive.read("controller.exe")
        require(len(image) == profile["controller_image"]["bytes"]
                and digest(image) == profile["controller_image"]["sha256"], "Controller image identity")
        for name in ["controller.exe", "x64.exe"]:
            image = archive.read(name)
            require(image[:2] == b"MZ", "DOS signature")
            offset = int.from_bytes(image[0x3C:0x40], "little")
            require(image[offset:offset + 4] == b"PE\x00\x00", "PE signature")
            require(int.from_bytes(image[offset + 4:offset + 6], "little") == profile["guest_machine"], "AMD64 input machine")
    return {"verified": True, "payload_members": len(manifest), "native_producers": 1,
            "native_child_exit": 0, "descriptor_query_status": "0xc0000002"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--profile", type=Path, default=Path(__file__).with_name("profile-29704-v1.json"))
    args = parser.parse_args()
    print(json.dumps(verify(args.profile, args.archive), sort_keys=True))


if __name__ == "__main__":
    main()
