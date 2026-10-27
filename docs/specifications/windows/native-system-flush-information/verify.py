"""Verify source, executable and raw-output identities of a native capture."""

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("flush_capture", FOLDER / "run-v2.py")
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(data):
    PROFILE.validate_dataset(data)
    producer = (FOLDER / "native-system-flush-information-v1.cpp").read_bytes()
    version = data.get("driver_version", 1)
    PROFILE.require(version in (1, 2), "driver version")
    driver = (FOLDER / f"run-v{version}.py").read_bytes()
    producer = producer.replace(b"\r\n", b"\n")
    driver = driver.replace(b"\r\n", b"\n")
    PROFILE.require(
        data["source_lf_sha256"] == digest(producer), "producer LF identity"
    )
    for label, raw in (("source", producer), ("driver", driver)):
        PROFILE.require(
            data[label + "_sha256"]
            in {digest(raw), digest(raw.replace(b"\n", b"\r\n"))},
            label + " compiler-input identity",
        )
    samples = {sample["arch"]: sample for sample in data["samples"]}
    captures = data["captures"]
    PROFILE.require(
        len(captures) == len(samples)
        and {capture["arch"] for capture in captures} == samples.keys(),
        "raw architecture coverage",
    )
    for capture in captures:
        sample = samples[capture["arch"]]
        PROFILE.require(
            capture["exit_code"] == 0 and capture["inputs_unchanged"] is True,
            "native producer verdict",
        )
        raw = base64.b64decode(capture["stdout_base64"], validate=True)
        PROFILE.require(digest(raw) == capture["stdout_sha256"], "raw stdout identity")
        PROFILE.require(
            [json.loads(line) for line in raw.splitlines()] == PROFILE.expand(sample),
            "raw rows differ from projection",
        )
        binary = base64.b64decode(capture["binary_base64"], validate=True)
        PROFILE.require(
            len(binary) == sample["binary_bytes"]
            and digest(binary) == sample["binary_sha256"],
            "executed binary identity",
        )
        PROFILE.require(binary[:2] == b"MZ" and len(binary) >= 64, "PE DOS header")
        pe = struct.unpack_from("<I", binary, 0x3C)[0]
        PROFILE.require(0 <= pe <= len(binary) - 6, "PE header bounds")
        PROFILE.require(
            binary[pe : pe + 4] == b"PE\0\0"
            and struct.unpack_from("<H", binary, pe + 4)[0]
            == PROFILE.MACHINES[capture["arch"]],
            "executed PE machine",
        )
    return sum(len(sample["rows"]) for sample in samples.values())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("captures", nargs="+", type=Path)
    for path in parser.parse_args().captures:
        print(f"{path.name}: verified {verify(json.loads(path.read_bytes()))} queries")


if __name__ == "__main__":
    main()
