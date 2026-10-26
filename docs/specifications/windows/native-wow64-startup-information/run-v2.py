"""Measure native WoW64 startup metadata in one process and an owned thread."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "control", FOLDER.parent / "native-exception-entry-profile/run-second-chance-v1.py"
)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)

BOOL_FIELDS = {
    "teb32_self",
    "native_teb_is_32",
    "native_teb_self",
    "native_teb_32_link",
    "teb_roundtrip",
    "tls32_information_nonnull",
    "tls_views_same",
    "shared_information_with_main",
    "same_words_as_main",
    "section_handle_nonnull",
    "work_list_nonnull",
    "unknown_word_nonzero",
}
INTEGER_FIELDS = {
    "wow_teb_offset",
    "reverse_wow_teb_offset",
    "information_minus_peb32",
    "native_page_size",
    "native_processor_architecture",
    "build",
    "process_machine",
    "native_machine",
    "information_native_machine",
    "information_emulated_machine",
}


def validate(rows):
    if len(rows) != 2:
        raise ValueError("main and owned-thread observations required")
    expected = BOOL_FIELDS | INTEGER_FIELDS | {"sample", "information_words"}
    for row, sample in zip(rows, ("main", "thread")):
        if set(row) != expected or row["sample"] != sample:
            raise ValueError("invalid startup information fields or sample order")
        if any(type(row[name]) is not bool for name in BOOL_FIELDS) or any(
            type(row[name]) is not int for name in INTEGER_FIELDS
        ):
            raise ValueError("invalid startup information scalar type")
        words = row["information_words"]
        if (
            type(words) is not list
            or len(words) != 3
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in words
            )
        ):
            raise ValueError("invalid bounded startup words")
        if (
            not -(1 << 31) <= row["wow_teb_offset"] < 0
            or row["reverse_wow_teb_offset"] != -row["wow_teb_offset"]
            or not -(1 << 32) < row["information_minus_peb32"] < (1 << 32)
            or not 0 < row["build"] <= 0xFFFFFFFF
            or row["native_page_size"] != words[0]
            or not 0 < words[0] <= 0x10000
            or words[0] & (words[0] - 1)
            or row["process_machine"] != 0x14C
            or row["native_machine"] not in (0x8664, 0xAA64)
            or row["information_native_machine"] != row["native_machine"]
            or row["information_emulated_machine"] != row["process_machine"]
            or not 0 <= row["native_processor_architecture"] <= 0xFFFF
        ):
            raise ValueError("inconsistent native startup identity or geometry")
        required_true = {
            "teb32_self",
            "native_teb_self",
            "native_teb_32_link",
            "teb_roundtrip",
            "shared_information_with_main",
            "same_words_as_main",
        }
        if row["native_teb_is_32"] or any(not row[name] for name in required_true):
            raise ValueError("missing native companion or shared process information")
    comparable = expected - {
        "sample",
        "wow_teb_offset",
        "reverse_wow_teb_offset",
        "tls32_information_nonnull",
        "tls_views_same",
    }
    if any(rows[0][name] != rows[1][name] for name in comparable):
        raise ValueError("owned thread startup information differs from main")
    return rows


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if sys.platform != "win32":
        raise RuntimeError("native Windows kernel required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment")
    args = parser.parse_args()
    root = FOLDER.parents[3]
    target = root / "target"
    target.mkdir(exist_ok=True)
    if not (root / "Cargo.toml").is_file() or not target.resolve().is_relative_to(root):
        raise RuntimeError("in-tree control target required")
    source = FOLDER / "native-wow64-information-v3.cpp"
    driver = Path(__file__).resolve()
    source_digest, driver_digest = sha(source), sha(driver)
    with CONTROL.build_directory(target) as build:
        temporary = build / "tmp"
        temporary.mkdir()
        env, compiler = CONTROL.PROFILE.compiler_environment(
            "x86", args.environment, temporary
        )
        compiler = Path(compiler)
        compiler_digest = sha(compiler)
        executable = build / "probe.exe"
        result = subprocess.run(
            [
                str(compiler),
                "/nologo",
                "/std:c++20",
                "/Od",
                "/EHsc",
                "/W4",
                "/WX",
                "/MT",
                str(source),
                "/Fe:" + str(executable),
                "/Fo:" + str(build / "probe.obj"),
            ],
            cwd=build,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode:
            raise RuntimeError(
                "control compilation failed: " + result.stdout + result.stderr
            )
        binary = executable.read_bytes()
        pe = struct.unpack_from("<I", binary, 0x3C)[0]
        if struct.unpack_from("<H", binary, pe + 4)[0] != 0x14C:
            raise RuntimeError("WoW64 x86 executable required")
        executable_digest = hashlib.sha256(binary).hexdigest()
        result = subprocess.run(
            [str(executable)],
            cwd=build,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if len(result.stdout) > 8192 or result.stderr:
            raise RuntimeError("native control exceeded its output contract")
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        unchanged = (
            sha(executable) == executable_digest
            and sha(source) == source_digest
            and sha(driver) == driver_digest
            and sha(compiler) == compiler_digest
        )
        capture = {
            "kind": "native_capture",
            "source_sha256": source_digest,
            "driver_sha256": driver_digest,
            "compiler_sha256": compiler_digest,
            "binary_sha256": executable_digest,
            "binary_bytes": len(binary),
            "inputs_unchanged": unchanged,
            "exit_code": result.returncode,
            "rows": rows,
        }
        print(json.dumps(capture), flush=True)
        if result.returncode or not unchanged:
            raise RuntimeError("native control failed or an executed input changed")
        validate(rows)
        print(json.dumps({"kind": "validated", "samples": len(rows)}), flush=True)


if __name__ == "__main__":
    main()
