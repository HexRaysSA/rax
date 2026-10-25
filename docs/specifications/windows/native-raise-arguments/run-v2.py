#!/usr/bin/env python3
"""Observe argument-copy order; retain statuses without inventing a profile."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    "second_chance_control",
    Path(__file__).resolve().parents[1]
    / "native-exception-entry-profile/run-second-chance-v1.py",
)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
POINTERS = (0, 1, 2, 3, 4, 7, 8, 12, 15, 16, 32, 4096)


def validate(rows, arch, first_chance):
    if arch not in ("arm64", "x64", "x86"):
        raise ValueError("unknown compiler ABI")
    if len(rows) != 38:
        raise ValueError("expected host/chance records and 36 argument pairs")
    host = rows[0]
    if (
        set(host)
        != {"kind", "build", "process_machine", "native_machine", "pointer_bytes"}
        or host["kind"] != "host"
    ):
        raise ValueError("invalid host record")
    if host["pointer_bytes"] != (4 if arch == "x86" else 8):
        raise ValueError("pointer width differs from compiler ABI")
    for name in ("build", "process_machine", "native_machine"):
        if type(host[name]) is not int or not 0 <= host[name] <= 0xFFFFFFFF:
            raise ValueError("invalid host integer")
    expected = [(mode, pointer) for mode in range(3) for pointer in POINTERS]
    if (
        rows[1] != {"kind": "chance", "first_chance": first_chance}
        or type(rows[1].get("first_chance")) is not bool
    ):
        raise ValueError("chance input identity differs")
    for row, pair in zip(rows[2:], expected):
        if set(row) != {"kind", "mode", "pointer", "status", "returned", "caught"}:
            raise ValueError("unexpected argument observation fields")
        if (
            row["kind"] != "case"
            or type(row["mode"]) is not int
            or type(row["pointer"]) is not int
            or (row["mode"], row["pointer"]) != pair
        ):
            raise ValueError("argument observation order or identity differs")
        if type(row["returned"]) is not bool:
            raise ValueError("invalid return marker")
        for field in ("status", "caught"):
            if type(row[field]) is not int or not 0 <= row[field] <= 0xFFFFFFFF:
                raise ValueError("invalid status integer")
    return rows


def main():
    if sys.platform != "win32":
        raise RuntimeError("native Windows kernel required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment")
    parser.add_argument(
        "--architectures",
        nargs="+",
        choices=("arm64", "x64", "x86"),
        default=("x64", "x86"),
    )
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parents[3]
    target = root / "target"
    target.mkdir(exist_ok=True)
    if not target.resolve().is_relative_to(root):
        raise RuntimeError("build target escapes worktree")
    source = folder / "native-raise-arguments-v2.cpp"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    for arch in args.architectures:
        with CONTROL.build_directory(target) as build:
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = CONTROL.PROFILE.compiler_environment(
                arch, args.environment, temporary
            )
            exe = build / "probe.exe"
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
                    "/Fe:" + str(exe),
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
                    "argument control compilation failed: "
                    + result.stdout
                    + result.stderr
                )
            image = exe.read_bytes()
            pe = struct.unpack_from("<I", image, 0x3C)[0]
            machine = struct.unpack_from("<H", image, pe + 4)[0]
            if machine != {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch]:
                raise RuntimeError("unexpected executable machine")
            executable_digest = hashlib.sha256(image).hexdigest()
            for first_chance in (False, True):
                result = subprocess.run(
                    [str(exe), "first" if first_chance else "second"],
                    cwd=build,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if len(result.stdout) > 16384 or result.stderr:
                    raise RuntimeError("argument control output exceeded its contract")
                rows = validate(
                    [json.loads(line) for line in result.stdout.splitlines()],
                    arch,
                    first_chance,
                )
                print(
                    json.dumps(
                        {
                            "kind": "observation",
                            "arch": arch,
                            "source_sha256": digest,
                            "binary_sha256": executable_digest,
                            "compiler_sha256": hashlib.sha256(
                                compiler.read_bytes()
                            ).hexdigest(),
                            "exit_code": result.returncode,
                            "rows": rows,
                        }
                    ),
                    flush=True,
                )
                if result.returncode or any(
                    not row["returned"] or row["caught"] or row["status"] < 0x80000000
                    for row in rows[2:]
                ):
                    raise RuntimeError(
                        "argument control did not return an error for every unreadable input"
                    )
                if hashlib.sha256(exe.read_bytes()).hexdigest() != executable_digest:
                    raise RuntimeError("argument control executable changed")
    if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
        raise RuntimeError("argument control source changed")


if __name__ == "__main__":
    main()
