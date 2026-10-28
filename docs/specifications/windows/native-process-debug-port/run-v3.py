#!/usr/bin/env python3
"""Observe owned ProcessDebugPort queries without attaching a debugger."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    "control",
    Path(__file__).resolve().parents[1]
    / "native-exception-entry-profile/run-second-chance-v1.py",
)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


def width(arch):
    if arch not in ("arm64", "x64", "x86"):
        raise ValueError("unknown executable view")
    return 4 if arch == "x86" else 8


def base_inputs(arch):
    size = width(arch)
    yield from (("length", 0, 0, 0, 0, n, -1) for n in (0, 1, 3, 4, 5, 8, 16))
    yield from (("buffer", 0, 0, a, b, size, -1) for a in range(10) for b in range(10))
    yield from (
        ("handle", h, 0, a, b, n, -1)
        for h in range(5)
        for n in (size - 1, size)
        for a in range(4)
        for b in range(3)
    )
    yield from (
        ("rights", 5, access, 0, 0, size, -1)
        for access in (0, 8, 0x20, 0x400, 0x1000, 0x1400, 0x1FFFFF)
    )
    yield from (("alias", 0, 0, 0, 0, size, offset) for offset in range(size + 1))

    yield from (
        ("null-length", 0, 0, 1, returned, length, -1)
        for length in (0, 1, 3, 4, 5, 8, 16)
        for returned in range(10)
    )


def inputs(arch):
    yield from ((7, *identity) for identity in base_inputs(arch))
    for family, info_class, size in (
        ("upper-debug", 7, width(arch)),
        ("upper-flags", 34, 4),
        ("upper-cookie", 36, 4),
    ):
        for handle in (0, 2):
            for length in (0, 1, size - 1, size, size + 1, 0xFFFFFFFF):
                for output in (10, 11):
                    for returned in (0, 1, 6, 7):
                        yield (
                            info_class,
                            family,
                            handle,
                            0,
                            output,
                            returned,
                            length,
                            -1,
                        )


def validate(rows, arch):
    size = width(arch)
    expected = list(inputs(arch))
    if len(rows) != len(expected) + 2:
        raise ValueError("incomplete debug-port observation")
    host = rows[0]
    if (
        set(host)
        != {
            "kind",
            "build",
            "process_machine",
            "native_machine",
            "pointer_bytes",
            "query_class",
            "debugger_present",
            "remote_query_ok",
            "remote_error",
            "remote_debugger_present",
        }
        or host["kind"] != "host"
    ):
        raise ValueError("unexpected host fields")
    for field in (
        "build",
        "process_machine",
        "native_machine",
        "pointer_bytes",
        "query_class",
        "remote_error",
    ):
        if type(host[field]) is not int or not 0 <= host[field] <= 0xFFFFFFFF:
            raise ValueError("invalid host integer")
    for field in ("debugger_present", "remote_query_ok", "remote_debugger_present"):
        if type(host[field]) is not bool:
            raise ValueError("invalid host Boolean")
    if host["pointer_bytes"] != size or host["query_class"] != 7:
        raise ValueError("query or executable pointer width differs")
    if host["native_machine"] not in (0x14C, 0x8664, 0xAA64):
        raise ValueError("unknown native machine")
    names = (
        "query_class",
        "family",
        "handle_kind",
        "access",
        "output_role",
        "return_role",
        "length",
        "alias",
    )
    for index, (row, identity) in enumerate(zip(rows[1:-1], expected)):
        if set(row) != {
            "kind",
            "ordinal",
            *names,
            "opened",
            "status",
            "exception",
            "guard_protection",
            "output",
            "returned",
        }:
            raise ValueError("unexpected query fields")
        if (
            row["kind"] != "case"
            or type(row["ordinal"]) is not int
            or row["ordinal"] != index
            or tuple(row[n] for n in names) != identity
        ):
            raise ValueError("query input identity or order differs")
        if type(row["opened"]) is not bool:
            raise ValueError("invalid handle-open marker")
        for field in (
            "query_class",
            "handle_kind",
            "access",
            "output_role",
            "return_role",
            "length",
            "status",
            "exception",
            "guard_protection",
        ):
            if type(row[field]) is not int or not 0 <= row[field] <= 0xFFFFFFFF:
                raise ValueError("invalid query integer")
        if type(row["alias"]) is not int:
            raise ValueError("invalid alias input")
        if any(
            not isinstance(row[n], str) or re.fullmatch("[0-9a-f]{32}", row[n]) is None
            for n in ("output", "returned")
        ):
            raise ValueError("invalid fixed-width buffer projection")
    if (
        rows[-1] != {"kind": "complete", "cases": len(expected)}
        or type(rows[-1].get("cases")) is not int
    ):
        raise ValueError("missing query cleanup receipt")
    baseline = next(
        row for row in rows[1:-1] if row["family"] == "length" and row["length"] == size
    )
    if baseline["status"] or baseline["exception"]:
        raise ValueError("valid current-process query failed")
    if host["remote_query_ok"]:
        value = int.from_bytes(bytes.fromhex(baseline["output"])[:size], "little")
        if bool(value) != host["remote_debugger_present"]:
            raise ValueError("native and Win32 debugger state disagree")
    return rows


def main():
    if sys.platform != "win32":
        raise RuntimeError("native Windows required")
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
    if not (root / "Cargo.toml").is_file() or not target.resolve().is_relative_to(root):
        raise RuntimeError("in-tree compiler output required")
    source = folder / "native-debug-port-v3.cpp"
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    for arch in args.architectures:
        with CONTROL.build_directory(target) as build:
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = CONTROL.PROFILE.compiler_environment(
                arch, args.environment, temporary
            )
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
                    "/link",
                    "/NXCOMPAT",
                ],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode:
                raise RuntimeError(
                    "debug-port compilation failed: " + result.stdout + result.stderr
                )
            binary = executable.read_bytes()
            pe = struct.unpack_from("<I", binary, 0x3C)[0]
            if (
                struct.unpack_from("<H", binary, pe + 4)[0]
                != {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch]
            ):
                raise RuntimeError("unexpected control executable machine")
            digest = hashlib.sha256(binary).hexdigest()
            identity = {
                "arch": arch,
                "source_sha256": source_sha,
                "binary_sha256": digest,
                "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
            }
            print(json.dumps({"kind": "producer", **identity}), flush=True)
            result = subprocess.run(
                [str(executable)],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if len(result.stdout) > 262144 or result.stderr:
                raise RuntimeError("query output exceeds scalar contract")
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            print(
                json.dumps(
                    {
                        "kind": "observation",
                        **identity,
                        "exit_code": result.returncode,
                        "rows": rows,
                    }
                ),
                flush=True,
            )
            validate(rows, arch)
            if (
                result.returncode
                or hashlib.sha256(executable.read_bytes()).hexdigest() != digest
            ):
                raise RuntimeError("query executable failed or changed")
    if hashlib.sha256(source.read_bytes()).hexdigest() != source_sha:
        raise RuntimeError("query source changed")


if __name__ == "__main__":
    main()
