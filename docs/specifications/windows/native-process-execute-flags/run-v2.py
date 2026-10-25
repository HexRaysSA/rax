#!/usr/bin/env python3
"""Observe fixed, owned ProcessExecuteFlags queries without changing DEP policy."""

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


def inputs():
    yield from (("length", 0, 0, 0, 0, n, -1) for n in (0, 1, 3, 4, 5, 8, 16))
    yield from (("buffer", 0, 0, a, b, 4, -1) for a in range(10) for b in range(10))
    yield from (
        ("handle", h, 0, a, b, n, -1)
        for h in range(5)
        for n in (3, 4)
        for a in range(4)
        for b in range(3)
    )
    yield from (
        ("rights", 5, access, 0, 0, 4, -1)
        for access in (0, 8, 0x20, 0x400, 0x1000, 0x1400, 0x1FFFFF)
    )
    yield from (("alias", 0, 0, 0, 0, 4, offset) for offset in range(5))


def validate(rows, arch):
    if arch not in ("arm64", "x64", "x86"):
        raise ValueError("unknown executable view")
    expected = list(inputs())
    if len(rows) != len(expected) + 2:
        raise ValueError("incomplete execute-flags observation")
    host = rows[0]
    if (
        set(host)
        != {
            "kind",
            "build",
            "process_machine",
            "native_machine",
            "pointer_bytes",
            "nx_compat",
            "system_dep_policy",
            "dep_query_ok",
            "dep_error",
            "dep_flags",
            "dep_permanent",
        }
        or host["kind"] != "host"
    ):
        raise ValueError("unexpected host fields")
    if host["pointer_bytes"] != (4 if arch == "x86" else 8):
        raise ValueError("compiler and executable pointer width disagree")
    for field in (
        "build",
        "process_machine",
        "native_machine",
        "pointer_bytes",
        "system_dep_policy",
        "dep_error",
        "dep_flags",
    ):
        if type(host[field]) is not int or not 0 <= host[field] <= 0xFFFFFFFF:
            raise ValueError("invalid host integer")
    for field in ("nx_compat", "dep_query_ok", "dep_permanent"):
        if type(host[field]) is not bool:
            raise ValueError("invalid host Boolean")
    if host["native_machine"] not in (0x14C, 0x8664, 0xAA64) or host[
        "system_dep_policy"
    ] not in range(4):
        raise ValueError("unknown native machine or system DEP policy")
    names = (
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
    return rows


def validate_unavailable(record):
    if set(record) != {
        "kind",
        "arch",
        "requested_nx_compat",
        "available",
        "windows_error",
        "machine",
        "dll_characteristics",
        "source_sha256",
        "binary_sha256",
        "compiler_sha256",
    }:
        raise ValueError("unexpected loader-result fields")
    if (
        record["kind"] != "unavailable"
        or record["available"] is not False
        or record["requested_nx_compat"] is not False
        or record["windows_error"] != 193
    ):
        raise ValueError("unexpected loader result")
    if (
        record["arch"] not in ("arm64", "x64", "x86")
        or record["machine"]
        != {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[record["arch"]]
    ):
        raise ValueError("loader executable identity differs")
    flags = record["dll_characteristics"]
    if type(flags) is not int or not 0 <= flags <= 0xFFFF or flags & 0x100:
        raise ValueError("rejected variant did not clear NX_COMPAT")
    for field in ("source_sha256", "binary_sha256", "compiler_sha256"):
        if (
            not isinstance(record[field], str)
            or re.fullmatch("[0-9a-f]{64}", record[field]) is None
        ):
            raise ValueError("invalid loader-result identity")


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
    source = folder / "native-execute-flags-v1.cpp"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    for arch in args.architectures:
        for nx in (True, False):
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
                        "/link",
                        "/NXCOMPAT" if nx else "/NXCOMPAT:NO",
                    ],
                    cwd=build,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode:
                    raise RuntimeError(
                        "execute-flags compilation failed: "
                        + result.stdout
                        + result.stderr
                    )
                binary = exe.read_bytes()
                pe = struct.unpack_from("<I", binary, 0x3C)[0]
                if (
                    struct.unpack_from("<H", binary, pe + 4)[0]
                    != {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch]
                ):
                    raise RuntimeError("unexpected control executable machine")
                binary_digest = hashlib.sha256(binary).hexdigest()
                try:
                    result = subprocess.run(
                        [str(exe)],
                        cwd=build,
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                except OSError as error:
                    if getattr(error, "winerror", None) != 193 or nx:
                        raise
                    record = {
                        "kind": "unavailable",
                        "arch": arch,
                        "requested_nx_compat": False,
                        "available": False,
                        "windows_error": 193,
                        "machine": struct.unpack_from("<H", binary, pe + 4)[0],
                        "dll_characteristics": struct.unpack_from(
                            "<H", binary, pe + 24 + 70
                        )[0],
                        "source_sha256": digest,
                        "binary_sha256": binary_digest,
                        "compiler_sha256": hashlib.sha256(
                            compiler.read_bytes()
                        ).hexdigest(),
                    }
                    print(json.dumps(record), flush=True)
                    validate_unavailable(record)
                    if hashlib.sha256(exe.read_bytes()).hexdigest() != binary_digest:
                        raise RuntimeError("rejected executable changed")
                    continue
                if len(result.stdout) > 262144 or result.stderr:
                    raise RuntimeError("query output exceeds scalar contract")
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                print(
                    json.dumps(
                        {
                            "kind": "observation",
                            "arch": arch,
                            "requested_nx_compat": nx,
                            "source_sha256": digest,
                            "binary_sha256": binary_digest,
                            "compiler_sha256": hashlib.sha256(
                                compiler.read_bytes()
                            ).hexdigest(),
                            "exit_code": result.returncode,
                            "rows": rows,
                        }
                    ),
                    flush=True,
                )
                validate(rows, arch)
                if (
                    result.returncode
                    or hashlib.sha256(exe.read_bytes()).hexdigest() != binary_digest
                ):
                    raise RuntimeError("query executable failed or changed")
    if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
        raise RuntimeError("query source changed")


if __name__ == "__main__":
    main()
