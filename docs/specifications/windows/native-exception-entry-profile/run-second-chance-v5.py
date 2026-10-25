#!/usr/bin/env python3
"""Observe native readable-buffer alignment without inventing a kernel profile."""

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import shutil
import subprocess
import sys
import tempfile
import time

SPEC = importlib.util.spec_from_file_location(
    "exception_profile", Path(__file__).with_name("run-v2.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)
require = PROFILE.require
EXCEPTION = 0xE0425345
ACCESS_VIOLATION = 0xC0000005
MODES = (
    "last",
    "invalid-record",
    "invalid-context",
    *(f"record-{i}" for i in range(1, 33)),
    *(f"context-{i}" for i in range(1, 33)),
    "context-split",
    "context-split-aligned",
)


def validate(mode, exit_code, rows, arch):
    require(mode in MODES and arch in ("arm64", "x64", "x86"), "unknown input identity")
    require(
        rows
        and set(rows[0])
        == {
            "kind",
            "mode",
            "code",
            "build",
            "process_machine",
            "native_machine",
            "pointer_bytes",
        },
        "input fields",
    )
    host = rows[0]
    require(
        host["kind"] == "ready" and host["mode"] == mode and host["code"] == EXCEPTION,
        "input identity",
    )
    require(
        all(
            type(host[n]) is int and 0 <= host[n] <= 0xFFFFFFFF
            for n in (
                "code",
                "build",
                "process_machine",
                "native_machine",
                "pointer_bytes",
            )
        ),
        "input integer types",
    )
    require(host["pointer_bytes"] == (4 if arch == "x86" else 8), "input ABI width")
    require(
        host["native_machine"] in (0x8664, 0xAA64)
        and host["process_machine"] in (0, 0x14C, 0x8664),
        "native execution identity",
    )
    if exit_code & 0xFFFFFFFF == EXCEPTION:
        require(len(rows) == 1, "termination must not redispatch user handlers")
        return
    require(
        exit_code == 0 and len(rows) == 2,
        "argument query neither returned nor terminated",
    )
    result = rows[1]
    require(
        set(result) == {"kind", "seen", "caught", "call_returned", "status", "removed"},
        "unexpected result fields",
    )
    require(
        result["kind"] == "complete"
        and result["seen"] == 0
        and result["caught"] == 0
        and result["call_returned"] is True
        and result["removed"] is True,
        "native result and handler cleanup",
    )
    require(
        type(result["status"]) is int and 0x80000000 <= result["status"] <= 0xFFFFFFFF,
        "native error status",
    )


@contextmanager
def build_directory(target):
    path = Path(tempfile.mkdtemp(prefix="native-second-chance-", dir=target))
    try:
        yield path
    finally:
        # Windows reporting or scanning can retain a terminated executable
        # briefly. Retry only this owned directory, with a finite deadline.
        deadline = time.monotonic() + 15
        while True:
            try:
                shutil.rmtree(path)
                break
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)


def main():
    require(sys.platform == "win32", "native Windows kernel required")
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
    require((root / "Cargo.toml").is_file(), "owning worktree required")
    target.mkdir(exist_ok=True)
    require(target.resolve().is_relative_to(root), "control target escapes worktree")
    source = folder / "native-second-chance-v4.cpp"
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    failures = []
    for arch in args.architectures:
        with build_directory(target) as build:
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = PROFILE.compiler_environment(
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
                ],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            require(result.returncode == 0, "second-chance control compilation failed")
            binary = executable.read_bytes()
            pe = struct.unpack_from("<I", binary, 0x3C)[0]
            machine = struct.unpack_from("<H", binary, pe + 4)[0]
            require(
                machine == {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch],
                "control PE machine",
            )
            binary_sha = hashlib.sha256(binary).hexdigest()
            print(
                json.dumps(
                    {
                        "kind": "producer",
                        "arch": arch,
                        "source_sha256": source_sha,
                        "binary_sha256": binary_sha,
                        "compiler_sha256": hashlib.sha256(
                            compiler.read_bytes()
                        ).hexdigest(),
                        "machine": machine,
                    }
                ),
                flush=True,
            )
            for mode in MODES:
                result = subprocess.run(
                    [str(executable), mode],
                    cwd=build,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                require(
                    len(result.stdout) <= 4096 and not result.stderr,
                    "second-chance output bound",
                )
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                require(
                    hashlib.sha256(executable.read_bytes()).hexdigest() == binary_sha,
                    "control executable identity changed",
                )
                print(
                    json.dumps(
                        {
                            "kind": "case",
                            "arch": arch,
                            "mode": mode,
                            "exit_code": result.returncode,
                            "records": rows,
                        }
                    ),
                    flush=True,
                )
                try:
                    validate(mode, result.returncode, rows, arch)
                except (ValueError, RuntimeError) as error:
                    failures.append(f"{arch}/{mode}: {error}")
    require(not failures, "native profile mismatches: " + "; ".join(failures))
    require(
        hashlib.sha256(source.read_bytes()).hexdigest() == source_sha,
        "control source changed",
    )


if __name__ == "__main__":
    main()
