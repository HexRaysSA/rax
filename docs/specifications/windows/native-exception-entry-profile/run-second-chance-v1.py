#!/usr/bin/env python3
"""Measure native second-chance termination and argument-copy failures."""

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
MODES = ("last", "invalid-record", "invalid-context")


def validate(mode, exit_code, rows):
    require(mode in MODES, "unknown second-chance control mode")
    require(
        rows and rows[0] == {"kind": "ready", "mode": mode, "code": EXCEPTION},
        "second-chance input identity",
    )
    if mode == "last":
        require(
            exit_code & 0xFFFFFFFF == EXCEPTION and len(rows) == 1,
            "second-chance process termination without user handler",
        )
    else:
        require(exit_code == 0 and len(rows) == 2, "invalid argument control exit")
        require(
            rows[1]
            == {
                "kind": "complete",
                "seen": 0,
                "caught": 0,
                "call_returned": True,
                "status": ACCESS_VIOLATION,
                "removed": True,
            },
            "invalid argument copy status and handler cleanup",
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
    source = folder / "native-second-chance-v1.cpp"
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
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
                validate(mode, result.returncode, rows)
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
    require(
        hashlib.sha256(source.read_bytes()).hexdigest() == source_sha,
        "control source changed",
    )


if __name__ == "__main__":
    main()
