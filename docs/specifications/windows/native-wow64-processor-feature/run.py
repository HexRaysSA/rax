#!/usr/bin/env python3
"""Observe the native WoW64 processor-feature service without host emulation."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
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
INDICES = (*range(256), 0x10000, 0x80000000, 0xFFFFFFFF)


def validate(rows):
    if len(rows) != len(INDICES) + 1:
        raise ValueError("incomplete feature observation")
    host = rows[0]
    if (
        set(host)
        != {"kind", "build", "process_machine", "native_machine", "pointer_bytes"}
        or host["kind"] != "host"
        or host["process_machine"] != 0x14C
        or host["pointer_bytes"] != 4
        or host["native_machine"] not in (0x8664, 0xAA64)
        or type(host["build"]) is not int
        or host["build"] <= 0
    ):
        raise ValueError("invalid WoW64 host identity")
    for index, row in zip(INDICES, rows[1:]):
        if (
            set(row) != {"kind", "index", "nt", "rtl", "win32"}
            or row["kind"] != "feature"
            or type(row["index"]) is not int
            or row["index"] != index
            or any(
                type(row[name]) is not int or row[name] not in (0, 1)
                for name in ("nt", "rtl", "win32")
            )
        ):
            raise ValueError("invalid feature observation")
    return rows


def main():
    if sys.platform != "win32":
        raise RuntimeError("native Windows kernel required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment")
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parents[3]
    target = root / "target"
    target.mkdir(exist_ok=True)
    if not (root / "Cargo.toml").is_file() or not target.resolve().is_relative_to(root):
        raise RuntimeError("in-tree control target required")
    source = folder / "native-wow64-processor-v1.cpp"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with CONTROL.build_directory(target) as build:
        temporary = build / "tmp"
        temporary.mkdir()
        env, compiler = CONTROL.PROFILE.compiler_environment(
            "x86", args.environment, temporary
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
                "control compilation failed: " + result.stdout + result.stderr
            )
        binary = exe.read_bytes()
        pe = struct.unpack_from("<I", binary, 0x3C)[0]
        if struct.unpack_from("<H", binary, pe + 4)[0] != 0x14C:
            raise RuntimeError("WoW64 x86 executable required")
        binary_digest = hashlib.sha256(binary).hexdigest()
        result = subprocess.run(
            [str(exe)], cwd=build, env=env, capture_output=True, text=True, timeout=15
        )
        if result.returncode or result.stderr or len(result.stdout) > 32768:
            raise RuntimeError("control failed or exceeded its output contract")
        rows = validate([json.loads(line) for line in result.stdout.splitlines()])
        if hashlib.sha256(exe.read_bytes()).hexdigest() != binary_digest:
            raise RuntimeError("control executable changed")
        print(
            json.dumps(
                {
                    "kind": "observation",
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
    if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
        raise RuntimeError("control source changed")


if __name__ == "__main__":
    main()
