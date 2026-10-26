#!/usr/bin/env python3
"""Observe image metadata before a task-owned child executes user code."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("image_control", FOLDER / "run-v9.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
PROFILES = (
    "default",
    "no-relocation-directory",
    "no-directory-no-dynamic-base",
    "stripped-with-directory",
)


def patched(binary, profile):
    if profile not in PROFILES:
        raise ValueError("unknown relocation-directory profile")
    data = bytearray(binary)
    pe = struct.unpack_from("<I", data, 60)[0]
    optional = pe + 24
    wide = struct.unpack_from("<H", data, optional)[0] == 0x20B
    if profile in ("no-relocation-directory", "no-directory-no-dynamic-base"):
        struct.pack_into("<II", data, optional + (112 if wide else 96) + 40, 0, 0)
    if profile == "no-directory-no-dynamic-base":
        flags = struct.unpack_from("<H", data, optional + 70)[0]
        struct.pack_into("<H", data, optional + 70, flags & ~0x60)
    if profile == "stripped-with-directory":
        flags = struct.unpack_from("<H", data, pe + 22)[0]
        struct.pack_into("<H", data, pe + 22, flags | 1)
    return bytes(data)


def query_suspended(candidate, env, build):
    # CREATE_SUSPENDED (0x4) keeps this owned image before user entry; no startup
    # success is inferred from section creation. Popen retains our process handle.
    child = subprocess.Popen(
        [str(candidate)],
        cwd=build,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=0x4 | subprocess.CREATE_NO_WINDOW,
    )
    try:
        query = ctypes.WinDLL("ntdll").NtQueryInformationProcess
        query.argtypes = [
            wintypes.HANDLE,
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        ]
        query.restype = wintypes.LONG
        output, returned = ctypes.create_string_buffer(64), wintypes.ULONG()
        status = (
            query(int(child._handle), 37, output, 64, ctypes.byref(returned))
            & 0xFFFFFFFF
        )
        raw = output.raw
        section = [
            struct.unpack_from("<I", raw, 8)[0],
            struct.unpack_from("<Q", raw, 16)[0],
            struct.unpack_from("<Q", raw, 24)[0],
            struct.unpack_from("<I", raw, 32)[0],
            *struct.unpack_from("<HHHHHHHBBIII", raw, 36),
        ]
        if status or returned.value != 64:
            raise RuntimeError("native image-section query failed")
        # TransferAddress and native padding are never published.
        return {
            "available": True,
            "status": status,
            "returned": returned.value,
            "section": section,
            "query_calls": 1,
            "child_suspended": True,
            "parent_pointer_bytes": 8,
        }
    finally:
        child.terminate()
        child.wait(timeout=30)


def main():
    if sys.platform != "win32" or struct.calcsize("P") != 8:
        raise RuntimeError("native 64-bit Windows Python required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment")
    parser.add_argument(
        "--architectures",
        nargs="+",
        choices=("arm64", "x64", "x86"),
        default=("x64", "x86"),
    )
    args = parser.parse_args()
    root = FOLDER.parents[3]
    target = root / "target"
    target.mkdir(exist_ok=True)
    if not (root / "Cargo.toml").is_file() or not target.resolve().is_relative_to(root):
        raise RuntimeError("in-tree compiler output required")
    source = FOLDER / "native-image-information-v7.cpp"
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    driver_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    for arch in args.architectures:
        with CONTROL.CONTROL.build_directory(target) as build:
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = CONTROL.CONTROL.PROFILE.compiler_environment(
                arch, args.environment, temporary
            )
            original = build / "original.exe"
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
                    "/Fe:" + str(original),
                    "/Fo:" + str(build / "observer.obj"),
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
                raise RuntimeError(result.stdout + result.stderr)
            binary = original.read_bytes()
            base, fields = CONTROL.file_metadata(binary)
            result = subprocess.run(
                [str(original), format(base, "x"), "metadata"],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            CONTROL.validate(rows, arch, True)
            if result.returncode or result.stderr:
                raise RuntimeError("original metadata observer failed")
            print(
                json.dumps(
                    {
                        "kind": "metadata-baseline",
                        "arch": arch,
                        "rows": rows,
                        "binary_sha256": hashlib.sha256(binary).hexdigest(),
                        "source_sha256": source_sha,
                        "driver_sha256": driver_sha,
                        "query_calls": 1,
                    }
                ),
                flush=True,
            )
            for profile in PROFILES:
                payload = patched(binary, profile)
                candidate = build / (profile + ".exe")
                candidate.write_bytes(payload)
                digest = hashlib.sha256(payload).hexdigest()
                _, fields = CONTROL.file_metadata(payload)
                row = {
                    "kind": "section-metadata",
                    "arch": arch,
                    "profile": profile,
                    "pe_fields": fields,
                    "file_bytes": len(payload),
                    "source_sha256": source_sha,
                    "driver_sha256": driver_sha,
                    "binary_sha256": digest,
                    "compiled_binary_sha256": hashlib.sha256(binary).hexdigest(),
                    "compiler_sha256": hashlib.sha256(
                        compiler.read_bytes()
                    ).hexdigest(),
                    "host": rows[0],
                    "relocation_directory": list(
                        struct.unpack_from(
                            "<II",
                            payload,
                            struct.unpack_from("<I", payload, 60)[0]
                            + 24
                            + (112 if arch != "x86" else 96)
                            + 40,
                        )
                    ),
                }
                try:
                    row.update(query_suspended(candidate, env, build))
                except OSError as error:
                    if (
                        arch != "arm64"
                        or profile
                        not in (
                            "no-directory-no-dynamic-base",
                            "stripped-with-directory",
                        )
                        or error.winerror != 193
                    ):
                        raise
                    row.update(available=False, windows_error=193, query_calls=0)
                print(json.dumps(row), flush=True)
                if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                    raise RuntimeError("owned executable changed")
            if (
                hashlib.sha256(original.read_bytes()).hexdigest()
                != hashlib.sha256(binary).hexdigest()
            ):
                raise RuntimeError("original executable changed")
    if (
        hashlib.sha256(source.read_bytes()).hexdigest() != source_sha
        or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != driver_sha
    ):
        raise RuntimeError("observation source changed")


if __name__ == "__main__":
    main()
