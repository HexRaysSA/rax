#!/usr/bin/env python3
"""Rebuild the small native exception-entry fixtures without an SDK or CRT."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--linker", default="lld-link")
    parser.add_argument("--dlltool", default="llvm-dlltool")
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parents[4]
    assert (root / "Cargo.toml").is_file()
    target = root / "target"
    target.mkdir(exist_ok=True)
    assert target.resolve().is_relative_to(root)
    tools = {}
    for key, value in vars(args).items():
        found = shutil.which(value)
        if found is None:
            raise FileNotFoundError(f"required tool is unavailable: {value}")
        # LLVM's multi-call tools select their personality from argv[0].
        tools[key] = Path(found).absolute()
    manifest = {
        "source_sha256": sha256(folder / "src/fault.c"),
        "tools": {
            key: {"name": value.name, "sha256": sha256(value)}
            for key, value in tools.items()
        },
        "fixtures": [],
    }
    matrix = [
        (
            "x86",
            "i686-pc-windows-msvc",
            "i386",
            "x86",
            "AddVectoredExceptionHandler@8\nRemoveVectoredExceptionHandler@4\nExitProcess@4",
            [],
        ),
        (
            "x64",
            "x86_64-pc-windows-msvc",
            "i386:x86-64",
            "x64",
            "AddVectoredExceptionHandler\nRemoveVectoredExceptionHandler\nExitProcess",
            [],
        ),
        (
            "arm64",
            "aarch64-pc-windows-msvc",
            "arm64",
            "arm64",
            "AddVectoredExceptionHandler\nRemoveVectoredExceptionHandler\nExitProcess",
            ["-mgeneral-regs-only", "-ffixed-x18"],
        ),
    ]
    with tempfile.TemporaryDirectory(
        prefix="native-exception-fixture-", dir=target
    ) as temporary:
        build = Path(temporary)
        env = os.environ.copy()
        env.update(TMPDIR=str(build), TMP=str(build), TEMP=str(build))
        for arch, triple, dll_machine, machine, exports, extra in matrix:
            definition = build / "kernel32.def"
            definition.write_text("LIBRARY KERNEL32.dll\nEXPORTS\n" + exports + "\n")
            library, obj = build / "kernel32.lib", build / "fault.obj"
            output = folder / "bin" / arch / "fault.exe"
            output.parent.mkdir(parents=True, exist_ok=True)
            commands = [
                [
                    str(tools["dlltool"]),
                    "-m",
                    dll_machine,
                    "-k",
                    "-d",
                    str(definition),
                    "-l",
                    str(library),
                ],
                [
                    str(tools["clang"]),
                    "--target=" + triple,
                    "-O1",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-fno-ident",
                    "-fno-vectorize",
                    "-fno-slp-vectorize",
                    "-fno-asynchronous-unwind-tables",
                    "-fno-unwind-tables",
                    "-ffile-prefix-map=" + str(folder) + "=.",
                    *extra,
                    "-c",
                    str(folder / "src/fault.c"),
                    "-o",
                    str(obj),
                ],
                [
                    str(tools["linker"]),
                    "/machine:" + machine,
                    "/entry:entry",
                    "/subsystem:console",
                    "/nodefaultlib",
                    "/timestamp:0",
                    "/dynamicbase",
                    "/nxcompat",
                    "/stack:1048576,4096",
                    "/heap:1048576,4096",
                    "/out:" + str(output),
                    str(obj),
                    str(library),
                ],
            ]
            for command in commands:
                subprocess.run(command, cwd=build, env=env, check=True)
            manifest["fixtures"].append(
                {
                    "arch": arch,
                    "path": str(output.relative_to(folder)).replace("\\", "/"),
                    "bytes": output.stat().st_size,
                    "sha256": sha256(output),
                }
            )
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
