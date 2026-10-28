"""Observe the resources behind this process's native WoW64 information."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("startup", FOLDER / "run-v2.py")
STARTUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STARTUP)


def validate(rows):
    kinds = [row["kind"] for row in rows]
    if kinds not in (["unknown_word"], ["unknown_word", "section", "work_list"]):
        raise ValueError("complete resource observations required")
    unknown = rows[0]
    if unknown["nonnull"]:
        if len(rows) != 3:
            raise ValueError("software-emulator resources are missing")
        if not (
            unknown["mapped"]
            and unknown["state"] == 0x1000
            and unknown["protect"] == 0x20
            and unknown["type"] == 0x1000000
            and unknown["module_basename"].lower() == "xtajit.dll"
            and not unknown["equals_ntdll_base"]
        ):
            raise ValueError("opaque word has an unqualified native identity")
    if len(rows) == 3:
        section, work = rows[1:]
        if not (
            section["query_status"] == section["object_status"] == 0
            and section["return_bytes"] == 16
            and section["maximum_bytes"] == 16384
            and section["attributes"] == 0x08000000
            and not section["base_nonnull"]
            and section["object_return_bytes"] == 56
            and section["object_attributes"] == 0
            and section["granted_access"] == 0xF001F
            and work["status"] == 0
            and work["copied_bytes"] == 48
            and work["free_first"] == 16328
            and work["free_counter"] == 408
            and work["work_first"] == work["work_counter"] == 0
            and not work["reserved_nonzero"]
        ):
            raise ValueError("unqualified quiescent section/work-list state")
    return rows


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
    source = FOLDER / "native-wow64-resources-v2.cpp"
    inputs = [source, Path(__file__).resolve(), FOLDER / "run-v2.py"]
    digests = {str(p.relative_to(FOLDER)): STARTUP.sha(p) for p in inputs}
    with STARTUP.CONTROL.build_directory(target) as build:
        temporary = build / "tmp"
        temporary.mkdir()
        env, compiler = STARTUP.CONTROL.PROFILE.compiler_environment(
            "x86", args.environment, temporary
        )
        compiler = Path(compiler)
        compiler_digest = STARTUP.sha(compiler)
        executable = build / "probe.exe"
        built = subprocess.run(
            [
                str(compiler),
                "/nologo",
                "/std:c++20",
                "/MT",
                "/EHsc",
                "/utf-8",
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
        if built.returncode:
            raise RuntimeError(
                "control compilation failed: " + built.stdout + built.stderr
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
            STARTUP.sha(executable) == executable_digest
            and STARTUP.sha(compiler) == compiler_digest
            and all(
                STARTUP.sha(FOLDER / name) == value for name, value in digests.items()
            )
        )
        print(
            json.dumps(
                {
                    "kind": "native_resource_capture",
                    "sources": digests,
                    "compiler_sha256": compiler_digest,
                    "binary_sha256": executable_digest,
                    "binary_bytes": len(binary),
                    "inputs_unchanged": unchanged,
                    "exit_code": result.returncode,
                    "rows": rows,
                }
            ),
            flush=True,
        )
        if result.returncode or not unchanged:
            raise RuntimeError(
                "native resource control failed or an executed input changed"
            )
        validate(rows)
        print(json.dumps({"kind": "validated", "resources": len(rows)}), flush=True)


if __name__ == "__main__":
    main()
