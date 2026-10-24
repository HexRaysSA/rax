#!/usr/bin/env python3
"""Observe an owned child's native dispatcher entry without exporting stack bytes."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location(
    "exception_profile", Path(__file__).with_name("run-v2.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)
require = PROFILE.require

FIELDS = {
    "host": {
        "build",
        "native_processor_architecture",
        "process_machine",
        "native_machine",
        "ntdll_machine",
        "context_bytes",
        "record_bytes",
        "dispatcher_rva",
    },
    "fault_stop": {
        "context_read",
        "selected_ntdll_identity",
        "breakpoint_installed",
        "fault_sp_mod16",
    },
    "dispatcher_entry": {
        "frame_bytes",
        "entry_sp_mod16",
        "context_candidates",
        "record_candidates",
        "context_offset_bytes",
        "record_offset_bytes",
        "context_flags",
        "frame_captured",
    },
    "child_handler": {
        "seen",
        "caught",
        "context_to_fault_sp_bytes",
        "record_to_fault_sp_bytes",
        "handler_removed",
        "freed",
    },
    "complete": {
        "fault_seen",
        "entry_captured",
        "breakpoint_restored",
        "child_exit",
        "child_wait",
        "failed",
    },
    "last_chance": {"code"},
    "create_failed": {"error"},
}


def project_record(row):
    """Reject undeclared fields before a native record can enter a public log."""
    if row.get("kind") == "code":
        return PROFILE.project_record(row)
    require(row.get("kind") in FIELDS, "unknown dispatcher record")
    require(set(row) == {"kind"} | FIELDS[row["kind"]], "unexpected dispatcher fields")
    return dict(row)


def validate_capture(rows, arch):
    require(
        [row["kind"] for row in rows]
        == [
            "host",
            "code",
            "fault_stop",
            "dispatcher_entry",
            "child_handler",
            "complete",
        ],
        "dispatcher event sequence",
    )
    host, code, fault, entry, child, complete = rows
    require(
        host["ntdll_machine"] == {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch],
        "selected NTDLL ABI",
    )
    require(host["native_machine"] in (0xAA64, 0x8664, 0x14C), "native kernel machine")
    require(
        code["export"] == "KiUserExceptionDispatcher"
        and code["rva"] == host["dispatcher_rva"],
        "dispatcher code identity",
    )
    require(
        all(
            fault[key] is True
            for key in (
                "context_read",
                "selected_ntdll_identity",
                "breakpoint_installed",
            )
        ),
        "owned fault and selected dispatcher",
    )
    require(
        entry["frame_captured"] is True
        and entry["context_candidates"] == 1
        and entry["record_candidates"] == 1,
        "unique entry records",
    )
    require(0 < entry["frame_bytes"] <= 8192, "entry frame bound")
    for prefix in ("context", "record"):
        offset = entry[prefix + "_offset_bytes"]
        require(
            isinstance(offset, int)
            and 0 <= offset <= entry["frame_bytes"] - host[prefix + "_bytes"],
            "record within captured frame",
        )
        require(
            offset - entry["frame_bytes"] == child[prefix + "_to_fault_sp_bytes"],
            "VEH pointer identity",
        )
    require(
        child["seen"] == 1
        and child["caught"] == "C0000005"
        and child["handler_removed"] is True
        and child["freed"] is True,
        "native handler and cleanup",
    )
    require(
        complete
        == {
            "kind": "complete",
            "fault_seen": True,
            "entry_captured": True,
            "breakpoint_restored": True,
            "child_exit": 0,
            "child_wait": 0,
            "failed": False,
        },
        "owned child terminal state",
    )


def main():
    require(sys.platform == "win32", "native Windows kernel required")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--environment", help="existing private Visual Studio environment"
    )
    parser.add_argument(
        "--architectures",
        nargs="+",
        choices=("arm64", "x64", "x86"),
        default=("x64", "x86"),
    )
    arguments = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parents[3]
    target = root / "target"
    require((root / "Cargo.toml").is_file(), "owning RAX worktree required")
    target.mkdir(exist_ok=True)
    require(target.resolve().is_relative_to(root), "build target escapes worktree")
    source = folder / "native-dispatch-entry-v3.cpp"
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    for arch in arguments.architectures:
        with tempfile.TemporaryDirectory(
            prefix="native-dispatch-profile-", dir=target
        ) as name:
            build = Path(name)
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = PROFILE.compiler_environment(
                arch, arguments.environment, temporary
            )
            executable = build / "observer.exe"
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
                    "/Fo:" + str(build / "observer.obj"),
                ],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            require(
                result.returncode == 0,
                "dispatcher observer compilation failed; capture_sha256="
                + hashlib.sha256((result.stdout + result.stderr).encode()).hexdigest(),
            )
            binary = executable.read_bytes()
            pe = struct.unpack_from("<I", binary, 0x3C)[0]
            machine = struct.unpack_from("<H", binary, pe + 4)[0]
            require(
                machine == {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch],
                "observer PE machine",
            )
            binary_sha = hashlib.sha256(binary).hexdigest()
            result = subprocess.run(
                [str(executable)],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            require(
                len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
                "dispatcher output bound",
            )
            rows = [
                project_record(json.loads(line)) for line in result.stdout.splitlines()
            ]
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
            for row in rows:
                print(json.dumps({"arch": arch, **row}), flush=True)
            require(
                result.returncode == 0,
                "dispatcher observer failed: " + str(result.returncode),
            )
            validate_capture(rows, arch)
            require(
                hashlib.sha256(executable.read_bytes()).hexdigest() == binary_sha,
                "observer executable identity changed",
            )
    require(
        hashlib.sha256(source.read_bytes()).hexdigest() == source_sha,
        "observer source changed",
    )


if __name__ == "__main__":
    main()
