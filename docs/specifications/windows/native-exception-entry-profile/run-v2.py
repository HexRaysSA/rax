#!/usr/bin/env python3
"""Build and run bounded native Windows exception-entry observations."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def compiler_environment(arch, saved, temporary):
    env = {key.upper(): value for key, value in os.environ.items()}
    if saved:
        snapshot = json.loads(Path(saved).read_text(encoding="utf-8-sig"))
        env.update({key.upper(): value for key, value in snapshot.items()})
    env.update(TMP=str(temporary), TEMP=str(temporary), TMPDIR=str(temporary))
    if saved:
        installation = Path(env["VCTOOLSINSTALLDIR"]).parents[3]
    else:
        where = (
            Path(env["PROGRAMFILES(X86)"])
            / "Microsoft Visual Studio/Installer/vswhere.exe"
        )
        installation = Path(
            subprocess.check_output(
                [
                    str(where),
                    "-latest",
                    "-products",
                    "*",
                    "-requires",
                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                    "-property",
                    "installationPath",
                ],
                text=True,
                env=env,
                timeout=30,
            ).strip()
        )
    batch = installation / "Common7/Tools/VsDevCmd.bat"
    require(batch.is_file(), "Visual Studio developer command unavailable")
    require(
        not any(value in str(batch) for value in ('"', "\n", "\r", "%")),
        "developer command path",
    )
    host = "arm64" if platform.machine().lower() == "arm64" else "x64"
    command = f'call "{batch}" -no_logo -host_arch={host} -arch={arch} >nul && set'
    # Keep environment output private. Only fixed compiler variables are copied;
    # credentials and unrelated environment values are never logged or emitted.
    result = subprocess.run(
        'cmd.exe /d /s /v:off /c "' + command + '"',
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    require(result.returncode == 0, "Visual Studio environment setup failed")
    selected = {
        "PATH",
        "INCLUDE",
        "LIB",
        "LIBPATH",
        "VCTOOLSINSTALLDIR",
        "VSCMD_ARG_HOST_ARCH",
        "VSCMD_ARG_TGT_ARCH",
    }
    values = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.upper() in selected:
            values[key.upper()] = value
    require(selected <= values.keys(), "incomplete native compiler environment")
    # Windows environment keys are case insensitive, including in inherited
    # snapshots. Drop case variants before installing the selected values.
    env = {key: value for key, value in env.items() if key.upper() not in selected}
    env.update(values)
    for key in ("CL", "_CL_", "LINK", "_LINK_", "CCACHE_DIR", "SCCACHE_DIR"):
        env.pop(key, None)
    compiler = (
        Path(values["VCTOOLSINSTALLDIR"]) / "bin" / ("Host" + host) / arch / "cl.exe"
    )
    require(compiler.is_file(), "native compiler executable absent")
    return env, compiler


def project_record(row):
    """Emit only the bounded public form of a dispatcher code observation."""
    if row.get("kind") != "code":
        require("hex" not in row, "unexpected private instruction capture")
        return dict(row)
    if "hex" not in row:
        require(
            set(row) == {"kind", "export", "available"} and row["available"] is False,
            "unmeasured code record",
        )
        return dict(row)
    require(set(row) == {"kind", "export", "rva", "hex"}, "unexpected code fields")
    code = bytes.fromhex(row["hex"])
    require(len(code) == 192, "dispatcher code extent")
    return {
        "kind": "code",
        "export": row["export"],
        "rva": row["rva"],
        "instruction_bytes": len(code),
        "code_sha256": hashlib.sha256(code).hexdigest(),
    }


def main():
    require(sys.platform == "win32", "native Windows kernel required")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--environment", help="existing private compiler environment snapshot"
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
    source = folder / "native-exception-entry-v2.cpp"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    for arch in arguments.architectures:
        with tempfile.TemporaryDirectory(
            prefix="native-seh-profile-", dir=target
        ) as name:
            build = Path(name)
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = compiler_environment(arch, arguments.environment, temporary)
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
                "SEH observer compilation failed: " + result.stdout + result.stderr,
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
                result.returncode == 0,
                "SEH observer failed: "
                + str(result.returncode)
                + "; capture_sha256="
                + hashlib.sha256(result.stdout.encode()).hexdigest(),
            )
            require(len(result.stdout) <= 65536, "SEH output bound")
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            require(len(rows) == 8 and rows[0]["kind"] == "host", "observer row count")
            cases = [row for row in rows if row["kind"] == "case"]
            require(
                [row["ordinal"] for row in cases] == list(range(4)), "observer cases"
            )
            require(
                all(
                    row["seen"] == 1 and row["freed"] and row["pc_matches"]
                    for row in cases
                ),
                "native observation and cleanup",
            )
            require(
                rows[-1] == {"kind": "complete", "cases": 4, "handler_removed": True},
                "observer terminal record",
            )
            require(
                hashlib.sha256(executable.read_bytes()).hexdigest() == binary_sha,
                "observer executable identity changed",
            )
            print(
                json.dumps(
                    {
                        "kind": "producer",
                        "arch": arch,
                        "source_sha256": digest,
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
                print(json.dumps({"arch": arch, **project_record(row)}), flush=True)
    require(
        hashlib.sha256(source.read_bytes()).hexdigest() == digest,
        "observer source changed",
    )


if __name__ == "__main__":
    main()
