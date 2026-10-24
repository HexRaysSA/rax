#!/usr/bin/env python3
"""Build and run own-process native clock fault controls on Windows."""

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


def normalised_environment(inherited, saved, temporary):
    """Return the compiler environment with every key in its upper-case spelling.

    Windows stores os.environ keys in upper case and resolves environment
    lookups case-insensitively. Copying that mapping into a plain dict keeps the
    upper-case spelling but loses the resolution, so normalise inherited and
    snapshot keys once and read the mixed-case Microsoft names in that spelling.
    A snapshot captured from `set` is not required to preserve any casing.
    """
    environment = {key.upper(): value for key, value in inherited.items()}
    if saved:
        snapshot = json.loads(Path(saved).read_text(encoding="utf-8-sig"))
        environment.update({key.upper(): value for key, value in snapshot.items()})
    environment.update(
        TMP=str(temporary), TEMP=str(temporary), TMPDIR=str(temporary)
    )
    return environment


def self_check():
    """Verify environment normalisation without a native Windows kernel."""
    with tempfile.TemporaryDirectory(prefix="native-clock-profile-") as name:
        saved = Path(name) / "environment.json"
        saved.write_text(
            json.dumps(
                {
                    "VCToolsInstallDir": "C:\\Visual Studio\\VC\\Tools\\MSVC\\14.0",
                    "Path": "C:\\Windows\\System32",
                }
            ),
            encoding="utf-8",
        )
        environment = normalised_environment(
            {"ProgramFiles(x86)": "C:\\Program Files (x86)", "Path": "C:\\stale"},
            str(saved),
            Path(name),
        )
        require(
            environment["PROGRAMFILES(X86)"] == "C:\\Program Files (x86)",
            "inherited environment normalisation",
        )
        require(
            environment["VCTOOLSINSTALLDIR"]
            == "C:\\Visual Studio\\VC\\Tools\\MSVC\\14.0",
            "saved environment normalisation",
        )
        require(
            environment["PATH"] == "C:\\Windows\\System32"
            and "Path" not in environment,
            "saved environment replaces the inherited spelling",
        )
        require(
            environment["TMP"] == name and environment["TEMP"] == name,
            "temporary directory override",
        )


def compiler_environment(arch, saved, temporary):
    env = normalised_environment(os.environ, saved, temporary)
    if saved:
        require("VCTOOLSINSTALLDIR" in env, "developer tools directory absent")
        installation = Path(env["VCTOOLSINSTALLDIR"]).parents[3]
    else:
        require("PROGRAMFILES(X86)" in env, "x86 program files directory absent")
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


def main():
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
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="validate environment normalisation without a native Windows kernel",
    )
    arguments = parser.parse_args()
    if arguments.self_check:
        self_check()
        return
    require(sys.platform == "win32", "native Windows kernel required")
    folder = Path(__file__).resolve().parent
    root = folder.parents[3]
    target = root / "target"
    target.mkdir(exist_ok=True)
    source = folder / "native-clock-profile-v1.cpp"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    for arch in arguments.architectures:
        with tempfile.TemporaryDirectory(
            prefix="native-clock-profile-", dir=target
        ) as name:
            build = Path(name)
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = compiler_environment(arch, arguments.environment, temporary)
            env.update(
                TMP=str(temporary),
                TEMP=str(temporary),
                TMPDIR=str(temporary),
                CCACHE_DISABLE="1",
                SCCACHE_DISABLE="1",
            )
            executable = build / "clock.exe"
            command = [
                str(compiler),
                "/nologo",
                "/std:c++20",
                "/EHsc",
                "/W4",
                "/WX",
                "/MT",
                str(source),
                "/Fe:" + str(executable),
                "/Fo:" + str(build / "clock.obj"),
            ]
            result = subprocess.run(
                command, cwd=build, env=env, capture_output=True, text=True, timeout=60
            )
            if result.returncode:
                raise RuntimeError(
                    "native clock compilation failed: " + result.stdout + result.stderr
                )
            binary = executable.read_bytes()
            pe = struct.unpack_from("<I", binary, 0x3C)[0]
            require(binary[pe : pe + 4] == b"PE\0\0", "producer PE signature")
            machine = struct.unpack_from("<H", binary, pe + 4)[0]
            require(
                machine == {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch],
                "producer PE architecture",
            )
            identity = hashlib.sha256(binary).hexdigest()
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
                f"native clock producer failed: {result.returncode}",
            )
            require(len(result.stdout) <= 262144, "native clock capture bound")
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            require(
                len(rows) == 18 and rows[0]["kind"] == "host",
                "native host and case count",
            )
            require(
                rows[-1] == {"kind": "complete", "cases": 16},
                "terminal native clock record",
            )
            require(
                [row["ordinal"] for row in rows[1:-1]] == list(range(16)),
                "native clock case ordinals",
            )
            require(
                hashlib.sha256(executable.read_bytes()).hexdigest() == identity,
                "producer identity changed",
            )
            print(
                json.dumps(
                    {
                        "kind": "producer",
                        "arch": arch,
                        "machine": machine,
                        "source_sha256": digest,
                        "binary_sha256": identity,
                        "compiler_sha256": hashlib.sha256(
                            compiler.read_bytes()
                        ).hexdigest(),
                    }
                ),
                flush=True,
            )
            for row in rows:
                print(json.dumps({"arch": arch, **row}), flush=True)
    require(
        hashlib.sha256(source.read_bytes()).hexdigest() == digest,
        "native source changed",
    )


if __name__ == "__main__":
    main()
