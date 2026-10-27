#!/usr/bin/env python3
"""Observe owned native startup connections and initialized CSR metadata."""

import argparse
import base64
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def machine(path):
    data = Path(path).read_bytes()
    require(data[:2] == b"MZ" and len(data) >= 64, "PE image header")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    require(data[offset : offset + 4] == b"PE\0\0", "PE signature")
    return struct.unpack_from("<H", data, offset + 4)[0]


def startup_summary(raw, secure):
    text = raw.decode("ascii")
    export = "NtSecureConnectPort" if secure else "NtConnectPort"
    arguments = 9 if secure else 8
    require(
        f"protocol export={export} arguments={arguments}" in text, "protocol identity"
    )
    require(re.search(r"^profile width=8 ", text, re.M), "native64 observer width")
    complete = re.findall(
        r"^complete captured=(\d+) calls=(\d+) exit=(\d+)\r?$", text, re.M
    )
    require(len(complete) == 1, "one terminal observer record")
    captured, calls, exit_code = map(int, complete[0])
    require(
        captured == calls and captured < 16 and exit_code == 41,
        "natural owned-child outcome",
    )
    entries = re.findall(
        r"^entry ordinal=(\d+) caller=([A-F0-9]+) args=([A-F0-9,]+)\r?$", text, re.M
    )
    returns = re.findall(r"^return ordinal=(\d+) status=([A-F0-9]{8})\r?$", text, re.M)
    require(len(entries) == len(returns) == calls, "complete entry/return coverage")
    require([int(row[0]) for row in entries] == list(range(calls)), "entry ordering")
    require([int(row[0]) for row in returns] == list(range(calls)), "return ordering")
    require(
        all(row[1] == "00000000" for row in returns),
        "unmodified successful startup calls",
    )
    require(
        all(len(row[2].rstrip(",").split(",")) == arguments for row in entries),
        "argument count",
    )
    dumps = []
    for line in text.splitlines():
        if not line.startswith("dump "):
            continue
        match = re.fullmatch(
            r"dump name=([\w-]+) address=([A-F0-9]+) requested=(\d+) ok=(\d+) error=(\d+) got=(\d+) hex=([A-F0-9]*)",
            line,
        )
        require(match is not None, "raw dump grammar")
        name, address, requested, ok, error, got, data = match.groups()
        data = bytes.fromhex(data)
        require(len(data) == int(got) <= int(requested), "raw dump extent")
        if name != "caller-code":
            require(
                int(ok) == 1 and int(error) == 0 and len(data) == int(requested),
                "complete protocol dump",
            )
        dumps.append(
            {
                "name": name,
                "address": int(address, 16),
                "requested": int(requested),
                "ok": int(ok),
                "error": int(error),
                "hex": data.hex(),
            }
        )
    return {
        "export": export,
        "arguments": arguments,
        "calls": calls,
        "child_exit": exit_code,
        "dumps": dumps,
    }


def main():
    require(sys.platform == "win32", "native Windows required")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--environment", help="private native compiler environment snapshot"
    )
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parents[3]
    target = root / "target"
    target.mkdir(exist_ok=True)
    require(target.resolve().is_relative_to(root), "contained build output")
    arch = "arm64" if platform.machine().lower() == "arm64" else "x64"
    expected = 0xAA64 if arch == "arm64" else 0x8664
    require(machine(sys.executable) == expected, "native64 Python PE")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.IsWow64Process2.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort),
        ctypes.POINTER(ctypes.c_ushort),
    ]
    process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
    require(
        kernel.IsWow64Process2(
            kernel.GetCurrentProcess(),
            ctypes.byref(process_machine),
            ctypes.byref(native_machine),
        ),
        "native machine query",
    )
    require(
        process_machine.value == 0 and native_machine.value == expected,
        "native process/kernel machine",
    )
    helper = folder.parent / "native-exception-entry-profile/run-v2.py"
    spec = importlib.util.spec_from_file_location("native_compiler_profile", helper)
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    sources = [
        Path(__file__).resolve(),
        helper,
        folder / "startup-v2.cpp",
        folder / "metadata-v2.cpp",
    ]
    source_before = {str(path.relative_to(root)): digest(path) for path in sources}
    ntdll = Path(os.environ["WINDIR"]) / "System32/ntdll.dll"
    identities = {"python": digest(sys.executable), "ntdll": digest(ntdll)}
    report = {
        "schema": 3,
        "arch": arch,
        "machine": expected,
        "kernel": list(sys.getwindowsversion()),
        "sources": source_before,
        "identities": identities,
        "runs": [],
        "state": "running",
    }
    destination = target / "native-session-csr-connect-v3.json"

    def save():
        destination.write_text(json.dumps(report, indent=2), encoding="utf-8")

    save()
    try:
        with tempfile.TemporaryDirectory(
            prefix="native-session-csr-connect-v3-", dir=target
        ) as name:
            build = Path(name)
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = profile.compiler_environment(
                arch, args.environment, temporary
            )
            report["compiler_sha256"] = digest(compiler)
            for kind, source, defines in [
                ("connect", folder / "startup-v2.cpp", []),
                ("secure", folder / "startup-v2.cpp", ["/DOBSERVE_SECURE_CONNECT=1"]),
                ("metadata", folder / "metadata-v2.cpp", []),
            ]:
                executable = build / (kind + ".exe")
                command = [
                    str(compiler),
                    "/nologo",
                    "/std:c++20",
                    "/Od",
                    "/EHsc",
                    "/W4",
                    "/WX",
                    "/MT",
                    *defines,
                    str(source),
                    "/Fe:" + str(executable),
                    "/Fo:" + str(build / (kind + ".obj")),
                ]
                result = subprocess.run(
                    command, cwd=build, env=env, capture_output=True, timeout=120
                )
                row = {
                    "kind": kind,
                    "compile_exit": result.returncode,
                    "compile_stdout_b64": base64.b64encode(result.stdout).decode(),
                    "compile_stderr_b64": base64.b64encode(result.stderr).decode(),
                }
                report["runs"].append(row)
                save()
                require(
                    result.returncode == 0,
                    "native observer compilation failed: "
                    + result.stdout.decode(errors="replace")
                    + result.stderr.decode(errors="replace"),
                )
                require(machine(executable) == expected, "native observer PE machine")
                row["binary_sha256"] = digest(executable)
                result = subprocess.run(
                    [str(executable)],
                    cwd=build,
                    env=env,
                    capture_output=True,
                    timeout=150,
                )
                require(
                    len(result.stdout) <= 262144 and len(result.stderr) <= 16384,
                    "bounded observer output",
                )
                row.update(
                    exit_code=result.returncode,
                    stdout_b64=base64.b64encode(result.stdout).decode(),
                    stderr_b64=base64.b64encode(result.stderr).decode(),
                    stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                )
                save()
                require(
                    result.returncode == 0,
                    f"native {kind} observer failed; raw output preserved",
                )
                require(
                    digest(executable) == row["binary_sha256"],
                    "observer executable unchanged",
                )
                if kind != "metadata":
                    row["summary"] = startup_summary(result.stdout, kind == "secure")
                else:
                    text = result.stdout.decode("ascii")
                    require(
                        "complete status=0 read-only=1" in text,
                        "readonly metadata terminal record",
                    )
                    require(
                        re.search(r"^session id=\d+\r?$", text, re.M),
                        "own primary-session record",
                    )
                    require(
                        "dump name=selected-prefix " in text
                        and "selected-region ordinal=0 " in text,
                        "initialized readonly section geometry",
                    )
                save()
            require(
                sum(row.get("summary", {}).get("calls", 0) for row in report["runs"])
                > 0,
                "at least one native startup connection captured",
            )
            if arch == "x64":
                metadata_row = next(
                    row for row in report["runs"] if row["kind"] == "metadata"
                )
                text = base64.b64decode(metadata_row["stdout_b64"]).decode("ascii")
                match = re.search(
                    r"^csr-pid-global pid-address=[A-F0-9]+ flag-address=[A-F0-9]+ raw=([A-F0-9]+) flag=(\d+) effective=([A-F0-9]+)\r?$",
                    text,
                    re.M,
                )
                require(match is not None, "verified readonly PID-global capture")
                pid = int(match[3], 16)
                require(pid > 0, "initialized nonzero CSR PID")
                replies = [
                    bytes.fromhex(dump["hex"])
                    for row in report["runs"]
                    for dump in row.get("summary", {}).get("dumps", [])
                    if dump["name"] == "connection-after"
                ]
                require(
                    replies
                    and all(
                        len(reply) >= 24
                        and int.from_bytes(reply[16:24], "little") == pid
                        for reply in replies
                    ),
                    "independent reply/PID-global agreement",
                )
                report["pid_global_matches_replies"] = True
            require(
                digest(compiler) == report["compiler_sha256"],
                "compiler identity unchanged",
            )
        require(
            source_before
            == {str(path.relative_to(root)): digest(path) for path in sources},
            "source identities unchanged",
        )
        require(
            identities == {"python": digest(sys.executable), "ntdll": digest(ntdll)},
            "runtime identities unchanged",
        )
        report["state"] = "finished"
    except BaseException as error:
        report.update(state="failed", error=repr(error))
        raise
    finally:
        save()
    print(
        json.dumps(
            {
                "output": str(destination.relative_to(root)),
                "state": report["state"],
                "calls": [
                    row.get("summary", {}).get("calls") for row in report["runs"]
                ],
            }
        )
    )


if __name__ == "__main__":
    main()
