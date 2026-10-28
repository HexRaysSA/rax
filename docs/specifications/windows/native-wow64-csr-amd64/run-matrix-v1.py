"""Run the frozen fresh/retry WoW64 CSR controls on native AMD64 kernels."""

from pathlib import Path
import base64
import hashlib
import importlib.util
import json
import os
import platform
import re
import struct
import subprocess
import sys
import tempfile
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
OUTPUT = ROOT / "target/native-wow64-csr-amd64-matrix-v1.json"
SOURCE = ROOT / "docs/specifications/windows/native-wow64-csr-connect"
HELPER = ROOT / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
HELPER_HASH = "391b84e6c0477abc27ca6d20c41a37078f2074fe34d4b2620a3ec8ec34df30ba"
FROZEN = {
    "initial-v8.cpp": (
        "edffb6d0fbb4e4224e8ae294c36a767760245d243c271e80fde4d97318d04af5",
        "bcd63838aa137f280c4076d9c18227048c1af437d63b2d89f263b9cff7fdbd03",
    ),
    "initial-v9.cpp": (
        "868bd617de633cc742e64fa2da600a336edb36cc3359e593172c329f00504c0b",
        "e5792efd546e9ab6c73bcdcae0dc272ad8235f7e673637f7207e83782dd4fcea",
    ),
    "initial-child-v1.cpp": (
        "ef16f8b19e715cd4cfe2064f97326e874ff50c0d54be72dec5a511a68084af7c",
        "b6caac231954214245d2abae2da5ddd2b55082cd05c23f648cd475a156dc4ee9",
    ),
}
CASES = {
    "initial-v8.cpp": [
        "valid",
        "zero",
        "short",
        "null-buffer",
        "noaccess-buffer",
        "readonly-buffer",
        "guard-buffer",
        "bad-inside",
        "guard-inside",
        "null-root",
        "bad-root",
        "missing-root",
        "readonly-inside",
        "readonly-guard-inside",
        "null-inside",
        "guard-root",
        "null-buffer-null-root",
        "zero-bad-root",
        "length-16",
        "length-64",
        "retry-valid",
        "retry-readonly-buffer",
        "retry-noaccess-buffer",
        "retry-guard-buffer",
        "retry-bad-inside",
        "retry-guard-inside",
    ],
    "initial-v9.cpp": [
        "lower-root",
        "upper-root",
        "trailing-root",
        "root-only",
        "retry-guard-inside-null-buffer",
    ],
}


def identity(path):
    path = Path(path)
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest}


def pe_machine(path):
    raw = path.read_bytes()
    offset = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[offset : offset + 4] != b"PE\0\0":
        raise RuntimeError("Compiled control is not a PE image")
    return struct.unpack_from("<H", raw, offset + 4)[0]


def main():
    if sys.platform != "win32" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("Independent native AMD64 Windows kernel required")
    kernel = list(sys.getwindowsversion())
    if tuple(kernel[:2]) != (10, 0) or kernel[2] not in (20348, 26100):
        raise RuntimeError(f"Unmeasured native AMD64 kernel: {kernel}")
    target = ROOT / "target"
    target.mkdir(exist_ok=True)
    if not target.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("Target escaped source worktree")
    state = {
        "schema": "native-wow64-csr-amd64-matrix-v1",
        "pid": os.getpid(),
        "kernel": kernel,
        "machine": platform.machine(),
        "state": "started",
        "compilations": [],
        "samples": [],
    }
    with OUTPUT.open("x", encoding="utf-8") as out:
        json.dump(state, out, indent=2)

    def save():
        OUTPUT.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def execute(argv, env, work, timeout):
        start = time.monotonic()
        result = subprocess.run(
            argv,
            cwd=work,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "exit_code": result.returncode,
            "seconds": time.monotonic() - start,
            "stdout_b64": base64.b64encode(result.stdout).decode(),
            "stderr_b64": base64.b64encode(result.stderr).decode(),
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        }

    try:
        if identity(HELPER)["sha256"] != HELPER_HASH:
            raise RuntimeError("Frozen compiler helper changed")
        for name, hashes in FROZEN.items():
            if identity(SOURCE / name)["sha256"] not in hashes:
                raise RuntimeError(f"Frozen control source changed: {name}")
        windows = Path(os.environ["SystemRoot"])
        paths = [
            Path(__file__).resolve(),
            HELPER,
            *(SOURCE / name for name in FROZEN),
            Path(sys.executable),
            windows / "System32/ntdll.dll",
            windows / "SysWOW64/ntdll.dll",
        ]
        state["inputs"] = [identity(path) for path in paths]
        save()
        spec = importlib.util.spec_from_file_location("profile", HELPER)
        profile = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profile)
        with tempfile.TemporaryDirectory(
            prefix="native-wow64-csr-amd64-matrix-v1-", dir=target
        ) as temporary:
            work = Path(temporary)
            if not work.resolve().is_relative_to(ROOT.resolve()):
                raise RuntimeError("Build directory escaped source worktree")
            environments = {}
            compilers = {}
            for architecture in ("x86", "x64"):
                scratch = work / ("tmp-" + architecture)
                scratch.mkdir()
                env, compiler = profile.compiler_environment(
                    architecture, None, scratch
                )
                environments[architecture] = env
                compilers[architecture] = identity(compiler)
            state["compilers"] = compilers
            save()
            child = work / "controlled-child.exe"
            child_args = [
                compilers["x86"]["path"],
                "/nologo",
                "/std:c++20",
                "/GS-",
                "/Zl",
                "/W4",
                "/WX",
                str(SOURCE / "initial-child-v1.cpp"),
                "/Fe:" + str(child),
                "/Fo:" + str(work / "child.obj"),
                "/link",
                "/ENTRY:entry",
                "/SUBSYSTEM:CONSOLE",
                "/NODEFAULTLIB",
                "kernel32.lib",
            ]
            plans = [("child", child, 0x14C, child_args, "x86")]
            for ordinal, name in enumerate(CASES):
                executable = work / ("control-" + str(ordinal) + ".exe")
                arguments = [
                    compilers["x64"]["path"],
                    "/nologo",
                    "/std:c++20",
                    "/MT",
                    "/EHsc",
                    "/utf-8",
                    "/W4",
                    "/WX",
                    str(SOURCE / name),
                    "/Fe:" + str(executable),
                    "/Fo:" + str(work / ("parent-" + str(ordinal) + ".obj")),
                ]
                plans.append((name, executable, 0x8664, arguments, "x64"))
            binaries = {}
            for name, executable, machine, argv, architecture in plans:
                state.update(state="compiling", current=name)
                save()
                result = execute(argv, environments[architecture], work, 120)
                state["compilations"].append({"source": name, "argv": argv, **result})
                save()
                if result["exit_code"] or pe_machine(executable) != machine:
                    raise RuntimeError(
                        f"Control compilation or PE machine failed: {name}"
                    )
                binaries[name] = {"machine": machine, **identity(executable)}
            state["binaries"] = binaries
            save()
            for source, modes in CASES.items():
                executable = binaries[source]["path"]
                for mode in modes:
                    state.update(state="observing", current=source + ":" + mode)
                    save()
                    result = execute(
                        [executable, str(child), mode], environments["x64"], work, 150
                    )
                    state["samples"].append({"source": source, "mode": mode, **result})
                    save()
                    lines = (
                        base64.b64decode(result["stdout_b64"])
                        .decode("utf-8")
                        .splitlines()
                    )
                    terminal = lines[-1] if lines else ""
                    match = re.fullmatch(
                        r"DONE installed=1 entered=(\d+) returned=(\d+) base-calls=(\d+) pending=0 exit=70",
                        terminal,
                    )
                    expected = 2 if mode.startswith("retry-") else 1
                    if (
                        result["exit_code"]
                        or not match
                        or int(match[1]) != expected
                        or int(match[2]) != expected
                        or not 1 <= int(match[3]) <= expected
                    ):
                        raise RuntimeError(
                            f"Incomplete controlled entry/return proof: {source}:{mode}"
                        )
                    state["samples"][-1]["terminal"] = terminal
                    if [identity(path) for path in paths] != state["inputs"]:
                        raise RuntimeError(
                            "Control source or installed runtime changed"
                        )
                    for name, binary in binaries.items():
                        if identity(binary["path"]) != {
                            k: v for k, v in binary.items() if k != "machine"
                        }:
                            raise RuntimeError(f"Executed control changed: {name}")
                    if any(identity(v["path"]) != v for v in compilers.values()):
                        raise RuntimeError("Native compiler changed")
                    save()
            if len(state["samples"]) != 31:
                raise RuntimeError("Incomplete native control matrix")
        state.update(
            state="finished",
            exit_code=0,
            inputs_unchanged=True,
            build_outputs_removed=True,
        )
    except BaseException:
        state.update(state="failed", exit_code=1, error=traceback.format_exc())
    finally:
        save()
    if state["exit_code"]:
        raise RuntimeError(state["error"])
    print(
        json.dumps(
            {"output": str(OUTPUT), "samples": len(state["samples"]), "kernel": kernel}
        )
    )


if __name__ == "__main__":
    main()
