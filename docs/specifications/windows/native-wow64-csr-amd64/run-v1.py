"""Observe the original x86 fault child at its native AMD64 WoW64 CSR call."""

from pathlib import Path
import base64
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
OUTPUT = ROOT / "target/native-wow64-csr-amd64-startup-v1.json"
CHILD = ROOT / "tests/fixtures/user/windows/native_exception_entry/bin/x86/fault.exe"
CHILD_HASH = "4a0f28a1fba11a97b7498f6bf5b231d32c124ce15d2bcb90084816e342c09544"
HELPER = ROOT / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
HELPER_HASH = "391b84e6c0477abc27ca6d20c41a37078f2074fe34d4b2620a3ec8ec34df30ba"


def identity(path):
    path = Path(path)
    with path.open("rb") as f:
        value = hashlib.file_digest(f, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": value}


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
        "schema": "native-wow64-csr-amd64-startup-v1",
        "kernel": kernel,
        "machine": platform.machine(),
        "pid": os.getpid(),
        "state": "started",
    }
    with OUTPUT.open("x", encoding="utf-8") as out:
        json.dump(state, out, indent=2)

    def save():
        OUTPUT.write_text(json.dumps(state, indent=2), encoding="utf-8")

    try:
        if (
            identity(CHILD)["sha256"] != CHILD_HASH
            or identity(HELPER)["sha256"] != HELPER_HASH
        ):
            raise RuntimeError("Original fixture or frozen compiler helper changed")
        windows = Path(os.environ["SystemRoot"])
        paths = [
            Path(__file__).resolve(),
            Path(__file__).with_name("startup-v1.cpp"),
            CHILD,
            HELPER,
            Path(sys.executable),
            windows / "System32/ntdll.dll",
            windows / "SysWOW64/ntdll.dll",
        ]
        state["inputs"] = [identity(p) for p in paths]
        save()
        spec = importlib.util.spec_from_file_location("profile", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory(
            prefix="native-wow64-csr-amd64-v1-", dir=target
        ) as temporary:
            work = Path(temporary)
            if not work.resolve().is_relative_to(ROOT.resolve()):
                raise RuntimeError("Build directory escaped source worktree")
            scratch = work / "tmp"
            scratch.mkdir()
            env, compiler = helper.compiler_environment("x64", None, scratch)
            compiler_before = identity(compiler)
            exe = work / "observe.exe"
            argv = [
                str(compiler),
                "/nologo",
                "/std:c++20",
                "/MT",
                "/EHsc",
                "/utf-8",
                "/W4",
                "/WX",
                str(paths[1]),
                "/Fe:" + str(exe),
                "/Fo:" + str(work / "observe.obj"),
            ]
            state.update(state="compiling", compiler=compiler_before, compile_argv=argv)
            save()
            start = time.monotonic()
            result = subprocess.run(
                argv,
                cwd=work,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
            )
            state["compile"] = {
                "exit_code": result.returncode,
                "seconds": time.monotonic() - start,
                "stdout_b64": base64.b64encode(result.stdout).decode(),
                "stderr_b64": base64.b64encode(result.stderr).decode(),
            }
            save()
            if result.returncode:
                raise RuntimeError("Native observer compilation failed")
            binary = identity(exe)
            state.update(state="observing", binary=binary)
            save()
            start = time.monotonic()
            observed = subprocess.run(
                [str(exe), str(CHILD)],
                cwd=work,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=150,
            )
            state["observation"] = {
                "exit_code": observed.returncode,
                "seconds": time.monotonic() - start,
                "stdout_b64": base64.b64encode(observed.stdout).decode(),
                "stderr_b64": base64.b64encode(observed.stderr).decode(),
                "stdout_sha256": hashlib.sha256(observed.stdout).hexdigest(),
            }
            save()
            if identity(exe) != binary or identity(compiler) != compiler_before:
                raise RuntimeError("Executed observer or compiler changed")
            if [identity(p) for p in paths] != state["inputs"]:
                raise RuntimeError(
                    "Original fixture, observer source or installed runtime changed"
                )
            state["inputs_unchanged"] = True
            if observed.returncode:
                raise RuntimeError("Native original-child observation failed")
            lines = observed.stdout.decode("utf-8").splitlines()
            match = re.fullmatch(
                r"DONE installed=1 entered=(\d+) returned=(\d+) base-calls=(\d+) pending=0 exit=0",
                lines[-1],
            )
            if (
                not match
                or int(match[1]) != int(match[2])
                or not 1 <= int(match[3]) <= int(match[1]) <= 64
            ):
                raise RuntimeError(
                    "Incomplete original-child entry/return/natural-exit proof"
                )
            state["terminal"] = lines[-1]
        state.update(state="finished", exit_code=0, build_outputs_removed=True)
    except BaseException:
        state.update(state="failed", exit_code=1, error=traceback.format_exc())
    finally:
        save()
    if state["exit_code"]:
        raise RuntimeError(state["error"])
    print(
        json.dumps(
            {"output": str(OUTPUT), "kernel": kernel, "terminal": state["terminal"]}
        )
    )


if __name__ == "__main__":
    main()
