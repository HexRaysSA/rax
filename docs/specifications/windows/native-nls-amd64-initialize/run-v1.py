"""Observe frozen initialization/protection probes on independent AMD64 kernels."""

from pathlib import Path
import base64
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
OUTPUT = ROOT / "target/native-nls-amd64-initialize-v1.json"
FROZEN = {
    "docs/specifications/windows/native-nls-build-29695/native-nls-initialize-v2.cpp": "c003afe72d55ccfbf4367694fe4c516cdd82f7e3925f7bf9cab560b63f1b4e70",
    "docs/specifications/windows/native-nls-build-29695/native-nls-initialize-protection-v2.cpp": "43fd1aa406e456c3e28ecb60d3194de39a77dee6f9cc96ef1a09ca347666256a",
    "docs/specifications/windows/native-exception-entry-profile/run-v2.py": "391b84e6c0477abc27ca6d20c41a37078f2074fe34d4b2620a3ec8ec34df30ba",
}


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def identity(path):
    path = Path(path)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def observe():
    if sys.platform != "win32" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("Independent native AMD64 Windows kernel required")
    kernel = list(sys.getwindowsversion())
    if tuple(kernel[:2]) != (10, 0) or kernel[2] not in (20348, 26100):
        raise RuntimeError(f"Unmeasured AMD64 kernel: {kernel}")
    target = ROOT / "target"
    target.mkdir(exist_ok=True)
    if not target.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("Target resolves outside this source worktree")
    record = {
        "schema": "native-nls-amd64-initialize-v1",
        "pid": os.getpid(),
        "kernel": kernel,
        "machine": platform.machine(),
        "state": "started",
        "samples": [],
    }
    # A second producer must not overwrite an active or completed observation.
    with OUTPUT.open("x", encoding="utf-8") as out:
        json.dump(record, out, indent=2)

    def save():
        OUTPUT.write_text(json.dumps(record, indent=2), encoding="utf-8")

    try:
        for name, expected in FROZEN.items():
            if digest(ROOT / name) != expected:
                raise RuntimeError(f"Frozen observation input changed: {name}")
        inputs = [ROOT / name for name in FROZEN] + [Path(__file__).resolve()]
        record["inputs"] = [identity(path) for path in inputs]
        windows = Path(os.environ["SystemRoot"])
        runtime = [
            windows / "System32/ntdll.dll",
            windows / "SysWOW64/ntdll.dll",
            windows / "System32/locale.nls",
            Path(sys.executable),
        ]
        record["runtime"] = [identity(path) for path in runtime]
        save()
        helper_path = (
            ROOT
            / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
        )
        spec = importlib.util.spec_from_file_location("native_profile", helper_path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        sources = {
            "initialize": ROOT
            / "docs/specifications/windows/native-nls-build-29695/native-nls-initialize-v2.cpp",
            "protect": ROOT
            / "docs/specifications/windows/native-nls-build-29695/native-nls-initialize-protection-v2.cpp",
        }
        with tempfile.TemporaryDirectory(
            prefix="native-nls-amd64-initialize-v1-", dir=target
        ) as temporary:
            work = Path(temporary)
            if not work.resolve().is_relative_to(ROOT.resolve()):
                raise RuntimeError("Temporary directory escaped source worktree")
            for arch in ("x64", "x86", "x86-laa"):
                machine = "x86" if arch == "x86-laa" else arch
                for kind, source in sources.items():
                    label = arch + "-" + kind
                    build = work / label
                    build.mkdir()
                    scratch = build / "tmp"
                    scratch.mkdir()
                    env, compiler = helper.compiler_environment(machine, None, scratch)
                    compiler_before = identity(compiler)
                    exe = build / (label + ".exe")
                    argv = [
                        str(compiler),
                        "/nologo",
                        "/std:c++20",
                        "/MT",
                        "/EHsc",
                        "/utf-8",
                        "/W4",
                        "/WX",
                        str(source),
                        "psapi.lib",
                        "/Fe:" + str(exe),
                        "/Fo:" + str(build / "probe.obj"),
                    ]
                    if arch == "x86-laa":
                        argv += ["/link", "/LARGEADDRESSAWARE"]
                    row = {
                        "arch": arch,
                        "kind": kind,
                        "source": identity(source),
                        "compiler": compiler_before,
                        "compile_argv": argv,
                    }
                    record["state"] = label + "-compile"
                    record["samples"].append(row)
                    save()
                    start = time.monotonic()
                    compiled = subprocess.run(
                        argv,
                        cwd=build,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=120,
                    )
                    row["compile"] = {
                        "exit_code": compiled.returncode,
                        "seconds": time.monotonic() - start,
                        "stdout_b64": base64.b64encode(compiled.stdout).decode(),
                        "stderr_b64": base64.b64encode(compiled.stderr).decode(),
                    }
                    save()
                    if compiled.returncode:
                        raise RuntimeError(f"Native probe compile failed: {label}")
                    binary_before = identity(exe)
                    row["binary"] = binary_before
                    record["state"] = label + "-observe"
                    save()
                    start = time.monotonic()
                    observed = subprocess.run(
                        [str(exe)],
                        cwd=build,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=90,
                    )
                    row["observation"] = {
                        "exit_code": observed.returncode,
                        "seconds": time.monotonic() - start,
                        "stdout_b64": base64.b64encode(observed.stdout).decode(),
                        "stderr_b64": base64.b64encode(observed.stderr).decode(),
                        "stdout_sha256": hashlib.sha256(observed.stdout).hexdigest(),
                    }
                    if (
                        identity(exe) != binary_before
                        or identity(compiler) != compiler_before
                    ):
                        raise RuntimeError(
                            "Executed PE or compiler changed during observation"
                        )
                    if [identity(path) for path in inputs] != record["inputs"]:
                        raise RuntimeError(
                            "Observation source changed during execution"
                        )
                    if [identity(path) for path in runtime] != record["runtime"]:
                        raise RuntimeError(
                            "Installed runtime changed during observation"
                        )
                    row["inputs_unchanged"] = True
                    save()
                    if observed.returncode:
                        raise RuntimeError(f"Native probe failed: {label}")
                    expected = (
                        b"complete cases=79 "
                        if kind == "initialize"
                        else b"complete cases=12 "
                    )
                    if (
                        not observed.stdout.splitlines()
                        or not observed.stdout.splitlines()[-1].startswith(expected)
                    ):
                        raise RuntimeError(f"Incomplete native report: {label}")
        record.update(state="finished", exit_code=0, build_outputs_removed=True)
    except BaseException:
        record.update(state="failed", exit_code=1, error=traceback.format_exc())
    finally:
        save()
    if record["exit_code"]:
        raise RuntimeError(record["error"])
    print(
        json.dumps(
            {"output": str(OUTPUT), "kernel": kernel, "samples": len(record["samples"])}
        )
    )


if __name__ == "__main__":
    observe()
