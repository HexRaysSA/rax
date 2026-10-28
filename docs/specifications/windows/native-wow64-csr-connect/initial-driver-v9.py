from pathlib import Path
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import time
import traceback

ROOT = Path("C:/Windows/Temp/assist-native-rax-20261010/src-display-candidate1")
OUT = ROOT / "target/native-wow64-csr-initial-29695-v9"
state = {"pid": os.getpid(), "state": "checking", "commands": [], "samples": []}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save():
    (OUT / "receipt.json").write_text(json.dumps(state, indent=2))


def run(argv, env, cwd, label):
    start = time.monotonic()
    with (OUT / (label + ".log")).open("wb") as log:
        child = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log
        )
        state.update(state=label, child_pid=child.pid)
        save()
        code = child.wait()
    state["commands"].append(
        {"label": label, "exit_code": code, "seconds": time.monotonic() - start}
    )
    save()
    assert code == 0, label


def environment(profile, arch, temporary):
    temporary.mkdir()
    return profile.compiler_environment(
        arch,
        str(
            ROOT
            / "target/win32u-validation-recovery-v2/transfer/mutant-native-compiler-env-epoch4.json"
        ),
        temporary,
    )


save()
try:
    assert sys.getwindowsversion().build == 29695
    helper = (
        ROOT / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
    )
    assert (
        digest(helper)
        == "391b84e6c0477abc27ca6d20c41a37078f2074fe34d4b2620a3ec8ec34df30ba"
    )
    inputs = [
        OUT / "probe.cpp",
        OUT / "child.cpp",
        Path(__file__),
        Path("C:/Windows/System32/ntdll.dll"),
        Path("C:/Windows/SysWOW64/ntdll.dll"),
    ]
    before = {str(path): digest(path) for path in inputs}
    state.update(kernel=list(sys.getwindowsversion()), inputs_sha256=before)
    save()
    spec = importlib.util.spec_from_file_location("profile", helper)
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    build = OUT / "build"
    build.mkdir()
    child_env, child_compiler = environment(profile, "x86", build / "tmp-x86")
    child_exe = build / "controlled-child.exe"
    child_args = [
        str(child_compiler),
        "/nologo",
        "/std:c++20",
        "/GS-",
        "/Zl",
        "/W4",
        "/WX",
        str(OUT / "child.cpp"),
        "/Fe:" + str(child_exe),
        "/Fo:" + str(build / "child.obj"),
        "/link",
        "/ENTRY:entry",
        "/SUBSYSTEM:CONSOLE",
        "/NODEFAULTLIB",
        "kernel32.lib",
    ]
    run(child_args, child_env, build, "child-compile")
    env, compiler = environment(profile, "arm64", build / "tmp-arm64")
    exe = build / "initial-control.exe"
    args = [
        str(compiler),
        "/nologo",
        "/std:c++20",
        "/MT",
        "/EHsc",
        "/utf-8",
        "/W4",
        "/WX",
        str(OUT / "probe.cpp"),
        "/Fe:" + str(exe),
        "/Fo:" + str(build / "parent.obj"),
    ]
    run(args, env, build, "parent-compile")
    binary_hashes = {str(path): digest(path) for path in [exe, child_exe]}
    for path, expected in [(exe, 0xAA64), (child_exe, 0x14C)]:
        raw = path.read_bytes()
        offset = struct.unpack_from("<I", raw, 0x3C)[0]
        assert (
            raw[offset : offset + 4] == b"PE\0\0"
            and struct.unpack_from("<H", raw, offset + 4)[0] == expected
        )
    state.update(
        binary_sha256=binary_hashes,
        compiler_sha256={"arm64": digest(compiler), "x86": digest(child_compiler)},
    )
    save()
    modes = [
        "lower-root",
        "upper-root",
        "trailing-root",
        "root-only",
        "retry-guard-inside-null-buffer",
    ]
    for mode in modes:
        run([str(exe), str(child_exe), mode], env, build, mode)
        text = (OUT / (mode + ".log")).read_text()
        assert (
            "entered=2 returned=2"
            if mode.startswith("retry-")
            else "entered=1 returned=1"
        ) in text.splitlines()[-1] and "exit=70" in text.splitlines()[-1]
        state["samples"].append(
            {
                "mode": mode,
                "stdout_sha256": digest(OUT / (mode + ".log")),
                "terminal": text.splitlines()[-1],
            }
        )
        save()
        assert all(digest(Path(path)) == value for path, value in before.items())
        assert all(digest(Path(path)) == value for path, value in binary_hashes.items())
    state.update(state="finished", exit_code=0, inputs_unchanged=True)
except BaseException:
    state.update(state="failed", exit_code=1, error=traceback.format_exc())
finally:
    save()
raise SystemExit(state["exit_code"])
