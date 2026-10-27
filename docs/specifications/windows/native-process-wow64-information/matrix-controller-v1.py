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
OUT = ROOT / "target/native-process-wow64-information-29695-v1"
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


save()
try:
    source = OUT / "probe.cpp"
    source_hash = digest(source)
    driver_hash = digest(__file__)
    state.update(
        kernel=list(sys.getwindowsversion()),
        source_sha256=source_hash,
        driver_sha256=driver_hash,
    )
    assert sys.getwindowsversion().build == 29695
    helper = (
        ROOT / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
    )
    assert (
        digest(helper)
        == "391b84e6c0477abc27ca6d20c41a37078f2074fe34d4b2620a3ec8ec34df30ba"
    )
    images = [
        Path("C:/Windows/System32/ntdll.dll"),
        Path("C:/Windows/SysWOW64/ntdll.dll"),
    ]
    before = {str(path): digest(path) for path in images}
    state["installed_ntdll_sha256"] = before
    save()
    spec = importlib.util.spec_from_file_location("profile", helper)
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    for arch, machine in [("arm64", 0xAA64), ("x64", 0x8664), ("x86", 0x14C)]:
        build = OUT / arch
        build.mkdir()
        tmp = build / "tmp"
        tmp.mkdir()
        env, compiler = profile.compiler_environment(
            arch,
            str(
                ROOT
                / "target/win32u-validation-recovery-v2/transfer/mutant-native-compiler-env-epoch4.json"
            ),
            tmp,
        )
        exe = build / ("process-wow64-" + arch + ".exe")
        args = [
            str(compiler),
            "/nologo",
            "/std:c++20",
            "/MT",
            "/EHsc",
            "/utf-8",
            "/W4",
            "/WX",
            str(source),
            "/Fe:" + str(exe),
            "/Fo:" + str(build / "probe.obj"),
        ]
        run(args, env, build, arch + "-compile")
        raw = exe.read_bytes()
        pe = struct.unpack_from("<I", raw, 0x3C)[0]
        assert (
            raw[pe : pe + 4] == b"PE\0\0"
            and struct.unpack_from("<H", raw, pe + 4)[0] == machine
        )
        binary_hash = digest(exe)
        run([str(exe), arch], env, build, arch + "-observe")
        text = (OUT / (arch + "-observe.log")).read_text()
        decoded = [json.loads(line) for line in text.splitlines()]
        rows = [row for row in decoded if row.get("kind") == "case"]
        assert len(rows) == (405 if arch == "x86" else 409)
        assert decoded[-1] == {"kind": "complete", "cases": len(rows)}
        assert decoded[0]["query_class"] == 26
        assert all(row["query_class"] == 26 for row in rows)
        assert (
            digest(exe) == binary_hash
            and digest(source) == source_hash
            and digest(__file__) == driver_hash
        )
        assert all(digest(Path(path)) == value for path, value in before.items())
        state["samples"].append(
            {
                "arch": arch,
                "machine": machine,
                "binary_bytes": len(raw),
                "binary_sha256": binary_hash,
                "compiler_sha256": digest(compiler),
                "rows": len(rows),
                "stdout_sha256": digest(OUT / (arch + "-observe.log")),
            }
        )
        save()
    state.update(state="finished", exit_code=0, inputs_unchanged=True)
except BaseException:
    state.update(state="failed", exit_code=1, error=traceback.format_exc())
finally:
    save()
raise SystemExit(state["exit_code"])
