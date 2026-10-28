from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
import traceback

ROOT = Path("C:/Windows/Temp/assist-native-rax-20261010/src-display-candidate1")
OUT = ROOT / "target/native-process-execute-flags-set-observe-v1"
state = {"pid": os.getpid(), "state": "checking", "commands": []}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save():
    (OUT / "receipt.json").write_text(json.dumps(state, indent=2))


def run(argv, env, label):
    start = time.monotonic()
    with (OUT / (label + ".log")).open("wb") as log:
        child = subprocess.Popen(
            argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log
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
    frame = json.loads((OUT / "source-hashes.json").read_text())
    expected = {**frame["retained"], **frame["current"]}
    assert all(digest(ROOT / name) == value for name, value in expected.items())
    source = OUT / "observe.rs"
    driver_hash = digest(__file__)
    source_hash = digest(source)
    deps = ROOT / "target/normal-candidate1/debug/deps"
    library = deps / "librax-543b4263456c7c06.rlib"
    library_hash = digest(library)
    assert (
        library_hash
        == "d01389e7636fd85d0632832dbd913bf2fd780d01118b30c36350bc4b35f890d0"
    )
    fixture = (
        ROOT / "tests/fixtures/user/windows/native_exception_entry/bin/x86/fault.exe"
    )
    assert (
        digest(fixture)
        == "4a0f28a1fba11a97b7498f6bf5b231d32c124ce15d2bcb90084816e342c09544"
    )
    ntdll = Path("C:/Windows/SysWOW64/ntdll.dll")
    assert (
        digest(ntdll)
        == "830cfffd91b39ee07578b2fcf89d9b1b838d7e805a2180597521df90ea022a0e"
    )
    state.update(
        kernel=list(sys.getwindowsversion()),
        input_hashes=expected,
        source_sha256=source_hash,
        driver_sha256=driver_hash,
        rlib_sha256=library_hash,
    )
    save()
    helper = (
        ROOT / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
    )
    assert (
        digest(helper)
        == "391b84e6c0477abc27ca6d20c41a37078f2074fe34d4b2620a3ec8ec34df30ba"
    )
    spec = importlib.util.spec_from_file_location("profile", helper)
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    temporary = OUT / "tmp"
    temporary.mkdir()
    env, _ = profile.compiler_environment(
        "arm64",
        str(
            ROOT
            / "target/win32u-validation-recovery-v2/transfer/mutant-native-compiler-env-epoch4.json"
        ),
        temporary,
    )
    env.update(RUSTC_WRAPPER="", RUSTFLAGS="", CCACHE_DISABLE="1", SCCACHE_DISABLE="1")
    executable = OUT / "observe.exe"
    argv = [
        str(ROOT.parent / "toolchain/bin/rustc.exe"),
        "--edition=2024",
        "--crate-name=native_process_execute_flags_set_observe_v1",
        str(source),
        "--extern",
        f"rax={library}",
        "-L",
        f"dependency={deps}",
        "-C",
        "debuginfo=0",
        "-o",
        str(executable),
    ]
    for folder in (ROOT / "target/normal-candidate1/debug/build").glob("*/out"):
        if any(folder.glob("*.lib")) or any(folder.glob("*.a")):
            argv.extend(["-L", f"native={folder}"])
    run(argv, env, "compile")
    executable_hash = digest(executable)
    state.update(
        executable_sha256=executable_hash, executable_bytes=executable.stat().st_size
    )
    save()
    run([str(executable), str(fixture)], env, "observe")
    text = (OUT / "observe.log").read_text()
    assert "NtSetInformationProcess class 34" in text and "DEPSET_ARGS" in text, text
    assert digest(executable) == executable_hash
    assert digest(source) == source_hash and digest(__file__) == driver_hash
    assert digest(library) == library_hash
    assert all(digest(ROOT / name) == value for name, value in expected.items())
    state.update(state="finished", exit_code=0, inputs_unchanged=True)
except BaseException:
    state.update(state="failed", exit_code=1, error=traceback.format_exc())
finally:
    save()
raise SystemExit(state["exit_code"])
