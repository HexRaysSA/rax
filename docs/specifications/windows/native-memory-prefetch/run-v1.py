"""Observe native memory-prefetch validation and working-set effects."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler-env")
    parser.add_argument("--require-native-machine", type=lambda value: int(value, 0))
    parser.add_argument("--architectures", nargs="+", choices=["arm64", "x64", "x86"], default=["x64", "x86"])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process_machine, native_machine = wintypes.USHORT(), wintypes.USHORT()
    assert kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process_machine), ctypes.byref(native_machine))
    if args.require_native_machine is not None:
        assert native_machine.value == args.require_native_machine
        assert process_machine.value == 0, "native observer required"
    folder = Path(__file__).resolve().parent
    root = folder.parents[3].resolve()
    output = args.output.resolve()
    assert output.is_relative_to(root)
    output.mkdir()
    source = folder / "probe-v1.c"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location("profile", root / "docs/specifications/windows/native-exception-entry-profile/run-v2.py")
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    result = {"pid": os.getpid(), "build": os.sys.getwindowsversion().build, "source_sha256": digest,
              "native_machine": native_machine.value, "runner_process_machine": process_machine.value,
              "cases": [], "binaries": {}, "state": "running"}

    def save():
        (output / "receipt.json").write_text(json.dumps(result, indent=2))

    save()
    try:
        for arch in args.architectures:
            build = output / arch
            build.mkdir()
            env, compiler = profile.compiler_environment(arch, args.compiler_env, build)
            binary = build / "probe.exe"
            with (build / "build.log").open("wb") as log:
                subprocess.run([str(compiler), "/nologo", "/O1", "/MD", "psapi.lib", str(source), "/Fe:" + str(binary)],
                               cwd=build, env=env, stdout=log, stderr=log, check=True)
            binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
            result["binaries"][arch] = binary_hash
            for case in range(192):
                child = subprocess.run([str(binary), str(case)], cwd=build, env=env, capture_output=True, timeout=20)
                entry = {"arch": arch, "case": case, "exit_code": child.returncode,
                         "stdout": child.stdout.decode("utf-8", errors="replace"), "stderr": child.stderr.decode("utf-8", errors="replace")}
                if child.returncode == 0:
                    entry["observation"] = json.loads(entry["stdout"])
                    assert entry["observation"]["id"] == case
                result["cases"].append(entry)
                save()
                assert child.returncode == 0, entry
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash
        assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
        result["state"] = "finished"
    except BaseException:
        result.update(state="failed", error=traceback.format_exc())
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
