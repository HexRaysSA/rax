#!/usr/bin/env python3
"""Capture paired fixed-key NtOpenKey/Ex controls with native Windows compilers."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import traceback


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--compiler-env", type=Path)
    parser.add_argument("--require-native-machine", type=lambda text: int(text, 0))
    args = parser.parse_args()
    root = (args.source_root or Path(__file__).resolve().parents[4]).resolve()
    assert Path(__file__).resolve().is_relative_to(root)
    out = (args.output or root / "target/native-open-key-ex-v1").resolve()
    assert out.is_relative_to(root) and out != root
    out.mkdir(parents=True, exist_ok=False)
    temporary = out / "tmp"
    temporary.mkdir()
    state = dict(state="running", exit_code=1, pid=os.getpid(), rows=[])

    def save():
        (out / "receipt.json").write_text(json.dumps(state, indent=2))

    try:
        import ctypes as c
        from ctypes import wintypes as w

        k = c.WinDLL("kernel32", use_last_error=True)
        k.GetCurrentProcess.restype = w.HANDLE
        k.IsWow64Process2.argtypes = [
            w.HANDLE,
            c.POINTER(w.USHORT),
            c.POINTER(w.USHORT),
        ]
        k.IsWow64Process2.restype = w.BOOL
        pm, nm = w.USHORT(), w.USHORT()
        assert k.IsWow64Process2(k.GetCurrentProcess(), c.byref(pm), c.byref(nm))
        assert pm.value == 0 and nm.value in [0x8664, 0xAA64]
        if args.require_native_machine is not None:
            assert nm.value == args.require_native_machine
        helper = (
            root
            / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
        )
        assert (
            digest(helper)
            == "391b84e6c0477abc27ca6d20c41a37078f2074fe34d4b2620a3ec8ec34df30ba"
        )
        spec = importlib.util.spec_from_file_location("native_compiler", helper)
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        state.update(
            source_sha256=digest(__file__),
            python_sha256=digest(sys.executable),
            native_machine=nm.value,
            process_machine=pm.value,
            kernel=list(sys.getwindowsversion()),
            compiler_adapter_sha256=digest(helper),
        )
        labels = [("x64", "x64"), ("x86", "x86"), ("x86-laa", "x86")]
        if nm.value == 0xAA64:
            labels.insert(0, ("arm64", "arm64"))
        for label, arch in labels:
            work = out / label
            work.mkdir()
            env, compiler = adapter.compiler_environment(
                arch, args.compiler_env, temporary
            )
            row = dict(label=label, compiler_sha256=digest(compiler), probes={})
            state["rows"].append(row)
            for version in ["v2"]:
                source = Path(__file__).parent / ("probe-" + version + ".cpp")
                exe = work / ("probe-" + version + ".exe")
                command = [
                    str(compiler),
                    "/nologo",
                    "/std:c++17",
                    "/EHsc",
                    "/utf-8",
                    "/MT",
                    str(source),
                    "/Fo" + str(work / ("probe-" + version + ".obj")),
                    "/Fd" + str(work / ("compile-" + version + ".pdb")),
                    "/Fe" + str(exe),
                    "/link",
                    "/PDB:" + str(work / ("link-" + version + ".pdb")),
                ]
                if arch == "x86":
                    command.append(
                        "/LARGEADDRESSAWARE"
                        if label == "x86-laa"
                        else "/LARGEADDRESSAWARE:NO"
                    )
                result = dict(source_sha256=digest(source), command=command)
                row["probes"][version] = result
                save()
                build = subprocess.run(
                    command, capture_output=True, env=env, cwd=work, timeout=120
                )
                (work / ("build-" + version + ".log")).write_bytes(
                    build.stdout + build.stderr
                )
                result["build_returncode"] = build.returncode
                save()
                assert build.returncode == 0
                raw = exe.read_bytes()
                header = struct.unpack_from("<I", raw, 0x3C)[0]
                assert raw[header : header + 4] == b"PE\0\0"
                machine, sections = struct.unpack_from("<HH", raw, header + 4)
                characteristics = struct.unpack_from("<H", raw, header + 22)[0]
                magic = struct.unpack_from("<H", raw, header + 24)[0]
                assert machine == {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch]
                assert magic == (0x10B if arch == "x86" else 0x20B)
                if arch == "x86":
                    assert bool(characteristics & 0x20) == (label == "x86-laa")
                result["pe_identity"] = dict(
                    machine=machine,
                    optional_magic=magic,
                    characteristics=characteristics,
                    sections=sections,
                )
                result["exe_before_sha256"] = digest(exe)
                save()
                run = subprocess.run(
                    [str(exe)], capture_output=True, env=env, cwd=work, timeout=60
                )
                (work / ("stdout-" + version + ".jsonl")).write_bytes(run.stdout)
                (work / ("stderr-" + version + ".log")).write_bytes(run.stderr)
                result.update(
                    run_returncode=run.returncode,
                    exe_after_sha256=digest(exe),
                    source_after_sha256=digest(source),
                    stdout_sha256=hashlib.sha256(run.stdout).hexdigest(),
                    stderr_sha256=hashlib.sha256(run.stderr).hexdigest(),
                    text=run.stdout.decode("utf-8"),
                )
                save()
                assert run.returncode == 0 and not run.stderr
                assert result["exe_before_sha256"] == result["exe_after_sha256"]
                assert result["source_sha256"] == result["source_after_sha256"]
                rows = [json.loads(line) for line in result["text"].splitlines()]
                expected_machine = 0x14C if arch == "x86" else 0
                assert (
                    rows[0]["native_machine"] == nm.value
                    and rows[0]["process_machine"] == expected_machine
                )
                assert rows[0]["pointer_bytes"] == (4 if arch == "x86" else 8)
                assert all(item.get("exception", 0) == 0 for item in rows)
        state.update(state="finished", exit_code=0)
    except BaseException:
        state.update(state="failed", error=traceback.format_exc())
    finally:
        save()
    return state["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
