"""Retain fresh native class-37 controls without changing executed inputs."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import traceback


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--environment", required=True)
    args = parser.parse_args()
    root, out = args.root.resolve(), args.output.resolve()
    assert sys.platform == "win32" and sys.getwindowsversion().build == 29695
    assert out.parent == (root / "target").resolve()
    assert not (out / "receipt.json").exists()
    folder = root / "docs/specifications/windows/native-process-image-information"
    source = folder / "native-image-information-v7.cpp"
    helper = (
        root / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
    )
    expected = json.loads((out / "expected-sources.json").read_text())
    before = {name: digest(root / name) for name in expected}
    assert before == expected
    before[str(Path(__file__).resolve())] = digest(Path(__file__))
    state = {
        "pid": os.getpid(),
        "created_epoch_seconds": time.time(),
        "kernel": list(sys.getwindowsversion()),
        "state": "checking",
        "sources_sha256": before,
        "commands": [],
        "records": [],
    }

    def save():
        (out / "receipt.json").write_text(json.dumps(state, indent=2) + "\n")

    def run(argv, env, build, label, deadline):
        started = time.monotonic()
        with (out / (label + ".log")).open("wb") as log:
            child = subprocess.Popen(
                argv,
                cwd=build,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
            )
            state.update(state=label, child_pid=child.pid)
            save()
            code = child.wait(timeout=deadline)
        state["commands"].append(
            {
                "label": label,
                "argv": argv,
                "exit_code": code,
                "seconds": time.monotonic() - started,
            }
        )
        save()
        return code

    save()
    try:
        control = module("image_profile", folder / "run-v9.py")
        compiler_helper = module("compiler_profile", helper)
        for view in ("arm64", "x64", "x86", "x86-laa"):
            arch = "x86" if view == "x86-laa" else view
            build = out / view
            build.mkdir()
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = compiler_helper.compiler_environment(
                arch, args.environment, temporary
            )
            compiler = Path(compiler)
            compiler_hash = digest(compiler)
            original = build / "original.exe"
            argv = [
                str(compiler),
                "/nologo",
                "/std:c++20",
                "/Od",
                "/EHsc",
                "/W4",
                "/WX",
                "/MT",
                str(source),
                "/Fe:" + str(original),
                "/Fo:" + str(build / "probe.obj"),
                "/link",
                "/NXCOMPAT",
            ]
            if view == "x86-laa":
                argv.append("/LARGEADDRESSAWARE")
            assert run(argv, env, build, view + "-compile", 60) == 0
            binary = original.read_bytes()
            pe = struct.unpack_from("<I", binary, 0x3C)[0]
            assert (
                struct.unpack_from("<H", binary, pe + 4)[0]
                == {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch]
            )
            if view == "x86-laa":
                assert struct.unpack_from("<H", binary, pe + 22)[0] & 0x20
            original_hash = digest(original)
            for profile in control.PROFILES:
                candidate = build / (profile + ".exe")
                assert not candidate.exists()
                payload = control.patched(binary, profile)
                candidate.write_bytes(payload)
                candidate_hash = digest(candidate)
                preferred, fields = control.file_metadata(payload)
                metadata = profile != "default"
                identity = {
                    "arch": arch,
                    "profile": profile,
                    "metadata_only": metadata,
                    "pe_fields": fields,
                    "file_bytes": len(payload),
                    "source_sha256": digest(source),
                    "binary_sha256": candidate_hash,
                    "compiled_binary_sha256": original_hash,
                    "compiler_sha256": compiler_hash,
                }
                label = view + "-" + profile
                argv = [
                    str(candidate),
                    format(preferred, "x"),
                    *(["metadata"] if metadata else []),
                ]
                try:
                    code = run(argv, env, build, label, 30)
                except OSError as error:
                    if (
                        arch != "arm64"
                        or profile
                        not in (
                            "no-dynamic-base",
                            "no-relocations",
                            "dynamic-base-no-relocations",
                        )
                        or getattr(error, "winerror", None) != 193
                    ):
                        raise
                    record = {
                        "kind": "unavailable",
                        **identity,
                        "available": False,
                        "windows_error": 193,
                        "query_calls": 0,
                    }
                    control.validate_unavailable(record)
                else:
                    raw = (out / (label + ".log")).read_bytes()
                    assert len(raw) <= 1048576
                    rows = [json.loads(line) for line in raw.decode().splitlines()]
                    control.validate(rows, arch, metadata)
                    assert (
                        code == 0
                        and rows[1]["pe"] == fields
                        and rows[1]["file_bytes"] == len(payload)
                    )
                    assert (
                        rows[0]["build"] == 29695
                        and rows[0]["native_machine"] == 0xAA64
                    )
                    record = {
                        "kind": "observation",
                        **identity,
                        "exit_code": code,
                        "rows": rows,
                    }
                assert (
                    digest(candidate) == candidate_hash
                    and digest(original) == original_hash
                )
                assert digest(compiler) == compiler_hash
                assert all(
                    digest(root / name) == value for name, value in before.items()
                )
                record["view"] = view
                record["inputs_unchanged"] = True
                state["records"].append(record)
                save()
        state.update(state="finished", exit_code=0)
    except BaseException:
        state.update(state="failed", exit_code=1, error=traceback.format_exc())
    finally:
        save()


if __name__ == "__main__":
    main()
