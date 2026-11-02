#!/usr/bin/env python3
"""Capture fixed MACHINE controls, then replay them through guest NT dispatch.

The native programs only open/query/close the fixed root and two fixed paths.
Builds, compiler temporaries and reports stay inside the selected checkout.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def run(arguments, root, environment, log):
    print("+ " + subprocess.list2cmdline([str(item) for item in arguments]), flush=True)
    with log.open("xb") as stream:
        subprocess.run(
            arguments,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=True,
        )


def require_tests(log, minimum):
    summaries = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
        log.read_text(encoding="utf-8", errors="replace"),
    )
    require(bool(summaries), "missing successful libtest summary: " + log.name)
    passed, failed, ignored = map(int, summaries[-1])
    require(passed >= minimum and failed == ignored == 0, "incomplete native selection: " + log.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="target/native-machine-hive-v1")
    options = parser.parse_args()
    require(sys.platform == "win32", "native Windows is required")

    root = Path(__file__).resolve().parents[2]
    output = (root / options.output).resolve()
    require(output.is_relative_to(root) and output != root, "output leaves checkout")
    require(not output.exists(), "output already exists; preserve the previous evidence")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-machine-hive-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    environment = os.environ.copy()
    environment.update(
        TMPDIR=str(temporary),
        TMP=str(temporary),
        TEMP=str(temporary),
        CCACHE_DISABLE="1",
        SCCACHE_DISABLE="1",
        RUSTC_WRAPPER="",
        RUSTC_WORKSPACE_WRAPPER="",
    )
    target = (root / environment.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(root), "Cargo target leaves checkout")
    environment["CARGO_TARGET_DIR"] = str(target)

    source = root / "docs/specifications/windows/native-machine-hive"
    inputs = {name: digest(source / name) for name in ("probe-v1.c", "probe-relative-v1.c", "CMakeLists.txt")}
    reports = []
    architectures = [("x64", "x64", 0x8664, 8), ("x86", "Win32", 0x14C, 4)]
    if platform.machine().lower() in ("arm64", "aarch64"):
        architectures.insert(0, ("arm64", "ARM64", 0xAA64, 8))
    for label, generator_arch, machine, width in architectures:
        build = output / ("build-" + label)
        run(["cmake", "-S", str(source), "-B", str(build), "-A", generator_arch],
            root, environment, output / (label + "-configure.log"))
        run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
            root, environment, output / (label + "-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == 2, "expected exactly two generated native target paths")
        observed = {"architecture": label, "images": {}}
        for kind, executable in zip(("absolute", "relative"), paths):
            image = Path(executable).resolve()
            require(image.is_relative_to(build.resolve()), "executable leaves owned build")
            raw = image.read_bytes()
            require(raw[:2] == b"MZ", "native DOS header")
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            require(raw[pe:pe + 4] == b"PE\0\0", "native PE signature")
            require(struct.unpack_from("<H", raw, pe + 4)[0] == machine, "native PE machine")
            result = subprocess.run([str(image)], cwd=build, env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, check=True)
            report_path = output / (label + "-" + kind + ".json")
            report_path.write_bytes(result.stdout)
            (output / (label + "-" + kind + ".stderr")).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            require(report["pointer_bytes"] == width, "native pointer width")
            require(report["handles_before"] == report["handles_after"], "native handle leak")
            require(len(report["rows"]) == (136 if kind == "absolute" else 36), "native case count")
            require(digest(image) == hashlib.sha256(raw).hexdigest(), "native image changed")
            observed[kind] = report
            observed["images"][kind] = {"machine": machine, "bytes": len(raw),
                "sha256": digest(image), "report_sha256": digest(report_path)}
        reports.append(observed)
        # All compiler/native child commands have returned. This project has no
        # services; /nr:false prevents MSBuild node reuse across the cleanup.
        require(build.resolve().is_relative_to(output), "build cleanup containment")
        shutil.rmtree(build)

    require(all(digest(source / name) == value for name, value in inputs.items()), "producer inputs changed")
    corpus = output / "observations.json"
    corpus.write_text(json.dumps({"state": "complete", "source_hashes": inputs,
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "reports": reports}, indent=2) + "\n", encoding="utf-8")
    environment["RAX_MACHINE_HIVE_CORPUS"] = str(corpus)
    try:
        run(["cargo", "test", "--locked", "--no-default-features", "--lib",
            "services_tests::registry_tests::machine_hive::", "--", "--test-threads=1", "--nocapture"],
            root, environment, output / "guest-replay.log")
        require_tests(output / "guest-replay.log", 4)
        run(["cargo", "test", "--locked", "--no-default-features", "--lib",
            "registry::installed::machine_hive::tests::", "--", "--test-threads=1", "--nocapture"],
            root, environment, output / "native-acquisition.log")
        require_tests(output / "native-acquisition.log", 3)
    finally:
        for log in (output / "guest-replay.log", output / "native-acquisition.log"):
            if log.exists():
                print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    shutil.rmtree(temporary)
    print(json.dumps({"corpus": str(corpus), "reports": len(reports), "sha256": digest(corpus)}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
