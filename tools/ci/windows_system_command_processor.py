#!/usr/bin/env python3
"""Verify fixed System registry producers and replay fresh native Windows calls."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys


KINDS = ("system", "system-relative", "system-parent", "system-parent-relative",
         "system-parent-graph")
ROOT = Path(__file__).resolve().parents[2]
SPECIFICATIONS = ROOT / "docs/specifications/windows"
SOURCE = SPECIFICATIONS / "native-system-command-processor"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def legacy_helpers():
    # Explicit loading also works with the Windows embedded interpreter's -I.
    path = ROOT / "tools/ci/windows_command_processor.py"
    spec = importlib.util.spec_from_file_location("rax_cmd_control_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_report(kind, report, width, helpers):
    original = ("graph" if kind.endswith("graph") else
                "relative" if kind.endswith("relative") else "absolute")
    helpers.validate_report(original, report, width)
    if original == "graph":
        require(bool(report["hives"][0]["states"]),
                "present System Software parent is required for reopen qualification")


def verify_sources(helpers):
    helpers.verify_sources(SPECIFICATIONS / "native-command-processor")
    corpus = json.loads((SOURCE / "controls-system-v1.json").read_text(encoding="utf-8"))
    expected = {"native-system-command-processor/" + kind + "-v1.c" for kind in KINDS}
    expected.update({"native-system-command-processor/CMakeLists.txt",
                     "native-command-processor/absolute-v1.c",
                     "native-command-processor/relative-v1.c"})
    require(corpus["state"] == "complete" and corpus["schema"] == "rax-native-system-command-v1",
            "incomplete retained System campaign")
    require(set(corpus["source_hashes"]) == expected, "System producer set differs")
    for name, digest in corpus["source_hashes"].items():
        require(sha((SPECIFICATIONS / name).read_bytes().replace(b"\r\n", b"\n")) == digest,
                "retained System producer changed: " + name)
    require({record["architecture"] for record in corpus["reports"]} == {"arm64", "x64", "x86"}
            and len(corpus["reports"]) == 3, "retained System ABI coverage differs")
    for record in corpus["reports"]:
        width = 4 if record["architecture"] == "x86" else 8
        for kind in KINDS:
            validate_report(kind, record[kind], width, helpers)
    return corpus["source_hashes"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-system-command-processor-v1")
    args = parser.parse_args()
    helpers = legacy_helpers()
    normalized = verify_sources(helpers)
    if args.verify_corpus:
        print(json.dumps({"verified_inputs": len(normalized), "retained_process_abis": 3}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    output = (ROOT / args.output).resolve()
    require(output != ROOT and output.is_relative_to(ROOT), "output leaves checkout")
    require(not output.exists(), "output exists; preserve previous evidence")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-system-command-processor-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               SystemTemp=str(temporary), CCACHE_DISABLE="1", SCCACHE_DISABLE="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    target = (ROOT / env.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(ROOT), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    raw_hashes = {name: sha((SPECIFICATIONS / name).read_bytes()) for name in normalized}
    architectures = [("x64", "x64", 0x8664, 8), ("x86", "Win32", 0x14C, 4)]
    if platform.machine().lower() in ("arm64", "aarch64"):
        architectures.insert(0, ("arm64", "ARM64", 0xAA64, 8))
    reports = []
    for label, generator_arch, machine, width in architectures:
        build = output / ("build-" + label)
        helpers.run(["cmake", "-S", str(SOURCE), "-B", str(build), "-A", generator_arch],
                    ROOT, env, output / (label + "-configure.log"))
        helpers.run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
                    ROOT, env, output / (label + "-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == len(KINDS), "System native target count")
        record = {"architecture": label, "images": {}, "raw_report_sha256": {}}
        for kind, name in zip(KINDS, paths):
            image = Path(name).resolve()
            require(image.is_relative_to(build.resolve()), "native image leaves build")
            raw = image.read_bytes()
            require(raw[:2] == b"MZ", "native DOS header")
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            require(raw[pe:pe + 4] == b"PE\0\0" and
                    struct.unpack_from("<H", raw, pe + 4)[0] == machine, "native PE machine")
            result = subprocess.run([str(image)], cwd=build, env=env,
                                    stdin=subprocess.DEVNULL, capture_output=True, check=True)
            (output / (label + "-" + kind + ".json")).write_bytes(result.stdout)
            (output / (label + "-" + kind + ".stderr")).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            validate_report(kind, report, width, helpers)
            require(sha(image.read_bytes()) == sha(raw), "native image changed")
            record[kind] = report
            record["raw_report_sha256"][kind] = sha(result.stdout)
            record["images"][kind] = {"machine": machine, "bytes": len(raw), "sha256": sha(raw)}
        reports.append(record)
        require(build.resolve().is_relative_to(output), "native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((SPECIFICATIONS / name).read_bytes()) == digest
                for name, digest in raw_hashes.items()), "native producer inputs changed")
    corpus = output / "observations.json"
    corpus.write_text(json.dumps({"state": "complete", "schema": "rax-native-system-command-v1",
        "source_hashes": raw_hashes, "normalized_source_hashes": normalized,
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine()}, "reports": reports}, indent=2) + "\n",
        encoding="utf-8")
    env["RAX_SYSTEM_COMMAND_PROCESSOR_CORPUS"] = str(corpus)
    log = output / "system-replay.log"
    try:
        helpers.run(["cargo", "test", "--locked", "--no-default-features", "--lib",
                     "system_command", "--", "--test-threads=1", "--nocapture"], ROOT, env, log)
        helpers.require_tests(log, 7)
    finally:
        if log.exists():
            print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    shutil.rmtree(temporary)
    print(json.dumps({"corpus": str(corpus), "reports": len(reports),
                      "sha256": sha(corpus.read_bytes())}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
