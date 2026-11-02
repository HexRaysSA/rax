#!/usr/bin/env python3
"""Verify OLE producers; capture and replay fixed native registry controls."""
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

ROOT = Path(__file__).resolve().parents[2]
SPECIFICATIONS = ROOT / "docs/specifications/windows"
SOURCE = SPECIFICATIONS / "native-ole-registry"
KINDS = ("absolute", "missing", "relative", "tree")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def helpers():
    spec = importlib.util.spec_from_file_location(
        "rax_native_registry_helpers", ROOT / "tools/ci/windows_command_processor.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_report(kind, report, width):
    require(report["pointer_bytes"] == width, "OLE process pointer width")
    require(report["handles_before"] == report["handles_after"], "OLE native handle leak")
    if kind in ("absolute", "missing"):
        require(len(report["rows"]) == 136, "OLE absolute open case count")
    elif kind == "relative":
        require(len(report["rows"]) == 12, "OLE MACHINE-relative case count")
    else:
        require(len(report["roots"]) == 2 and
                {root["view"] for root in report["roots"]} == {1, 2} and
                all(root["hive"] == 0 for root in report["roots"]), "OLE fixed root selection")
        require(len(report["nodes"]) <= 1024 and len(report["states"]) <= 32768,
                "OLE native tree bounds")
        for root in report["roots"]:
            require((root["status"] == 0 and 0 <= root["node"] < len(report["nodes"])) or
                    (root["status"] in (2, 3) and root["node"] == -1), "OLE root status")
        for index, node in enumerate(report["nodes"]):
            require(node["id"] == index and 0 <= node["state"] < len(report["states"]),
                    "OLE tree node identity")
            for opened in node["opens"]:
                for row in opened["rows"]:
                    require(0 <= row["source"] < len(report["states"]), "OLE source state")
                    require((row["status"] == 0 and 0 <= row["target"] < len(report["states"])) or
                            (row["status"] != 0 and row["target"] == -1), "OLE target state")


def verify_sources():
    corpus = json.loads((SOURCE / "controls-v1.json").read_text(encoding="utf-8"))
    expected = {"native-ole-registry/" + kind + "-v1.c" for kind in KINDS}
    expected.update({"native-ole-registry/CMakeLists.txt",
                     "native-command-processor/absolute-v1.c",
                     "native-command-processor/relative-v1.c"})
    require(corpus["schema"] == "rax-native-ole-registry-v1" and corpus["state"] == "complete",
            "incomplete retained OLE corpus")
    require(set(corpus["source_hashes"]) == expected, "OLE native producer set differs")
    for name, digest in corpus["source_hashes"].items():
        require(sha((SPECIFICATIONS / name).read_bytes().replace(b"\r\n", b"\n")) == digest,
                "retained OLE producer changed: " + name)
    require(len(corpus["reports"]) == 3 and
            {report["architecture"] for report in corpus["reports"]} == {"arm64", "x64", "x86"},
            "retained OLE process ABI coverage")
    for report in corpus["reports"]:
        for kind in KINDS:
            validate_report(kind, report[kind], 4 if report["architecture"] == "x86" else 8)
    return corpus["source_hashes"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-ole-registry-v1")
    args = parser.parse_args()
    hashes = verify_sources()
    if args.verify_corpus:
        print(json.dumps({"verified_inputs": len(hashes), "retained_process_abis": 3}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    output = (ROOT / args.output).resolve()
    require(output != ROOT and output.is_relative_to(ROOT) and not output.exists(),
            "OLE output must be new and inside the checkout")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-ole-registry-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               SystemTemp=str(temporary), CCACHE_DISABLE="1", SCCACHE_DISABLE="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    target = (ROOT / env.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(ROOT), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    native = helpers()
    raw_hashes = {name: sha((SPECIFICATIONS / name).read_bytes()) for name in hashes}
    architectures = [("x64", "x64", 0x8664, 8), ("x86", "Win32", 0x14C, 4)]
    if platform.machine().lower() in ("arm64", "aarch64"):
        architectures.insert(0, ("arm64", "ARM64", 0xAA64, 8))
    reports = []
    for label, generator_arch, machine, width in architectures:
        build = output / ("build-" + label)
        native.run(["cmake", "-S", str(SOURCE), "-B", str(build), "-A", generator_arch],
                   ROOT, env, output / (label + "-configure.log"))
        native.run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
                   ROOT, env, output / (label + "-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == len(KINDS), "OLE native target count")
        record = {"architecture": label, "images": {}, "raw_report_sha256": {}}
        for kind, name in zip(KINDS, paths):
            image = Path(name).resolve()
            require(image.is_relative_to(build.resolve()), "OLE native image leaves build")
            raw = image.read_bytes()
            require(raw[:2] == b"MZ", "OLE native DOS header")
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            require(raw[pe:pe + 4] == b"PE\0\0" and
                    struct.unpack_from("<H", raw, pe + 4)[0] == machine, "OLE native PE machine")
            result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=True)
            (output / (label + "-" + kind + ".json")).write_bytes(result.stdout)
            (output / (label + "-" + kind + ".stderr")).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            validate_report(kind, report, width)
            require(sha(image.read_bytes()) == sha(raw), "OLE native image changed")
            record[kind] = report
            record["raw_report_sha256"][kind] = sha(result.stdout)
            record["images"][kind] = {"machine": machine, "bytes": len(raw), "sha256": sha(raw)}
        reports.append(record)
        require(build.resolve().is_relative_to(output), "OLE native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((SPECIFICATIONS / name).read_bytes()) == value for name, value in raw_hashes.items()),
            "OLE native producer inputs changed")
    corpus = output / "observations.json"
    corpus.write_text(json.dumps({"state": "complete", "schema": "rax-native-ole-registry-v1",
        "source_hashes": raw_hashes, "normalized_source_hashes": hashes,
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine()}, "reports": reports}, indent=2) + "\n", encoding="utf-8")
    env["RAX_OLE_REGISTRY_CORPUS"] = str(corpus)
    for name, selected, minimum in [
        ("guest-replay", "ole_registry_replays_native_open_profiles", 1),
        ("pure-selection", "snapshot_root::ole_tests", 4),
        ("installed-selection", "command_processor::ole_tests", 1),
    ]:
        log = output / (name + ".log")
        try:
            native.run(["cargo", "test", "--locked", "--no-default-features", "--lib", selected,
                        "--", "--test-threads=1", "--nocapture"], ROOT, env, log)
            native.require_tests(log, minimum)
        finally:
            if log.exists():
                print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    shutil.rmtree(temporary)
    print(json.dumps({"corpus": str(corpus), "reports": len(reports), "sha256": sha(corpus.read_bytes())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
