#!/usr/bin/env python3
"""Verify fixed registry producers; capture and replay OLE or Processor0 controls."""
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
SUBJECT = "ole"
LABEL = "OLE"


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
    require(report["pointer_bytes"] == width, f"{LABEL} process pointer width")
    require(report["handles_before"] == report["handles_after"], f"{LABEL} native handle leak")
    if kind in ("absolute", "missing"):
        require(len(report["rows"]) == 136, f"{LABEL} absolute open case count")
    elif kind == "relative":
        require(len(report["rows"]) == 12, f"{LABEL} MACHINE-relative case count")
    else:
        require(len(report["roots"]) == 2 and
                {root["view"] for root in report["roots"]} == {1, 2} and
                all(root["hive"] == 0 for root in report["roots"]), f"{LABEL} fixed root selection")
        require(len(report["nodes"]) <= 1024 and len(report["states"]) <= 32768,
                f"{LABEL} native tree bounds")
        for root in report["roots"]:
            require((root["status"] == 0 and 0 <= root["node"] < len(report["nodes"])) or
                    (root["status"] in (2, 3) and root["node"] == -1), f"{LABEL} root status")
        for index, node in enumerate(report["nodes"]):
            if SUBJECT == "processor0":
                stamp = node.get("last_write_hex", "")
                require(len(stamp) == 16 and all(c in "0123456789abcdef" for c in stamp),
                        "Processor0 native FILETIME is not eight raw bytes")
            require(node["id"] == index and 0 <= node["state"] < len(report["states"]),
                    f"{LABEL} tree node identity")
            for opened in node["opens"]:
                for row in opened["rows"]:
                    require(0 <= row["source"] < len(report["states"]), f"{LABEL} source state")
                    require((row["status"] == 0 and 0 <= row["target"] < len(report["states"])) or
                            (row["status"] != 0 and row["target"] == -1), f"{LABEL} target state")


def verify_sources():
    corpus = json.loads((SOURCE / "controls-v1.json").read_text(encoding="utf-8"))
    expected = {SOURCE.name + "/" + kind + "-v1.c" for kind in KINDS}
    expected.update({SOURCE.name + "/CMakeLists.txt",
                     "native-command-processor/absolute-v1.c",
                     "native-command-processor/relative-v1.c"})
    require(corpus["schema"] == "rax-native-" + SUBJECT + "-registry-v1" and corpus["state"] == "complete",
            f"incomplete retained {LABEL} corpus")
    require(set(corpus["source_hashes"]) == expected, f"{LABEL} native producer set differs")
    for name, digest in corpus["source_hashes"].items():
        require(sha((SPECIFICATIONS / name).read_bytes().replace(b"\r\n", b"\n")) == digest,
                f"retained {LABEL} producer changed: " + name)
    require(len(corpus["reports"]) == 3 and
            {report["architecture"] for report in corpus["reports"]} == {"arm64", "x64", "x86"},
            f"retained {LABEL} process ABI coverage")
    for report in corpus["reports"]:
        for kind in KINDS:
            validate_report(kind, report[kind], 4 if report["architecture"] == "x86" else 8)
    return corpus["source_hashes"]


def main():
    global SOURCE, SUBJECT, LABEL
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--subject", choices=("ole", "processor0"), default="ole")
    parser.add_argument("--output")
    args = parser.parse_args()
    SUBJECT = args.subject
    LABEL = "OLE" if SUBJECT == "ole" else "Processor0"
    SOURCE = SPECIFICATIONS / ("native-" + SUBJECT + "-registry")
    hashes = verify_sources()
    if args.verify_corpus:
        print(json.dumps({"verified_inputs": len(hashes), "retained_process_abis": 3}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    output = (ROOT / (args.output or ("target/native-" + SUBJECT + "-registry-v1"))).resolve()
    require(output != ROOT and output.is_relative_to(ROOT) and not output.exists(),
            f"{LABEL} output must be new and inside the checkout")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-" + SUBJECT + "-registry-ci-v1\n", encoding="utf-8")
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
        require(len(paths) == len(KINDS), f"{LABEL} native target count")
        record = {"architecture": label, "images": {}, "raw_report_sha256": {}}
        for kind, name in zip(KINDS, paths):
            image = Path(name).resolve()
            require(image.is_relative_to(build.resolve()), f"{LABEL} native image leaves build")
            raw = image.read_bytes()
            require(raw[:2] == b"MZ", f"{LABEL} native DOS header")
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            require(raw[pe:pe + 4] == b"PE\0\0" and
                    struct.unpack_from("<H", raw, pe + 4)[0] == machine, f"{LABEL} native PE machine")
            result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=True)
            (output / (label + "-" + kind + ".json")).write_bytes(result.stdout)
            (output / (label + "-" + kind + ".stderr")).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            validate_report(kind, report, width)
            require(sha(image.read_bytes()) == sha(raw), f"{LABEL} native image changed")
            record[kind] = report
            record["raw_report_sha256"][kind] = sha(result.stdout)
            record["images"][kind] = {"machine": machine, "bytes": len(raw), "sha256": sha(raw)}
        reports.append(record)
        require(build.resolve().is_relative_to(output), f"{LABEL} native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((SPECIFICATIONS / name).read_bytes()) == value for name, value in raw_hashes.items()),
            f"{LABEL} native producer inputs changed")
    corpus = output / "observations.json"
    corpus.write_text(json.dumps({"state": "complete", "schema": "rax-native-" + SUBJECT + "-registry-v1",
        "source_hashes": raw_hashes, "normalized_source_hashes": hashes,
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine()}, "reports": reports}, indent=2) + "\n", encoding="utf-8")
    env["RAX_OLE_REGISTRY_CORPUS" if SUBJECT == "ole" else "RAX_PROCESSOR0_REGISTRY_CORPUS"] = str(corpus)
    selections = [
        ("guest-replay", "ole_registry_replays_native_open_profiles", 1),
        ("pure-selection", "snapshot_root::ole_tests", 4),
        ("installed-selection", "command_processor::ole_tests", 1),
    ] if SUBJECT == "ole" else [
        ("guest-replay", "processor0_registry_replays_native_open_profiles", 1),
        ("pure-selection", "processor0::tests", 4),
        ("installed-selection", "command_processor::processor0_tests", 2),
    ]
    for name, selected, minimum in selections:
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
