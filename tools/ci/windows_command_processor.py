#!/usr/bin/env python3
"""Verify retained CMD producers, then capture and replay native Windows controls."""
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

KINDS = ("absolute", "relative", "family", "physical", "graph", "physical-relative")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_sources(source):
    corpus = json.loads((source / "controls-v1.json").read_text(encoding="utf-8"))
    expected = {kind + "-v1.c" for kind in KINDS} | {"CMakeLists.txt"}
    require(set(corpus["source_hashes"]) == expected, "retained producer set differs")
    for name, digest in corpus["source_hashes"].items():
        normalized = (source / name).read_bytes().replace(b"\r\n", b"\n")
        require(sha(normalized) == digest, "retained producer changed: " + name)
    require(len(corpus["reports"]) == 3, "retained process ABI count")
    amd64 = json.loads((source / "controls-amd64-v1.json").read_text(encoding="utf-8"))
    require(amd64["normalized_source_hashes"] == corpus["source_hashes"],
            "AMD64 producer identity differs")
    return corpus["source_hashes"]


def verify_tree_sources(root):
    source = root / "docs/specifications/windows"
    corpus = json.loads((source / "native-command-processor-tree/controls-v1.json")
                        .read_text(encoding="utf-8"))
    require(set(corpus["source_hashes"]) == {
        "native-command-processor-tree/tree-v1.c",
        "native-command-processor-tree/CMakeLists.txt",
        "native-command-processor/absolute-v1.c"}, "tree producer input set differs")
    for name, digest in corpus["source_hashes"].items():
        require(sha((source / name).read_bytes().replace(b"\r\n", b"\n")) == digest,
                "retained tree producer changed: " + name)
    require(len(corpus["reports"]) == 3, "retained tree process ABI count")
    return corpus["source_hashes"]


def capture_trees(root, output, architectures, env, normalized):
    source = root / "docs/specifications/windows"
    raw_hashes = {name: sha((source / name).read_bytes()) for name in normalized}
    reports = []
    for label, generator_arch, machine, width in architectures:
        build = output / ("tree-build-" + label)
        run(["cmake", "-S", str(source / "native-command-processor-tree"),
             "-B", str(build), "-A", generator_arch], root, env,
            output / (label + "-tree-configure.log"))
        run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
            root, env, output / (label + "-tree-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == 1, "native tree target path count")
        image = Path(paths[0]).resolve()
        require(image.is_relative_to(build.resolve()), "native tree image leaves build")
        raw = image.read_bytes()
        require(raw[:2] == b"MZ", "native tree DOS header")
        pe = struct.unpack_from("<I", raw, 0x3C)[0]
        require(raw[pe:pe+4] == b"PE\0\0" and struct.unpack_from("<H", raw, pe+4)[0] == machine,
                "native tree PE machine")
        result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, check=True)
        (output / (label + "-tree.json")).write_bytes(result.stdout)
        (output / (label + "-tree.stderr")).write_bytes(result.stderr)
        report = json.loads(result.stdout)
        require(report["pointer_bytes"] == width, "native tree pointer width")
        require(report["handles_before"] == report["handles_after"], "native tree handle leak")
        require(len(report["roots"]) == 4 and 0 < len(report["nodes"]) <= 1024
                and 0 < len(report["states"]) <= 32768, "native tree selection bounds")
        rows = 0
        for index, node in enumerate(report["nodes"]):
            require(node["id"] == index and 0 <= node["state"] < len(report["states"]),
                    "native tree node identity")
            for opened in node["opens"]:
                for row in opened["rows"]:
                    rows += 1
                    require(0 <= row["source"] < len(report["states"]), "native tree row source")
                    require((row["status"] == 0 and 0 <= row["target"] < len(report["states"]))
                            or (row["status"] != 0 and row["target"] == -1), "native tree target")
        require(rows > 0, "empty native tree controls")
        require(sha(image.read_bytes()) == sha(raw), "native tree image changed")
        report.update(architecture=label, image={"machine": machine, "bytes": len(raw),
                      "sha256": sha(raw), "report_sha256": sha(result.stdout)})
        reports.append(report)
        require(build.resolve().is_relative_to(output), "native tree cleanup containment")
        shutil.rmtree(build)
    require(all(sha((source / name).read_bytes()) == value for name, value in raw_hashes.items()),
            "native tree producer inputs changed")
    corpus = output / "tree-observations.json"
    corpus.write_text(json.dumps({"state": "complete", "schema": "rax-native-command-tree-v1",
        "source_hashes": raw_hashes, "normalized_source_hashes": normalized,
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine()}, "reports": reports}, indent=2) + "\n", encoding="utf-8")
    return corpus


def run(argv, root, env, log):
    print("+ " + subprocess.list2cmdline([str(item) for item in argv]), flush=True)
    with log.open("xb") as stream:
        subprocess.run(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                       stdout=stream, stderr=subprocess.STDOUT, check=True)


def require_tests(log, minimum):
    rows = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
                      log.read_text(encoding="utf-8", errors="replace"))
    require(bool(rows), "missing libtest summary: " + log.name)
    passed, failed, ignored = map(int, rows[-1])
    require(passed >= minimum and failed == ignored == 0,
            "incomplete native test selection: " + log.name)


def validate_report(kind, report, width):
    require(report["pointer_bytes"] == width, "native pointer width")
    require(report["handles_before"] == report["handles_after"], "native handle leak")
    if kind in ("absolute", "physical"):
        require(len(report["rows"]) == 136, "native absolute case count")
    elif kind in ("relative", "physical-relative"):
        require(len(report["rows"]) == 12, "native relative case count")
    else:
        require(len(report["hives"]) == 2, "native hive count")
        for hive in report["hives"]:
            if kind == "family":
                require(len(hive["native_relative"]) == 8 and len(hive["captures"]) == 4,
                        "native family case count")
                for row in hive["captures"]:
                    if row["open_status"] == 0:
                        require(len(row["self_opens"]) == 8, "native self-open case count")
                    else:
                        require(row["open_status"] in (2, 3) and row["handle_nonzero"] == 0,
                                "unexpected native leaf absence")
            else:
                require(len(hive["states"]) <= 16 and len(hive["edges"]) == len(hive["states"]) * 8,
                        "native self-open graph is not closed")
                for edge in hive["edges"]:
                    require(0 <= edge["source"] < len(hive["states"]), "native graph source")
                    require((edge["status"] == 0 and 0 <= edge["target"] < len(hive["states"]))
                            or (edge["status"] != 0 and edge["target"] == -1), "native graph target")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-command-processor-v1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "docs/specifications/windows/native-command-processor"
    normalized = verify_sources(source)
    tree_normalized = verify_tree_sources(root)
    if args.verify_corpus:
        print(json.dumps({"verified_producers": len(normalized),
                          "verified_tree_inputs": len(tree_normalized), "retained_process_abis": 3}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    output = (root / args.output).resolve()
    require(output != root and output.is_relative_to(root), "output leaves checkout")
    require(not output.exists(), "output exists; preserve previous evidence")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-command-processor-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               CCACHE_DISABLE="1", SCCACHE_DISABLE="1", RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    target = (root / env.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(root), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    raw_hashes = {name: sha((source / name).read_bytes()) for name in normalized}
    architectures = [("x64", "x64", 0x8664, 8), ("x86", "Win32", 0x14C, 4)]
    if platform.machine().lower() in ("arm64", "aarch64"):
        architectures.insert(0, ("arm64", "ARM64", 0xAA64, 8))
    reports = []
    for label, generator_arch, machine, width in architectures:
        build = output / ("build-" + label)
        run(["cmake", "-S", str(source), "-B", str(build), "-A", generator_arch],
            root, env, output / (label + "-configure.log"))
        run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
            root, env, output / (label + "-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == len(KINDS), "native target path count")
        record = {"architecture": label, "images": {}, "raw_report_sha256": {}}
        for kind, path in zip(KINDS, paths):
            image = Path(path).resolve()
            require(image.is_relative_to(build.resolve()), "native image leaves build")
            raw = image.read_bytes()
            require(raw[:2] == b"MZ", "native DOS header")
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            require(raw[pe:pe+4] == b"PE\0\0" and struct.unpack_from("<H", raw, pe+4)[0] == machine,
                    "native PE machine")
            result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=True)
            (output / (label + "-" + kind + ".json")).write_bytes(result.stdout)
            (output / (label + "-" + kind + ".stderr")).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            validate_report(kind, report, width)
            require(sha(image.read_bytes()) == sha(raw), "native image changed")
            record[kind] = report
            record["raw_report_sha256"][kind] = sha(result.stdout)
            record["images"][kind] = {"machine": machine, "bytes": len(raw), "sha256": sha(raw)}
        reports.append(record)
        require(build.resolve().is_relative_to(output), "native build cleanup containment")
        shutil.rmtree(build)
    require(all(sha((source / name).read_bytes()) == value for name, value in raw_hashes.items()),
            "native producer inputs changed")
    corpus = output / "observations.json"
    corpus.write_text(json.dumps({"state": "complete", "source_hashes": raw_hashes,
        "normalized_source_hashes": normalized, "host": {"system": platform.system(),
        "release": platform.release(), "machine": platform.machine()}, "reports": reports}, indent=2)
        + "\n", encoding="utf-8")
    env["RAX_COMMAND_PROCESSOR_CORPUS"] = str(corpus)
    env["RAX_COMMAND_TREE_CORPUS"] = str(
        capture_trees(root, output, architectures, env, tree_normalized))
    try:
        for name, selection, minimum in [
            ("guest-replay", "services_tests::registry_tests::command_processor::", 4),
            ("native-acquisition", "registry::installed::command_processor::tests::", 3),
        ]:
            log = output / (name + ".log")
            run(["cargo", "test", "--locked", "--no-default-features", "--lib", selection,
                 "--", "--test-threads=1", "--nocapture"], root, env, log)
            require_tests(log, minimum)
    finally:
        for name in ("guest-replay", "native-acquisition"):
            log = output / (name + ".log")
            if log.exists():
                print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    shutil.rmtree(temporary)
    print(json.dumps({"corpus": str(corpus), "reports": len(reports), "sha256": sha(corpus.read_bytes())}),
          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
