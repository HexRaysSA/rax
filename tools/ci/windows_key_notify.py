#!/usr/bin/env python3
"""Verify native registry notification producers, capture controls, and replay them."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from windows_command_processor import require, require_tests, run, sha
from windows_key_enumeration import native_machine

KINDS = {"lifetime": 32, "admission": 184, "thread": 24, "flags": 208,
         "completion": 24, "completion_stores": 24}
SOURCES = ("CMakeLists.txt", "probe-lifetime-v1.c", "probe-admission-v2.c",
           "probe-thread-v3.c", "probe-flags-v4.c", "probe-completion-v5.c",
           "probe-completion-stores-v6.c")
CORPORA = (("controls-v1.json", 29695, 0xAA64, {"arm64", "x64", "x86"}),
           ("controls-amd64-20348-v1.json", 20348, 0x8664, {"x64", "x86"}),
           ("controls-amd64-26100-v1.json", 26100, 0x8664, {"x64", "x86"}))


def compact(report):
    data = {k: v for k, v in report.items()
            if k not in ("pointer_bytes", "handles_before", "handles_after")}
    identity = sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    return identity, data


def validate(report, kind, width):
    require(report["pointer_bytes"] == width, "native caller pointer width")
    require(report["handles_before"] == report["handles_after"], "native handle leak")
    require(len(report["rows"]) == KINDS[kind], "native case count: " + kind)


def verify_sources(source):
    expected = None
    for filename, build, machine, architectures in CORPORA:
        corpus = json.loads((source / filename).read_text(encoding="utf-8"))
        require(corpus["schema"] == "rax-native-key-notify-v1"
                and corpus["state"] == "complete", "native notification corpus schema")
        require(corpus["kernel"] == [10, 0, build] and corpus["native_machine"] == machine,
                "retained native kernel identity")
        if expected is None:
            expected = corpus["source_hashes"]
        require(corpus["source_hashes"] == expected, "native producer set differs by kernel")
        require({r["architecture"] for r in corpus["reports"]} == architectures
                and len(corpus["reports"]) == len(architectures), "retained native ABI set")
        for identity, data in corpus["datasets"].items():
            require(sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()) == identity,
                    "native notification dataset hash")
        for report in corpus["reports"]:
            require(set(report["datasets"]) == set(KINDS), "native notification report kinds")
            for kind in KINDS:
                before, after = report["handles"][kind]
                require(before == after, "retained native handle leak")
                data = corpus["datasets"][report["datasets"][kind]]
                require(len(data["rows"]) == KINDS[kind], "retained native matrix dimensions")
    require(set(expected) == set(SOURCES), "native notification producer input set")
    for name, digest in expected.items():
        require(sha((source / name).read_bytes().replace(b"\r\n", b"\n")) == digest,
                "native notification producer changed: " + name)
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify-corpus", action="store_true")
    mode.add_argument("--capture-only", action="store_true",
                      help="capture native controls without running guest replay")
    parser.add_argument("--output", default="target/native-key-notify-v1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "docs/specifications/windows/native-key-notify"
    expected = verify_sources(source)
    if args.verify_corpus:
        print(json.dumps({"verified_producers": len(expected), "retained_process_abis": 3,
                          "retained_kernel_profiles": len(CORPORA),
                          "retained_reports": sum(len(a) for _, _, _, a in CORPORA),
                          "observations": sum(KINDS.values()) *
                          sum(len(a) for _, _, _, a in CORPORA)}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    machine = native_machine()
    output = (root / args.output).resolve()
    require(output != root and output.is_relative_to(root), "output leaves checkout")
    require(not output.exists(), "preserve existing notification evidence")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-key-notify-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               SystemTemp=str(temporary), CCACHE_DISABLE="1", SCCACHE_DISABLE="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    target = (root / env.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(root), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    original = {name: sha((source / name).read_bytes()) for name in expected}
    architectures = [("x64", "x64", 0x8664, 8), ("x86", "Win32", 0x14C, 4)]
    if machine == 0xAA64:
        architectures.insert(0, ("arm64", "ARM64", 0xAA64, 8))
    version = sys.getwindowsversion()
    corpus = {"schema": "rax-native-key-notify-v1", "state": "complete",
              "kernel": [version.major, version.minor, version.build],
              "native_machine": machine, "source_hashes": expected,
              "raw_source_hashes": original, "datasets": {}, "reports": []}
    for label, generator_arch, pe_machine, width in architectures:
        build = output / ("build-" + label)
        run(["cmake", "-S", str(source), "-B", str(build), "-A", generator_arch],
            root, env, output / (label + "-configure.log"))
        run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
            root, env, output / (label + "-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == len(KINDS), "native notification target path count")
        record = {"architecture": label, "pointer_bytes": width, "datasets": {},
                  "handles": {}, "images": {}, "raw_report_sha256": {}}
        for kind, path in zip(KINDS, paths):
            image = Path(path).resolve()
            require(image.is_relative_to(build.resolve()), "native image leaves build")
            raw = image.read_bytes()
            require(raw[:2] == b"MZ", "native DOS header")
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            require(raw[pe:pe + 4] == b"PE\0\0"
                    and struct.unpack_from("<H", raw, pe + 4)[0] == pe_machine,
                    "native PE machine")
            result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=True, timeout=180)
            (output / (label + "-" + kind + ".json")).write_bytes(result.stdout)
            (output / (label + "-" + kind + ".stderr")).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            validate(report, kind, width)
            require(sha(image.read_bytes()) == sha(raw), "native image changed")
            identity, data = compact(report)
            corpus["datasets"].setdefault(identity, data)
            record["datasets"][kind] = identity
            record["handles"][kind] = [report["handles_before"], report["handles_after"]]
            record["images"][kind] = {"machine": pe_machine, "bytes": len(raw), "sha256": sha(raw)}
            record["raw_report_sha256"][kind] = sha(result.stdout)
        corpus["reports"].append(record)
        require(build.resolve().is_relative_to(output), "native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((source / name).read_bytes()) == digest for name, digest in original.items()),
            "native notification producer inputs changed")
    path = output / "observations.json"
    path.write_text(json.dumps(corpus, separators=(",", ":")) + "\n", encoding="utf-8")
    if args.capture_only:
        print(json.dumps({"native_process_abis": len(architectures),
                          "observations": sum(KINDS.values()) * len(architectures),
                          "guest_replay": "not_requested"}))
        return 0
    env["RAX_KEY_NOTIFY_CORPUS"] = str(path)
    log = output / "guest-replay.log"
    run(["cargo", "test", "--locked", "--no-default-features", "--lib",
         "registry_tests::key_notify::", "--", "--test-threads=1", "--nocapture"], root, env, log)
    require_tests(log, 10)
    print(json.dumps({"native_process_abis": len(architectures),
                      "observations": sum(KINDS.values()) * len(architectures)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
