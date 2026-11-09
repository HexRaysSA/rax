#!/usr/bin/env python3
"""Verify, acquire and replay independent native instruction-cache controls."""
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
SOURCE = SPECIFICATIONS / "native-instruction-cache"
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def normalize(report, architecture, raw_hash):
    width = 4 if architecture == "x86" else 8
    require(report["schema"] == "rax-native-instruction-cache-v1", "native schema")
    require(report["pointer_bytes"] == width, "native pointer width")
    require(report["handles_before"] == report["handles_after"], "native handle leak")
    require(len(report["handles"]) == (31 if width == 4 else 32), "native handle matrix")
    require(len(report["lengths_hex"]) == 15, "native length matrix")
    require(len(report["rows"]) == report["rows_count"], "native row count")
    require(all(h["query_status"] == 0 for h in report["handles"]), "native grant query")
    require(all(h["query_bytes"] in (0, 56) for h in report["handles"]), "native basic record")
    palette, matrix, at = [], [], 0
    for handle in range(len(report["handles"])):
        codes = ""
        for kind in range(24):
            for length in range(15):
                nt, win = report["rows"][at:at + 2]
                at += 2
                require(nt[:4] == [handle, kind, length, 0] and
                        win[:4] == [handle, kind, length, 1], "native case order")
                pair = nt[4:] + win[4:]
                require(len(pair) == 8 and all(0 <= n <= 0xffffffff for n in pair),
                        "native scalar widths")
                require(pair[3] <= 7 and pair[7] <= 7, "native guard mask")
                if pair not in palette:
                    palette.append(pair)
                require(len(palette) <= len(ALPHABET), "native result palette overflow")
                codes += ALPHABET[palette.index(pair)]
        matrix.append(codes)
    require(at == len(report["rows"]), "unconsumed native cases")
    return {"architecture": architecture, "pointer_bytes": width,
            "entry_hex": report["entry_hex"], "handles": report["handles"],
            "lengths_hex": report["lengths_hex"], "address_kinds": 24,
            "palette": palette, "matrix_rows": matrix, "native_calls": at,
            "raw_report_sha256": raw_hash}


def verify_sources():
    corpus = json.loads((SOURCE / "observations-v1.json").read_text(encoding="utf-8"))
    require(corpus["schema"] == "rax-native-instruction-cache-v1" and
            corpus["state"] == "complete", "incomplete retained corpus")
    expected = {"native-instruction-cache/native-oracle-v1.c",
                "native-instruction-cache/CMakeLists.txt"}
    require(set(corpus["source_hashes"]) == expected, "producer source set")
    for name, digest in corpus["source_hashes"].items():
        require(sha((SPECIFICATIONS / name).read_bytes().replace(b"\r\n", b"\n")) == digest,
                "retained producer changed: " + name)
    profiles = corpus["profiles"]
    require([p["architecture"] for p in profiles] == ["arm64", "x64", "x86"],
            "retained caller ABI coverage")
    for profile in profiles:
        require(len(profile["handles"]) == len(profile["matrix_rows"]), "retained handle rows")
        require(profile["address_kinds"] == 24 and len(profile["lengths_hex"]) == 15,
                "retained input matrix")
        require(0 < len(profile["palette"]) <= 64, "retained result palette")
        for codes in profile["matrix_rows"]:
            require(len(codes) == 360 and all(
                symbol in ALPHABET[:len(profile["palette"])] for symbol in codes),
                "retained case codes")
        require(profile["native_calls"] == len(profile["handles"]) * 720,
                "retained native case count")
    require(sum(p["native_calls"] for p in profiles) == 68400, "retained campaign size")
    return corpus["source_hashes"]


def helpers():
    spec = importlib.util.spec_from_file_location(
        "rax_native_cache_helpers", ROOT / "tools/ci/windows_command_processor.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-instruction-cache-v1")
    args = parser.parse_args()
    hashes = verify_sources()
    if args.verify_corpus:
        print(json.dumps({"verified_inputs": len(hashes), "native_calls": 68400,
                          "retained_process_abis": 3}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    output = (ROOT / args.output).resolve()
    require(output != ROOT and output.is_relative_to(ROOT) and not output.exists(),
            "output must be new and inside the checkout")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-instruction-cache-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    env = dict(os.environ, TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               SystemTemp=str(temporary), CCACHE_DISABLE="1", SCCACHE_DISABLE="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    target = (ROOT / env.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(ROOT), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    native = helpers()
    raw_hashes = {name: sha((SPECIFICATIONS / name).read_bytes()) for name in hashes}
    architectures = [("x64", "x64", 0x8664), ("x86", "Win32", 0x14c)]
    if platform.machine().lower() in ("arm64", "aarch64"):
        architectures.insert(0, ("arm64", "ARM64", 0xaa64))
    profiles, images = [], []
    for label, generator_arch, machine in architectures:
        build = output / ("build-" + label)
        native.run(["cmake", "-S", str(SOURCE), "-B", str(build), "-A", generator_arch],
                   ROOT, env, output / (label + "-configure.log"))
        native.run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
                   ROOT, env, output / (label + "-build.log"))
        image = Path((build / "probe-path-Release.txt").read_text(encoding="utf-8").strip()).resolve()
        require(image.is_relative_to(build.resolve()), "native image leaves build")
        raw = image.read_bytes()
        require(raw[:2] == b"MZ", "native DOS header")
        pe = struct.unpack_from("<I", raw, 0x3c)[0]
        require(raw[pe:pe + 4] == b"PE\0\0" and
                struct.unpack_from("<H", raw, pe + 4)[0] == machine, "native PE machine")
        result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, check=True)
        (output / (label + ".json")).write_bytes(result.stdout)
        (output / (label + ".stderr")).write_bytes(result.stderr)
        require(not result.stderr, "native producer stderr")
        profiles.append(normalize(json.loads(result.stdout), label, sha(result.stdout)))
        require(sha(image.read_bytes()) == sha(raw), "native image changed")
        images.append({"architecture": label, "bytes": len(raw), "sha256": sha(raw)})
        require(build.resolve().is_relative_to(output), "native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((SPECIFICATIONS / name).read_bytes()) == digest
                for name, digest in raw_hashes.items()), "producer inputs changed")
    corpus = output / "observations.json"
    corpus.write_text(json.dumps({"state": "complete", "schema": "rax-native-instruction-cache-v1",
        "source_hashes": hashes, "acquisition": {"native_kernel": platform.version(),
            "native_machine": platform.machine(), "programs": images},
        "profiles": profiles}, indent=2) + "\n", encoding="utf-8")
    env["RAX_INSTRUCTION_CACHE_CORPUS"] = str(corpus)
    log = output / "guest-replay.log"
    try:
        native.run(["cargo", "test", "--locked", "--no-default-features", "--lib",
                    "native_instruction_cache", "--", "--test-threads=1", "--nocapture"],
                   ROOT, env, log)
        native.require_tests(log, 6)
    finally:
        if log.exists():
            print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    shutil.rmtree(temporary)
    print(json.dumps({"corpus": str(corpus), "reports": len(profiles),
                      "native_calls": sum(p["native_calls"] for p in profiles),
                      "sha256": sha(corpus.read_bytes())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
