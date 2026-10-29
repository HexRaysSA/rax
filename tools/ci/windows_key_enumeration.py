#!/usr/bin/env python3
"""Verify native enumeration evidence, capture installed controls and replay them."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

# Embedded Python can omit the script directory even for direct script execution.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from windows_command_processor import require, require_tests, run, sha

KINDS = ("basic", "fault")
SOURCES = ("probe-v1.c", "fault-v1.c", "CMakeLists.txt")


def compact(report, kind):
    inputs = (["root", "view", "index", "class", "offset", "length"] if kind == "basic"
              else ["view", "handle_kind", "index", "class", "scenario", "length",
                    "out_watch", "result_watch"])
    outputs, output_ids, rows = [], {}, []

    def prefix(text, size, fill):
        raw = bytes.fromhex(text)
        require(len(raw) == size, "native monitor size")
        last = max((i + 1 for i, value in enumerate(raw) if value != fill), default=0)
        encoded = raw[:last].hex()
        require(bytes.fromhex(encoded).ljust(size, bytes([fill])) == raw,
                "native monitor projection lost bytes")
        return encoded

    for row in report["rows"]:
        result = {k: v for k, v in row.items()
                  if k not in inputs and k not in ("buffer_hex", "result_hex")}
        result["buffer_prefix_hex"] = prefix(row["buffer_hex"], 384, 0xA5)
        if kind == "fault":
            result["result_prefix_hex"] = prefix(row["result_hex"], 32, 0xCC)
        key = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if key not in output_ids:
            output_ids[key] = len(outputs)
            outputs.append(result)
        rows.append([row[k] for k in inputs] + [output_ids[key]])
    data = {k: v for k, v in report.items()
            if k not in ("pointer_bytes", "handles_before", "handles_after", "rows")}
    data.update(row_fields=inputs + ["output"], outputs=outputs, rows=rows)
    identity = sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    return identity, data


def verify_sources(source):
    corpus = json.loads((source / "controls-v1.json").read_text(encoding="utf-8"))
    require(corpus["schema"] == "rax-native-key-enumeration-v1"
            and corpus["state"] == "complete", "retained corpus schema")
    expected = corpus["source_hashes"]
    require(set(expected) == set(SOURCES), "native producer input set")
    for name, value in expected.items():
        require(sha((source / name).read_bytes().replace(b"\r\n", b"\n")) == value,
                "native producer changed: " + name)
    require(set(corpus["campaigns"]) == set(KINDS), "native campaign set")
    for kind, campaign in corpus["campaigns"].items():
        require(len(campaign["reports"]) == 3, "retained ABI count")
        for identity, data in campaign["datasets"].items():
            require(sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
                    == identity, "native dataset identity")
            for row in data["rows"]:
                require(len(row) == len(data["row_fields"])
                        and 0 <= row[-1] < len(data["outputs"]), "native dense row")
        for report in campaign["reports"]:
            require(report["handles_before"] == report["handles_after"], "retained handle leak")
            require(report["dataset"] in campaign["datasets"], "native dataset missing")
            require(len(campaign["datasets"][report["dataset"]]["rows"])
                    == (4872 if kind == "basic" else 5676), "retained row count")
    return expected


def native_machine():
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = [wintypes.HANDLE,
                                     ctypes.POINTER(wintypes.USHORT),
                                     ctypes.POINTER(wintypes.USHORT)]
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process, native = wintypes.USHORT(), wintypes.USHORT()
    require(kernel.IsWow64Process2(kernel.GetCurrentProcess(),
                                  ctypes.byref(process), ctypes.byref(native)),
            "IsWow64Process2 failed")
    require(native.value in (0x8664, 0xAA64), "native kernel architecture not captured")
    return native.value


def validate(report, kind, width):
    require(report["pointer_bytes"] == width, "native process width")
    require(report["handles_before"] == report["handles_after"], "native handle leak")
    require(all(row["exception"] == 0 for row in report["rows"]),
            "native caller-visible exception requires separate dispatch coverage")
    if kind == "basic":
        require(len(report["roots"]) == 6, "native fixed-root count")
        require(all(row["output_alignment"] == row["offset"] % 8
                    and 0 <= row["result_alignment"] < 8 for row in report["rows"]),
                "native measured pointer alignment")
        expected = 0
        for root in report["roots"]:
            require(root["status"] in (0, 2, 3), "native fixed-root failure")
            if root["status"] == 0:
                require(root["children"] == len(root["names"]), "native child count")
                expected += (root["children"] + 2) * 8 * 20 + 12
        require(len(report["rows"]) == expected and expected > 0, "native basic case count")
    else:
        require(report["page_size"] == 4096 and len(report["rows"]) == 5676
                and len(report["roots"]) == 2 and len(report["opens"]) == 10,
                "native fault matrix dimensions")
        require(all(row["access"] == row["granted"] for row in report["opens"]),
                "native owned handle grant differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-key-enumeration-v1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "docs/specifications/windows/native-key-enumeration"
    normalized = verify_sources(source)
    if args.verify_corpus:
        print(json.dumps({"verified_producers": len(normalized), "retained_process_abis": 3,
                          "basic_rows": 14616, "fault_rows": 17028}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    machine = native_machine()
    output = (root / args.output).resolve()
    require(output != root and output.is_relative_to(root), "output leaves checkout")
    require(not output.exists(), "preserve existing evidence")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-key-enumeration-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               SystemTemp=str(temporary), CCACHE_DISABLE="1", SCCACHE_DISABLE="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    target = (root / env.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(root), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    raw_hashes = {name: sha((source / name).read_bytes()) for name in normalized}
    architectures = [("x64", "x64", 0x8664, 8), ("x86", "Win32", 0x14C, 4)]
    if machine == 0xAA64:
        architectures.insert(0, ("arm64", "ARM64", 0xAA64, 8))
    version = sys.getwindowsversion()
    corpus = {"schema": "rax-native-key-enumeration-v1", "state": "complete",
              "kernel": [version.major, version.minor, version.build],
              "native_machine": machine, "source_hashes": raw_hashes,
              "normalized_source_hashes": normalized,
              "campaigns": {k: {"reports": [], "datasets": {}} for k in KINDS}}
    for label, generator_arch, pe_machine, width in architectures:
        build = output / ("build-" + label)
        run(["cmake", "-S", str(source), "-B", str(build), "-A", generator_arch],
            root, env, output / (label + "-configure.log"))
        run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
            root, env, output / (label + "-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == 2, "native target path count")
        for kind, path in zip(KINDS, paths):
            image = Path(path).resolve()
            require(image.is_relative_to(build.resolve()), "native image leaves build")
            raw = image.read_bytes()
            require(raw[:2] == b"MZ", "native DOS header")
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            require(raw[pe:pe+4] == b"PE\0\0"
                    and struct.unpack_from("<H", raw, pe+4)[0] == pe_machine,
                    "native PE machine")
            result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=True)
            (output / (label + "-" + kind + ".json")).write_bytes(result.stdout)
            (output / (label + "-" + kind + ".stderr")).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            validate(report, kind, width)
            require(sha(image.read_bytes()) == sha(raw), "native image changed")
            identity, data = compact(report, kind)
            campaign = corpus["campaigns"][kind]
            campaign["datasets"].setdefault(identity, data)
            campaign["reports"].append({"architecture": label, "pointer_bytes": width,
                "handles_before": report["handles_before"], "handles_after": report["handles_after"],
                "dataset": identity, "image": {"machine": pe_machine, "bytes": len(raw),
                "sha256": sha(raw), "report_sha256": sha(result.stdout)}})
        require(build.resolve().is_relative_to(output), "native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((source / name).read_bytes()) == value for name, value in raw_hashes.items()),
            "native producer inputs changed")
    corpus_path = output / "observations.json"
    corpus_path.write_text(json.dumps(corpus, separators=(",", ":")) + "\n", encoding="utf-8")
    env["RAX_KEY_ENUMERATION_CORPUS"] = str(corpus_path)
    log = output / "guest-replay.log"
    try:
        run(["cargo", "test", "--locked", "--no-default-features", "--lib",
             "registry_tests::key_enumeration::", "--", "--test-threads=1", "--nocapture"],
            root, env, log)
        require_tests(log, 6)
    finally:
        if log.exists():
            print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    shutil.rmtree(temporary)
    print(json.dumps({"corpus": str(corpus_path), "process_abis": len(architectures),
                      "sha256": sha(corpus_path.read_bytes())}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
