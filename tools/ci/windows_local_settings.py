#!/usr/bin/env python3
"""Verify Local Settings producers and compare fresh native snapshots and opens."""
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
SOURCE = SPECIFICATIONS / "native-local-settings"
SCHEMA = "rax-native-local-settings-v1"
INPUTS = {"native-command-processor/absolute-v1.c"} | {
    "native-local-settings/" + name for name in
    ("CMakeLists.txt", "probe-v1.c", "digest-v1.h", "opens-v1.h")}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def helpers():
    spec = importlib.util.spec_from_file_location(
        "rax_local_settings_ci_helpers", ROOT / "tools/ci/windows_command_processor.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate(snapshot, width):
    require(snapshot["pointer_bytes"] == width, "native process pointer width")
    require(snapshot["handles_before"] == snapshot["handles_after"], "native handle leak")
    roots = snapshot["roots"]
    require(len(roots) == 2 and roots[0] == roots[1] and
            all(v in (0, 0xC0000034, 0xC000003A) for v in roots),
            "shared Local Settings root presence or absence changed")
    for field, limit in (("nodes", 16384), ("values", 65536), ("path_bytes", 8 << 20),
                         ("value_bytes", 32 << 20), ("child_entries", 32768),
                         ("child_bytes", 2 << 20), ("wire_bytes", 64 << 20)):
        require(0 <= snapshot[field] <= limit, "native snapshot bound: " + field)
    require(len(snapshot["sha256"]) == 64 and
            len(bytes.fromhex(snapshot["sha256"])) == 32, "native snapshot SHA-256")
    sid = bytes.fromhex(snapshot["subject_sid_hex"])
    require(8 <= len(sid) <= 68 and sid[0] == 1 and len(sid) == 8 + 4 * sid[1],
            "native creator SID encoding")
    if roots[0] != 0:
        require(snapshot["nodes"] == snapshot["values"] == snapshot["child_entries"] == 0
                and snapshot["wire_bytes"] == 24 and not snapshot.get("opens"),
                "absent root has retained contents")
        return
    require(snapshot["nodes"] >= 2 and snapshot["child_entries"] == snapshot["nodes"] - 2,
            "complete paired tree geometry")
    require(len(bytes.fromhex(snapshot["canonical_hex"])) % 2 == 0,
            "native canonical UTF-16")
    rows = snapshot["opens"]
    require(len(rows) == 288, "native fixed open matrix size")
    cases = set()
    for row in rows:
        case = tuple(row[k] for k in ("route", "name", "extended", "view", "request", "parent_view"))
        require(case[0] in range(4) and case[1] in range(3) and case[2] in (0, 1)
                and case[3] in (0, 0x100, 0x200) and case[4] in (0x20019, 0x02000000)
                and case[5] in ((0, 0x100, 0x200) if case[0] >= 2 else (0,)),
                "native open selector")
        require(case not in cases, "duplicate native open case")
        cases.add(case)
        require(row["handle_nonzero"] == int(row["status"] == 0), "native handle publication")
        if row["status"] == 0:
            require(row["name"] == 0 and row["granted_access"] & ~0xF003F == 0,
                    "native fixed-subject grant")
        else:
            require(row["name"] != 0 and row["status"] in (0xC0000034, 0xC000003A),
                    "native fixed missing descendant")


def verify_sources():
    corpus = json.loads((SOURCE / "controls-v1.json").read_text(encoding="utf-8"))
    require(corpus["schema"] == SCHEMA and corpus["state"] == "complete",
            "incomplete retained Local Settings corpus")
    hashes = corpus["source_hashes"]
    require(set(hashes) == INPUTS, "native producer set changed")
    for name, expected in hashes.items():
        require(sha((SPECIFICATIONS / name).read_bytes().replace(b"\r\n", b"\n")) == expected,
                "retained native producer changed: " + name)
    records = corpus["reports"]
    require(len(records) == 3 and {v["architecture"] for v in records} == {"arm64", "x64", "x86"},
            "retained native process ABI coverage")
    for record in records:
        validate(record["snapshot"], 4 if record["architecture"] == "x86" else 8)
    return hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-local-settings-v1")
    args = parser.parse_args()
    normalized = verify_sources()
    if args.verify_corpus:
        print(json.dumps({"verified_inputs": len(normalized), "retained_process_abis": 3}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    output = (ROOT / args.output).resolve()
    require(output != ROOT and output.is_relative_to(ROOT) and not output.exists(),
            "output must be new and inside the checkout")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-local-settings-ci-v1\n", encoding="utf-8")
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
    native = helpers()
    architectures = [("x64", "x64", 0x8664, 8), ("x86", "Win32", 0x14C, 4)]
    if platform.machine().lower() in ("arm64", "aarch64"):
        architectures.insert(0, ("arm64", "ARM64", 0xAA64, 8))
    # A cold Rust build can outlive the captured registry state. Prepare the
    # exact test image before sampling the live subject, then compare promptly.
    native.run(["cargo", "test", "--locked", "--no-default-features", "--lib", "--no-run"],
               ROOT, env, output / "replay-build.log")
    records = []
    for label, arch, machine, width in architectures:
        build = output / ("build-" + label)
        native.run(["cmake", "-S", str(SOURCE), "-B", str(build), "-A", arch],
                   ROOT, env, output / (label + "-configure.log"))
        native.run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
                   ROOT, env, output / (label + "-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == 1, "native target count")
        image = Path(paths[0]).resolve()
        require(image.is_relative_to(build.resolve()), "native image leaves build")
        raw = image.read_bytes()
        require(len(raw) >= 64 and raw[:2] == b"MZ", "native DOS header")
        pe = struct.unpack_from("<I", raw, 0x3C)[0]
        require(pe <= len(raw) - 24 and raw[pe:pe + 4] == b"PE\0\0" and
                struct.unpack_from("<H", raw, pe + 4)[0] == machine, "native PE machine")
        result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True)
        (output / (label + ".json")).write_bytes(result.stdout)
        (output / (label + ".stderr")).write_bytes(result.stderr)
        require(result.returncode == 0, f"native {label} observer failed: {result.returncode}")
        snapshot = json.loads(result.stdout)
        validate(snapshot, width)
        require(sha(image.read_bytes()) == sha(raw), "native image changed")
        records.append({"architecture": label, "snapshot": snapshot,
                        "image": {"machine": machine, "bytes": len(raw), "sha256": sha(raw)},
                        "stdout_sha256": sha(result.stdout)})
        require(build.resolve().is_relative_to(output), "native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((SPECIFICATIONS / n).read_bytes()) == h for n, h in raw_hashes.items()),
            "native producer inputs changed")
    require(len({r["snapshot"]["sha256"] for r in records}) == 1,
            "snapshot changed between native process ABIs")
    corpus = output / "observations.json"
    corpus.write_text(json.dumps({"schema": SCHEMA, "state": "complete",
        "source_hashes": raw_hashes, "normalized_source_hashes": normalized,
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine()}, "reports": records}, indent=2) + "\n",
        encoding="utf-8")
    env["RAX_LOCAL_SETTINGS_CORPUS"] = str(corpus)
    log = output / "replay.log"
    try:
        native.run(["cargo", "test", "--locked", "--no-default-features", "--lib",
                    "local_settings", "--", "--test-threads=1", "--nocapture"], ROOT, env, log)
        native.require_tests(log, 12)
    finally:
        if log.exists():
            print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    shutil.rmtree(temporary)
    print(json.dumps({"corpus": str(corpus), "reports": len(records),
                      "sha256": sha(corpus.read_bytes())}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
