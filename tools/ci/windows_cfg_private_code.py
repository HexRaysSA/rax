#!/usr/bin/env python3
"""Capture and validate independent Windows CFG private-code observations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

SOURCES = {"api": "native-api-v1.rs", "calls": "native-calls-v1.rs"}
COUNTS = {"ALLOC": 88, "PROTECT": 66, "win32": 24, "nt": 18}
CASES = (
    "default", "invalid", "invalid-mark-valid", "default-mark-invalid",
    "invalid-protect-no-update", "invalid-protect-default", "invalid-recommit-default",
    "default-recommit-invalid", "invalid-decommit-recommit", "invalid-mark-invalid-then-valid",
    "default-unaligned", "invalid-mark-valid-unaligned", "default-mark-invalid-other-slot",
    "invalid-mark-valid-other-slot", "invalid-mark-valid-wrong-slot",
    "reserve-invalid-commit-default", "reserve-invalid-commit-invalid", "invalid-release-reuse",
    "rw-mark-valid-no-update", "rw-mark-invalid-no-update", "rw-mark-invalid-default",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(line):
    return dict(re.findall(r"(?:^| )([a-z_]+)=([^ ]+)", line))


def validate_api(stdout, architecture):
    lines = stdout.splitlines()
    profiles = [fields(line) for line in lines if line.startswith("PROFILE ")]
    expected = "aarch64" if architecture == "arm64" else "x86_64"
    require(len(profiles) == 1 and profiles[0]["arch"] == expected, "API process architecture")
    profile = profiles[0]
    require(profile["pointer_bytes"] == "8" and profile["list_bytes"] == "40", "API ABI sizes")
    require(profile["cfg_policy_query"] == "1" and int(profile["cfg_policy"], 16) & 1,
            "API CFG policy is not enabled")
    groups = {name: [] for name in COUNTS}
    for line in lines:
        if line.startswith(("ALLOC ", "PROTECT ")):
            kind = line.split()[0]
        elif line.startswith("TARGET "):
            kind = fields(line)["api"]
        else:
            continue
        require(kind in groups, "unknown API observation kind")
        groups[kind].append(fields(line))
    for kind, count in COUNTS.items():
        rows = groups[kind]
        require([int(row["index"]) for row in rows] == list(range(1, count + 1)),
                "incomplete or duplicate API observations: " + kind)
        if kind != "win32":
            require(all(re.fullmatch(r"[0-9a-f]{8}", row["status"]) for row in rows),
                    "invalid native status encoding")
    require(len({(r["mode"], r["protect"]) for r in groups["ALLOC"]}) == 88,
            "duplicate allocation matrix cell")
    require(len({(r["initial"], r["protect"]) for r in groups["PROTECT"]}) == 66,
            "duplicate protection matrix cell")
    complete = [line for line in lines if line.startswith("COMPLETE ")]
    require(complete == ["COMPLETE allocation_cases=88 protection_cases=66 "
                         "win32_target_cases=24 native_target_cases=18 "
                         "all_owned_allocations_released=true"], "API completion/release marker")
    return {kind: len(rows) for kind, rows in groups.items()}


def validate_calls(stdout, architecture):
    expected_arch = "aarch64" if architecture == "arm64" else "x86_64"
    begin = re.findall(r"^BEGIN_CASE case=([^ ]+) pid=([0-9]+)$", stdout, re.M)
    require([case for case, _ in begin] == list(CASES), "incomplete or reordered call controls")
    results = {}
    for index, (case, _) in enumerate(begin):
        start = stdout.index("BEGIN_CASE case=" + case + " ")
        end = stdout.index("BEGIN_CASE case=" + begin[index + 1][0] + " ", start) \
            if index + 1 < len(begin) else len(stdout)
        block = stdout[start:end]
        calls = re.findall(r"^CALL case=([^ ]+) arch=([^ ]+) cfg_policy=([0-9a-f]{8}) "
                           r"offset=([0-9]+) expected_leaf=1234$", block, re.M)
        require(len(calls) == 1 and calls[0][0] == case and calls[0][1] == expected_arch,
                "child exited before its private CALL: " + case)
        require(int(calls[0][2], 16) & 1, "child CFG policy is not enabled")
        endings = re.findall(r"^END_CASE case=([^ ]+) exit=([0-9a-f]{8})$", block, re.M)
        require(len(endings) == 1 and endings[0][0] == case, "missing child terminal status")
        status = int(endings[0][1], 16)
        require(status in (0, 0xC0000409), "unqualified child termination: " + case)
        if status == 0:
            require("RETURN case=" + case + " result=1234\n" in block, "private leaf result")
            require("COMPLETE case=" + case + " all_owned_allocations_released=true\n" in block,
                    "private allocation release marker")
        else:
            require("RETURN case=" not in block, "failed child reported a leaf return")
        results[case] = status
    require(stdout.splitlines()[-1] == "COMPLETE controls=21 all_children_terminal=true",
            "parent completion marker")
    return results


def validate_report(report):
    require(report["architecture"] in ("arm64", "x64"), "unsupported native observer architecture")
    require(report["exit_code"] == 0 and not report.get("stderr"), "observer process failed")
    require(sha(report["stdout"].encode("utf-8")) == report["stdout_sha256"], "stdout identity")
    require(re.fullmatch(r"[0-9a-f]{64}", report["image_sha256"]), "image identity")
    pe = report["pe"]
    require(pe["machine"] == (0xAA64 if report["architecture"] == "arm64" else 0x8664)
            and pe["dll_characteristics"] & 0x4000 and pe["guard_flags"] & 0x500 == 0x500,
            "observer PE CFG metadata")
    dlls = report["dll_sha256"]
    require(set(dlls) == {"ntdll.dll", "KernelBase.dll", "kernel32.dll"}
            and all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in dlls.values()),
            "native DLL identities")
    if report["kind"] == "api":
        return validate_api(report["stdout"], report["architecture"])
    require(report["kind"] == "calls", "unknown observer kind")
    return validate_calls(report["stdout"], report["architecture"])


def verify_retained(source):
    corpus = json.loads((source / "controls-arm64-29698-v1.json").read_text(encoding="utf-8"))
    require(corpus["schema"] == "rax-native-cfg-private-code-v1" and corpus["state"] == "complete",
            "retained CFG corpus schema")
    require(corpus["kernel"] == [10, 0, 29698] and corpus["native_machine"] == 0xAA64,
            "retained native kernel identity")
    require(set(corpus["source_hashes"]) == set(SOURCES.values()), "observer source set")
    for name, digest in corpus["source_hashes"].items():
        require(sha((source / name).read_bytes().replace(b"\r\n", b"\n")) == digest,
                "observer source changed: " + name)
    seen = set()
    for report in corpus["reports"]:
        key = report["architecture"], report["kind"]
        require(key not in seen, "duplicate retained native report")
        seen.add(key)
        name = SOURCES[report["kind"]]
        require(report["source"] == name
                and report["source_sha256"] == corpus["source_hashes"][name], "report source binding")
        require(report["dll_sha256"] == corpus["dll_sha256"], "report DLL binding")
        validate_report(report)
    require(seen == {("x64", "api"), ("x64", "calls"), ("arm64", "api"), ("arm64", "calls")},
            "retained native process views")
    return corpus


def pe_info(raw):
    require(raw[:2] == b"MZ", "observer DOS header")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    require(raw[pe:pe + 4] == b"PE\0\0", "observer NT header")
    optional = pe + 24
    require(struct.unpack_from("<H", raw, optional)[0] == 0x20B, "observer must be PE32+")
    characteristics = struct.unpack_from("<H", raw, optional + 70)[0]
    require(characteristics & 0x4000, "observer lacks CFG DLL characteristic")
    rva, size = struct.unpack_from("<II", raw, optional + 112 + 10 * 8)
    require(size >= 148, "observer load configuration is missing")
    sections = optional + struct.unpack_from("<H", raw, pe + 20)[0]
    for index in range(struct.unpack_from("<H", raw, pe + 6)[0]):
        at = sections + 40 * index
        va, raw_size, offset = struct.unpack_from("<III", raw, at + 12)
        if va <= rva and rva + 148 <= va + raw_size:
            flags = struct.unpack_from("<I", raw, offset + rva - va + 144)[0]
            require(flags & 0x500 == 0x500, "observer lacks CFG instrumentation/target table")
            return {"machine": struct.unpack_from("<H", raw, pe + 4)[0],
                    "dll_characteristics": characteristics, "guard_flags": flags}
    raise ValueError("observer load configuration is not file backed")


def execute(argv, root, env, output, label):
    progress = output / (label + "-process.json")
    with (output / (label + ".stdout")).open("xb") as stdout, \
            (output / (label + ".stderr")).open("xb") as stderr:
        child = subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr)
        record = {"state": "running", "pid": child.pid, "argv": argv}
        progress.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        # No timeout restarts or termination: preserve the original process.
        record.update(exit_code=child.wait(), state="terminal")
        progress.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    require(record["exit_code"] == 0, "observer command failed: " + label)
    return record


def capture(root, source, output, expected):
    require(sys.platform == "win32", "native CFG capture requires Windows")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from windows_key_enumeration import native_machine
    machine = native_machine()
    require(machine in (0x8664, 0xAA64), "native CFG observer requires AMD64 or ARM64")
    architecture, triple = ("arm64", "aarch64-pc-windows-msvc") if machine == 0xAA64 \
        else ("x64", "x86_64-pc-windows-msvc")
    require(output != root and output.is_relative_to(root), "capture output leaves checkout")
    require(not output.exists(), "preserve previous CFG observations")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-cfg-private-code-ci-v1\n", encoding="utf-8")
    build, temporary = output / "build", output / "tmp"
    build.mkdir()
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               CCACHE_DISABLE="1", SCCACHE_DISABLE="1", RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    raw_sources = {name: sha((source / name).read_bytes()) for name in SOURCES.values()}
    version = sys.getwindowsversion()
    system = Path(os.environ["SystemRoot"]) / "System32"
    dlls = {name: sha((system / name).read_bytes())
            for name in ("ntdll.dll", "KernelBase.dll", "kernel32.dll")}
    corpus = {"schema": "rax-native-cfg-private-code-v1", "state": "capturing",
              "kernel": [version.major, version.minor, version.build], "native_machine": machine,
              "source_hashes": expected, "raw_source_hashes": raw_sources,
              "source_commit": os.environ.get("GITHUB_SHA"), "dll_sha256": dlls, "reports": []}
    receipt = output / "observations.json"
    receipt.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")
    execute(["rustc", "+1.95.0", "--version", "--verbose"], root, env, output, "compiler")
    for kind, filename in SOURCES.items():
        image = build / (kind + ".exe")
        argv = ["rustc", "+1.95.0", "--edition=2024", "--target", triple, str(source / filename),
                "-C", "opt-level=0", "-C", "debuginfo=0", "-C", "control-flow-guard=yes",
                "-C", "link-arg=/guard:cf", "-o", str(image)]
        execute(argv, root, env, output, kind + "-build")
        raw = image.read_bytes()
        pe = pe_info(raw)
        require(pe["machine"] == machine, "observer executable machine")
        argv = [str(image)] + (["--all"] if kind == "calls" else [])
        execute(argv, root, env, output, kind)
        stdout = (output / (kind + ".stdout")).read_bytes()
        stderr = (output / (kind + ".stderr")).read_bytes()
        require(sha(image.read_bytes()) == sha(raw), "observer image changed during execution")
        report = {"architecture": architecture, "kind": kind, "source": filename,
                  "source_sha256": expected[filename], "image_sha256": sha(raw), "pe": pe,
                  "dll_sha256": dlls,
                  "stdout": stdout.decode("utf-8"), "stdout_sha256": sha(stdout),
                  "stderr": stderr.decode("utf-8"), "exit_code": 0}
        validate_report(report)
        corpus["reports"].append(report)
        receipt.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")
    require(all(sha((source / name).read_bytes()) == digest for name, digest in raw_sources.items()),
            "observer source changed during capture")
    require(all(sha((system / name).read_bytes()) == digest for name, digest in dlls.items()),
            "native system DLL changed during capture")
    # Both owned executables are terminal; retain observations, not build trees.
    require(build.resolve().is_relative_to(output) and temporary.resolve().is_relative_to(output),
            "CFG build cleanup containment")
    shutil.rmtree(build)
    shutil.rmtree(temporary)
    corpus["state"] = "complete"
    receipt.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"kernel": corpus["kernel"], "architecture": architecture,
                      "api_observations": sum(COUNTS.values()), "call_controls": len(CASES)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-retained", action="store_true")
    parser.add_argument("--output", default="target/native-cfg-private-code-v1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "docs/specifications/windows/native-cfg-private-code"
    retained = verify_retained(source)
    if args.verify_retained:
        print(json.dumps({"retained_reports": len(retained["reports"]),
                          "retained_api_observations": 392, "retained_call_controls": 42,
                          "native_machine": retained["native_machine"], "kernel": retained["kernel"]}))
    else:
        capture(root, source, (root / args.output).resolve(), retained["source_hashes"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
