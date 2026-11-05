#!/usr/bin/env python3
"""Qualify native CFG transitions against each reservation's original protection."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys

from windows_cfg_private_code import execute, pe_info, require, sha

SOURCE = "native-original-protection-v1.rs"
RETAINED = "original-protection-arm64-29698-v1.json"
PROTECTIONS = {"rw": 4, "ro": 2, "na": 1, "x": 0x10, "xr": 0x20}
OPERATIONS = (
    "repeat-default-invalid", "repeat-default-aligned", "repeat-exec-invalid",
    "repeat-commit-invalid", "commit-invalid-default", "neighbor-default-aligned",
)
CASES = tuple(f"initial-{kind}-{operation}" for kind in PROTECTIONS for operation in OPERATIONS)


def validate_stdout(stdout, architecture):
    stdout = stdout.replace("\r\n", "\n")
    expected_arch = "aarch64" if architecture == "arm64" else "x86_64"
    begin = re.findall(r"^BEGIN_CASE case=(\S+) pid=([0-9]+)$", stdout, re.M)
    ending = re.findall(r"^END_CASE case=(\S+) exit=([0-9a-f]{8})$", stdout, re.M)
    require(len(begin) == len(ending) == 74 and len(dict(begin)) == len(dict(ending)) == 74,
            "all original children must have unique terminal records")
    require(all(int(pid) > 0 for _, pid in begin), "invalid original child PID")
    require([case for case, _ in begin] == [case for case, _ in ending],
            "child terminal order differs from launch order")
    require([case for case, _ in begin if case in CASES] == list(CASES),
            "missing or reordered original-protection controls")
    require(stdout.splitlines()[-1] == "COMPLETE controls=74 all_children_terminal=true",
            "parent completion marker")
    require("COMPLETE storage_controls=7 all_owned_allocations_released=true" in stdout,
            "storage-control completion marker")
    results = {}
    for case in CASES:
        start = stdout.index("BEGIN_CASE case=" + case + " ")
        finish = stdout.index("END_CASE case=" + case + " ", start)
        block = stdout[start:finish]
        calls = re.findall(r"^CALL case=(\S+) arch=(\S+) cfg_policy=([0-9a-f]{8}) "
                           r"offset=([0-9]+) expected_leaf=1234$", block, re.M)
        require(len(calls) == 1 and calls[0][:2] == (case, expected_arch),
                "child exited before its original-protection CALL: " + case)
        require(int(calls[0][2], 16) & 1, "child CFG policy is not enabled")
        offset = (4 if architecture == "arm64" else 1) if case.endswith("-aligned") else 0
        require(int(calls[0][3]) == offset, "private target offset differs: " + case)
        kind = case.split("-", 2)[1]
        states = re.findall(r"^TARGET_STATE case=(\S+) base=([0-9a-f]+) "
                            r"initial=([0-9a-f]{8}) reserved=(\S+)$", block, re.M)
        require(len(states) == 1 and states[0][0] == case
                and int(states[0][2], 16) == PROTECTIONS[kind] and states[0][3] == "false",
                "original allocation protection was not observed: " + case)
        status = int(dict(ending)[case], 16)
        expected = 0 if kind in ("rw", "ro", "na") else 0xC0000409
        require(status == expected, "original-protection outcome differs: " + case)
        returns = re.findall(r"^RETURN case=(\S+) result=(\S+)$", block, re.M)
        if status == 0:
            require(returns == [(case, "1234")], "private leaf result: " + case)
            require("COMPLETE case=" + case + " all_owned_allocations_released=true\n" in block,
                    "private allocation release marker: " + case)
        else:
            require(not returns, "terminal child reported a leaf return: " + case)
        results[case] = status
    return results


def validate_report(report):
    architecture = report["architecture"]
    require(architecture in ("arm64", "x64"), "unsupported observer architecture")
    machine = report["native_machine"]
    require(machine in (0x8664, 0xAA64)
            and (architecture != "arm64" or machine == 0xAA64)
            and report["translated"] == (architecture == "x64" and machine == 0xAA64),
            "native process-view binding")
    require(report["exit_code"] == 0 and not report.get("stderr"), "observer process failed")
    require(sha(report["stdout"].encode()) == report["stdout_sha256"], "stdout identity")
    require(re.fullmatch(r"[0-9a-f]{64}", report["image_sha256"]), "image identity")
    pe = report["pe"]
    require(pe["machine"] == (0xAA64 if architecture == "arm64" else 0x8664)
            and pe["dll_characteristics"] & 0x4000 and pe["guard_flags"] & 0x500 == 0x500,
            "observer PE CFG metadata")
    require(set(report["dll_sha256"]) == {"ntdll.dll", "KernelBase.dll", "kernel32.dll"}
            and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in report["dll_sha256"].values()),
            "native DLL identities")
    return validate_stdout(report["stdout"], architecture)


def verify_retained(source):
    corpus = json.loads((source / RETAINED).read_text(encoding="utf-8"))
    require(corpus["schema"] == "rax-native-cfg-original-protection-v1"
            and corpus["state"] == "complete", "retained original-protection schema")
    require(corpus["kernel"] == [10, 0, 29698] and corpus["native_machine"] == 0xAA64,
            "retained native kernel identity")
    require(corpus["source"] == SOURCE and sha((source / SOURCE).read_bytes()) == corpus["source_sha256"],
            "original-protection producer identity")
    seen = set()
    for report in corpus["reports"]:
        architecture = report["architecture"]
        require(architecture not in seen, "duplicate retained process view")
        seen.add(architecture)
        require(report["source_sha256"] == corpus["source_sha256"]
                and report["dll_sha256"] == corpus["dll_sha256"]
                and report["native_machine"] == corpus["native_machine"], "retained source/DLL binding")
        validate_report(report)
    require(seen == {"arm64", "x64"}, "retained native and translated process views")
    return corpus


def capture(root, source, output):
    require(sys.platform == "win32", "native original-protection capture requires Windows")
    from windows_key_enumeration import native_machine
    machine = native_machine()
    require(machine in (0x8664, 0xAA64), "native observer requires AMD64 or ARM64")
    architecture, triple = ("arm64", "aarch64-pc-windows-msvc") if machine == 0xAA64 \
        else ("x64", "x86_64-pc-windows-msvc")
    require(output != root and output.is_relative_to(root), "capture output leaves checkout")
    require(not output.exists(), "preserve previous original-protection observations")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-cfg-original-protection-ci-v1\n", encoding="utf-8")
    build, temporary = output / "build", output / "tmp"
    build.mkdir()
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               CCACHE_DISABLE="1", SCCACHE_DISABLE="1", RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    producer = source / SOURCE
    source_hash = sha(producer.read_bytes())
    version = sys.getwindowsversion()
    system = Path(os.environ["SystemRoot"]) / "System32"
    dlls = {name: sha((system / name).read_bytes())
            for name in ("ntdll.dll", "KernelBase.dll", "kernel32.dll")}
    corpus = {"schema": "rax-native-cfg-original-protection-v1", "state": "capturing",
              "kernel": [version.major, version.minor, version.build], "native_machine": machine,
              "source": SOURCE, "source_sha256": source_hash, "source_commit": os.environ.get("GITHUB_SHA"),
              "dll_sha256": dlls, "reports": [], "scope": "Thirty repeated transitions from five original protections. Other child cases are terminality checks only. Exit0xc0000409 has no captured exception-record subcode."}
    receipt = output / "observations.json"
    receipt.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")
    execute(["rustc", "+1.95.0", "--version", "--verbose"], root, env, output, "compiler")
    image = build / "original-protection.exe"
    execute(["rustc", "+1.95.0", "--edition=2024", "--target", triple, str(producer),
             "-C", "opt-level=0", "-C", "debuginfo=0", "-C", "control-flow-guard=yes",
             "-C", "link-arg=/guard:cf", "-o", str(image)], root, env, output, "build")
    raw = image.read_bytes()
    pe = pe_info(raw)
    require(pe["machine"] == machine, "observer executable machine")
    execute([str(image), "--all"], root, env, output, "original-protection")
    stdout = (output / "original-protection.stdout").read_bytes()
    stderr = (output / "original-protection.stderr").read_bytes()
    require(sha(image.read_bytes()) == sha(raw), "observer image changed during execution")
    report = {"architecture": architecture, "native_machine": machine, "translated": False,
              "source_sha256": source_hash, "image_sha256": sha(raw),
              "pe": pe, "dll_sha256": dlls, "stdout": stdout.decode("utf-8"),
              "stdout_sha256": sha(stdout), "stderr": stderr.decode("utf-8"), "exit_code": 0}
    validate_report(report)
    require(sha(producer.read_bytes()) == source_hash, "producer changed during capture")
    require(all(sha((system / name).read_bytes()) == value for name, value in dlls.items()),
            "native DLL changed during capture")
    corpus["reports"].append(report)
    # All original child processes are terminal before removing owned build outputs.
    require(build.resolve().is_relative_to(output) and temporary.resolve().is_relative_to(output),
            "build cleanup containment")
    shutil.rmtree(build)
    shutil.rmtree(temporary)
    corpus["state"] = "complete"
    receipt.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"kernel": corpus["kernel"], "architecture": architecture,
                      "repeat_controls": len(CASES), "all_74_children_terminal": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-retained", action="store_true")
    parser.add_argument("--output", default="target/native-cfg-original-protection-v1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "docs/specifications/windows/native-cfg-private-code"
    corpus = verify_retained(source)
    if args.verify_retained:
        print(json.dumps({"process_views": len(corpus["reports"]), "repeat_controls": 60,
                          "kernel": corpus["kernel"], "native_machine": corpus["native_machine"]}))
    else:
        capture(root, source, (root / args.output).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
