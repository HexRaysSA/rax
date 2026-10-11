#!/usr/bin/env python3
"""Replay retained bootstrap observations; never rerun an oracle implicitly."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(root, name):
    return json.loads((root / name).read_text())


def raw(root, name):
    return (root / name).read_text(errors="strict")


def captured_start(root, arch, teb):
    name = f"native-startup-{'teb-' if teb else ''}probe-{arch}.log"
    text = raw(root, name)
    require("create ok=1" in text, name + ": create")
    require("peb heap=0 ldr=0" in text, name + ": cold PEB")
    peb = re.search(r"basic status=00000000 .* peb=([0-9A-F]+)", text)
    regs = re.search(r"registers .*", text)
    require(peb and regs, name + ": context missing")
    parameter = re.search(r"(?:x1|rdx|ebx)=([0-9A-F]+)", regs[0], re.I)
    require(parameter and parameter[1] == peb[1], name + ": main parameter")
    sizes = {"arm64": 912, "x64": 1232, "x86": 716}
    require(f"context ok=1 error=0 bytes={sizes[arch]}" in text, name + ": CONTEXT")
    require("cleanup terminate=1 error=0 wait=00000000" in text, name + ": cleanup")
    if teb:
        require("thread status=00000000" in text, name + ": thread basic")
        t = re.search(r"teb tls=0 peb=([0-9A-F]+) stack-base=([0-9A-F]+) stack-limit=([0-9A-F]+)", text)
        require(t and t[1] == peb[1], name + ": cold TLS/TEB PEB")
        sp = re.search(r"(?:sp|rsp|esp)=([0-9A-F]+)", regs[0], re.I)
        require(sp and int(t[3], 16) <= int(sp[1], 16) < int(t[2], 16), name + ": stack bounds")


def loader_capture(root, arch):
    text = raw(root, f"native-loader-entry-probe-{arch}.log")
    module = re.search(r"module=([0-9A-F]+)", text)
    result = re.search(r"loader pc=([0-9A-F]+) context=([0-9A-F]+) parameter=([0-9A-F]+) context-bytes=(\d+) saved-pc=([0-9A-F]+)", text)
    if arch == "x64":
        require(result is None and "caught=0" in text, "x64 failed capture must remain failed")
        return
    require(module and result and result[3] == module[1], arch + ": NTDLL-base parameter")
    expected = 912 if arch == "arm64" else 716
    require(int(result[4]) == expected, arch + ": context size")
    initial = re.search(r"initial-pc=([0-9A-F]+)", text)
    require(initial and initial[1] == result[5], arch + ": saved entry")
    require("caught=1 good=1 terminate=1 cleanup=1 exited=1 wait=00000000" in text, arch + ": debug exit cleanup")


def provenance(root):
    p = load(root, "ntdll-fault-provenance.json")
    f = p["function-extent"]
    start, end, fault = (int(f["rva"], 16), int(f["exclusive-end-rva"], 16), int(p["fault-pc-rva"], 16))
    require(start == 0x26450 and end == 0x267B0 and fault == 0x26528, "fault RVAs")
    require(start <= fault < end and end - start == f["bytes"] == 864 and fault - start == 0xD8, "fault/unwind bounds")
    require(p["nearest-public-symbol"]["name"] == "RtlpAllocateNTHeapInternal", "fault symbol")
    require(p["rsds"]["age"] == p["pdb-dbi-age"] == 1 and p["pdb-info-age"] == 4, "distinct PDB ages")
    identity = raw(root, "ntdll-pdb-identity.txt")
    require(p["rsds"]["guid"].upper() in identity.upper(), "matching PDB GUID")
    require("PdbStream:" in identity and "DbiStream:" in identity, "original PDB streams")
    selected = load(root, "selected-entry-contracts.json")
    require(len(selected) == 4, "bounded file entry contracts")
    for entry in selected:
        require(len(bytes.fromhex(entry["entry-hex"])) == entry["retained-bytes"] <= 64, "entry extent")
        if entry["profile"] == "arm64":
            require(entry["dll-sha256"] == p["dll-sha256"], "selected ARM64 DLL")
    header = root.parent / "native-process-parameters/phnt-ntrtl.h"
    require(digest(header.read_bytes()) == "8d37faeb36dd01d0f9931cc25ce35857848deacb28b21196b8a76732e2f3f3a3", "pinned PHNT header")
    require("LdrInitializeThunk(" in header.read_text() and "RtlUserThreadStart(" in header.read_text(), "primary declarations")
    license_file = root.parent / "native-process-parameters/phnt-LICENSE"
    require(digest(license_file.read_bytes()) == load(root, "primary-identities.json")["phnt-license-sha256"], "primary license")


def regression(root):
    for leaf in ("loader", "tls"):
        text = raw(root, f"macos-before-private-{leaf}-test.log")
        require("0 passed; 1 failed" in text and "68160" in text, "observed red baseline: " + leaf)
    original = (root / "native-bootstrap-before-production-trace.rs").read_bytes()
    after = (root / "native-bootstrap-after-production-trace.rs").read_bytes()
    require(original == after and digest(after) == "75d006334ffed51536d5d5b1c314c6b21b1e2e4f873add8db1b4e519874635f0", "identical unmodified ordinary observer")
    before = raw(root, "native-bootstrap-before-production-trace-output.log")
    require("first exception appears at turn=1459" in before and "PC=0x180026528 SP=0xabf9c0" in before, "ordinary baseline first fault")
    require("terminal turn=1500 Complete(Exited(3221225477))" in before, "ordinary baseline AV")
    after_text = raw(root, "native-bootstrap-after-production-trace-output.log")
    require("ProcessHeap=Ok(0)" in after_text, "ordinary cold heap")
    require("first exception appears" not in after_text, "ordinary continuation before any exception")
    require("relationship 6" in after_text and "class 107" in after_text and "Complete(Internal(" in after_text, "ordinary next unsupported frontier")
    require("terminal turn=40500" in after_text, "ordinary continuation scheduler count")
    require("diagnostic turn budget exhausted" not in after_text, "bounded observer must reach a terminal result")
    ordinary = raw(root, "native-bootstrap-after-ordinary-processes.log")
    require(ordinary.count("relationship 6") == 4, "four owning ordinary programs reach the recorded frontier")
    require(ordinary.count("run reason=5 exit=0") == 4, "four explicit internal failures; exit0 is not successful process completion")


def gates(root):
    validation = load(root, "validation.json")
    require(len(validation["gates"]) == 21, "complete three-host gate set")
    require(len({(x["host"], x["gate"]) for x in validation["gates"]}) == 21, "unique gates")
    for gate in validation["gates"]:
        text = raw(root, gate["path"])
        if "expected-summaries" in gate:
            require(re.findall(r"test result: .*", text) == gate["expected-summaries"], gate["path"] + ": summaries")
        for marker in gate.get("required-markers", []):
            require(marker in text, gate["path"] + ": " + marker)
        if gate["gate"] in ("targeted", "full", "capi", "integration"):
            counts = re.search(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
            expected = {"targeted": {"macos": (8, 0, 0), "linux": (8, 0, 0), "windows": (9, 0, 0)}, "full": {"macos": (7596, 0, 2), "linux": (7590, 0, 2), "windows": (6989, 5, 2)}, "capi": {host: (168, 0, 0) for host in ("macos", "linux", "windows")}, "integration": {"macos": (544, 0, 0), "linux": (544, 0, 0), "windows": (4, 0, 0)}}
            require(counts and tuple(map(int, counts.groups())) == expected[gate["gate"]][gate["host"]], gate["path"] + ": executed selection")
    for host, name in (("macos", "macos-final-full-macos.log"), ("linux", "linux-final-full.log"), ("windows", "native-bootstrap-final-full.log")):
        text = raw(root, name)
        failed = sorted(set(re.findall(r"test ([\w:]+) \.\.\. FAILED", text)))
        require(failed == sorted(validation["full-suite-failures"][host]), host + ": exact full failures")
    native = load(root, "native-owning-archive-hashes.json")
    require(native["core-features"] == [], "shipping core default features excluded")
    require(native["sources"] == load(root, "source-hashes-reviewed.json"), "same native compiled sources")
    require(len(native["archives"]) == 2, "Assist/core archive pair")
    for archive in native["archives"]:
        require(archive["structural-member-walk"] == "pass" and archive["bytes"] > 0 and archive["members"] > 0, "complete archive walk")
    artifacts = [json.loads(x) for x in raw(root, "native-bootstrap-after-artifacts.jsonl").splitlines()]
    core = [x for x in artifacts if x.get("reason") == "compiler-artifact" and x["target"]["name"] == "rax" and not x["manifest_path"].replace("\\", "/").endswith("/capi/Cargo.toml")]
    require(len(core) == 1 and core[0]["features"] == [], "Cargo-selected shipping RAX core")
    require(native["archives"][1]["path"] in core[0]["filenames"], "observer linked to selected owning core")


def main():
    require(not sys.flags.optimize, "Python -O is rejected")
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--source-root", type=Path)
    args = parser.parse_args()
    root = args.evidence_root
    manifest = load(root, "evidence-hashes.json")
    require(isinstance(manifest, list) and len(manifest) >= 50, "mandatory complete evidence manifest")
    require(len({x["path"] for x in manifest}) == len(manifest), "unique manifest paths")
    for row in manifest:
        name = Path(row["path"])
        require(not name.is_absolute() and ".." not in name.parts, "bounded manifest path")
        data = (root / name).read_bytes()
        require(len(data) == row["bytes"] and digest(data) == row["sha256"], str(name) + ": byte identity")
    source = args.source_root or Path(__file__).resolve().parents[4]
    sources = load(root, "source-hashes-reviewed.json")
    require(len(sources) == 8, "eight compiled owned sources")
    for row in sources:
        data = (source / row["path"]).read_bytes()
        require(len(data) == row["bytes"] and digest(data) == row["sha256"], row["path"] + ": frozen source identity")
    producers = {"native-startup-initial-probe.cpp": "6b086325e80731e2ae04afd641a39c712206a9c65fc11b69f13b9db81da49b7f", "native-startup-probe.cpp": "b865865eee00650e713904e0205b01cae95d1335367b655ee6865279ada28aa9", "native-loader-entry-probe.cpp": "b6598847230d766bd385b931d0c557e25051a11617320c67fee9152cc9204fa5"}
    for name, sha in producers.items():
        require(digest((root / name).read_bytes()) == sha, name + ": reviewed producer")
    identities = load(root, "native-producer-executable-identities.json")
    for prefix in ("native-startup-probe", "native-startup-teb-probe", "native-loader-entry-probe"):
        for arch, machine in (("arm64", "0xaa64"), ("x64", "0x8664"), ("x86", "0x14c")):
            rows = [x for x in identities if x["path"].endswith("\\" + prefix + "-" + arch + ".exe")]
            require(len(rows) == 1 and rows[0]["pe-machine"] == machine and rows[0]["bytes"] > 0, prefix + "/" + arch + ": compiled PE identity")
    for row in load(root, "owning-cpp-helper-hashes.json"):
        data = (root / row["path"]).read_bytes()
        require(len(data) == row["bytes"] and digest(data) == row["sha256"], row["path"] + ": actual owning helper")
    for arch in ("arm64", "x64", "x86"):
        captured_start(root, arch, False)
        captured_start(root, arch, True)
        loader_capture(root, arch)
    provenance(root)
    regression(root)
    gates(root)
    print("PASS: frozen sources, six cold-start captures, loader arguments/limits, primary provenance, red/green regressions, owning ordinary continuation, and 21 recorded gates")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("FAIL:", error, file=sys.stderr)
        sys.exit(1)
