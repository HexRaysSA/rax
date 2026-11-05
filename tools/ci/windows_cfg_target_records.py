#!/usr/bin/env python3
"""Capture independent NT class2 record semantics, including WoW64 conversion."""
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

SCHEMA = "rax-native-cfg-target-records-v1"
SOURCE = "native-target-records-v1.rs"
BUFFERS = ("ranges", "information", "targets", "processed")
ARCHES = {"arm64": ("aarch64", 0xAA64, 8, 40),
          "x64": ("x86_64", 0x8664, 8, 40),
          "x86": ("x86", 0x14C, 4, 32)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_sha(raw):
    return sha(raw.replace(b"\r\n", b"\n"))


def cases_from_source(source):
    match = re.search(r"const CASES:.*?= &\[(.*?)\];", source, re.S)
    require(match is not None, "observer case declaration")
    cases = re.findall(r'"([^"\n]+)"', match[1])
    require(len(cases) == 102 and len(set(cases)) == len(cases), "observer case set")
    return cases


def fields(line):
    return dict(re.findall(r"(?:^| )([a-z_]+)=([^ ]*)", line))


def hexadecimal(value, length, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value), label)
    return int(value, 16)


def validate_stdout(stdout, architecture, cases):
    require(architecture in ARCHES, "observer architecture")
    lines = stdout.splitlines()
    profiles = [fields(line) for line in lines if line.startswith("PROFILE ")]
    require(len(profiles) == 1, "observer profile count")
    profile = profiles[0]
    arch, _, width, list_bytes = ARCHES[architecture]
    require(profile["arch"] == arch and int(profile["pointer_bytes"]) == width
            and int(profile["list_bytes"]) == list_bytes, "observer ABI layout")
    require(hexadecimal(profile["cfg_policy"], 8, "CFG policy") & 1, "CFG is not enabled")
    require(int(profile["cases"]) == len(cases), "observer profile case count")
    starts = [(index, fields(line)["case"]) for index, line in enumerate(lines)
              if line.startswith("BEGIN_CASE ")]
    require([case for _, case in starts] == cases, "missing, duplicate or reordered cases")
    result = []
    for position, (index, case) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        block = lines[index:end]
        endings = [fields(line) for line in block if line.startswith("END_CASE ")]
        require(len(endings) == 1 and endings[0]["case"] == case, "child terminal marker")
        terminal = endings[0]
        status = hexadecimal(terminal["exit"], 8, "child exit code")
        require(terminal["stderr_hex"] == "", "child stderr is not empty: " + case)
        enters = [fields(line) for line in block if line.startswith("ENTER ")]
        require(len(enters) == 1 and enters[0]["case"] == case, "child did not enter NT call")
        enter = enters[0]
        require(int(enter["pointer_bytes"]) == width
                and int(enter["list_bytes"]) == list_bytes, "child ABI layout")
        for key in ("target", "range_pointer", "information_pointer"):
            require(re.fullmatch(r"[0-9a-f]+", enter[key]) is not None, "child address encoding")
        rows = [fields(line) for line in block if line.startswith("RESULT ")]
        buffers = [fields(line) for line in block if line.startswith("BUFFER ")]
        completion = [line for line in block if line.startswith("COMPLETE case=")]
        observation = {"case": case, "entry": enter, "child_exit": status}
        if status:
            # Retain a thunk exception without inventing an NT return value or
            # treating it as a successful row. Kernel NT failures have exit0.
            require(status in (0xC0000005, 0x80000002), "unqualified child exception")
            require(not rows and not buffers and not completion, "inconsistent child exception")
            observation["kind"] = "thunk-exception"
        else:
            require(len(rows) == 1 and rows[0]["case"] == case, "missing NT return row")
            row = rows[0]
            for key in ("status", "last_error", "processed"):
                hexadecimal(row[key], 8, "NT result " + key)
            require([item["name"] for item in buffers] == list(BUFFERS), "caller buffer set")
            for item in buffers:
                require(item["case"] == case, "caller buffer case binding")
                require(re.fullmatch(r"[0-9a-f]+", item["address"]), "buffer address encoding")
                hexadecimal(item["before"], 128, "caller buffer before")
                hexadecimal(item["after"], 128, "caller buffer after")
            require(completion == [f"COMPLETE case={case} all_owned_allocations_released=true"],
                    "child did not release all owned allocations")
            observation.update(kind="nt-result", result=row, buffers=buffers)
        result.append(observation)
    require(lines[-1] == f"COMPLETE controls={len(cases)} all_children_terminal=true",
            "observer terminal marker")
    valid = result[cases.index("valid")]
    require(valid["kind"] == "nt-result" and valid["result"]["status"] == "00000000"
            and valid["result"]["processed"] == "00000001", "valid record control failed")
    return result


def pe_info(raw):
    require(raw[:2] == b"MZ", "observer DOS header")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    require(raw[pe:pe + 4] == b"PE\0\0", "observer NT header")
    machine = struct.unpack_from("<H", raw, pe + 4)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    require((machine, magic) in ((0x14C, 0x10B), (0x8664, 0x20B), (0xAA64, 0x20B)),
            "observer machine and optional-header ABI")
    directories, guard_at = (96, 88) if magic == 0x10B else (112, 144)
    characteristics = struct.unpack_from("<H", raw, optional + 70)[0]
    require(characteristics & 0x4000, "observer CFG DLL characteristic")
    rva, length = struct.unpack_from("<II", raw, optional + directories + 10 * 8)
    require(length >= guard_at + 4, "observer load configuration length")
    sections = optional + struct.unpack_from("<H", raw, pe + 20)[0]
    for index in range(struct.unpack_from("<H", raw, pe + 6)[0]):
        at = sections + index * 40
        va, size, offset = struct.unpack_from("<III", raw, at + 12)
        if va <= rva and rva + guard_at + 4 <= va + size:
            flags = struct.unpack_from("<I", raw, offset + rva - va + guard_at)[0]
            require(flags & 0x500 == 0x500, "observer CFG instrumentation and function table")
            return {"machine": machine, "optional_magic": magic,
                    "dll_characteristics": characteristics, "guard_flags": flags}
    raise ValueError("observer load configuration is not file backed")


def validate_corpus(corpus, source):
    require(corpus["schema"] == SCHEMA and corpus["state"] == "complete", "capture schema/state")
    cases = cases_from_source(source.decode("utf-8"))
    require(corpus["source_sha256"] == source_sha(source), "observer source identity")
    hexadecimal(corpus["source_raw_sha256"], 64, "raw observer source identity")
    machine = corpus["native_machine"]
    require(machine in (0x8664, 0xAA64), "native kernel architecture")
    require(len(corpus["kernel"]) == 3 and all(isinstance(v, int) for v in corpus["kernel"]),
            "native kernel version")
    expected = {"x86", "x64" if machine == 0x8664 else "arm64"}
    allowed = expected | ({"x64"} if machine == 0xAA64 else set())
    seen = set()
    for report in corpus["reports"]:
        arch = report["architecture"]
        require(arch in allowed and arch not in seen, "capture process architecture set")
        seen.add(arch)
        view = "wow64" if arch == "x86" else \
            "translated-x64" if machine == 0xAA64 and arch == "x64" else "native"
        require(report["execution_view"] == view, "capture process execution view")
        require(report["exit_code"] == 0 and not report["stderr"], "observer process failed")
        require(report["stdout_sha256"] == sha(report["stdout"].encode("utf-8")), "stdout identity")
        hexadecimal(report["image_sha256"], 64, "observer image identity")
        require(report["pe"]["machine"] == ARCHES[arch][1], "observer PE machine")
        require(report["pe"]["optional_magic"] == (0x10B if arch == "x86" else 0x20B),
                "observer PE optional-header ABI")
        require(report["pe"]["dll_characteristics"] & 0x4000
                and report["pe"]["guard_flags"] & 0x500 == 0x500, "observer CFG PE metadata")
        dlls = report["dll_sha256"]
        require(set(dlls) == {"ntdll.dll", "KernelBase.dll", "kernel32.dll"}, "observer DLL set")
        for digest in dlls.values():
            hexadecimal(digest, 64, "native DLL identity")
        validate_stdout(report["stdout"], arch, cases)
    require(expected <= seen, "capture omitted the native or WoW64 ABI")
    return sum(len(cases) for _ in seen)


def capture(root, source_path, output):
    require(sys.platform == "win32", "NT record capture requires native Windows")
    from windows_key_enumeration import native_machine
    from windows_cfg_private_code import execute
    machine = native_machine()
    require(machine in (0x8664, 0xAA64), "native kernel architecture")
    require(output != root and output.is_relative_to(root), "capture output leaves checkout")
    require(not output.exists(), "preserve existing NT record observations")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-cfg-target-records-ci-v1\n", encoding="utf-8")
    build, temporary = output / "build", output / "tmp"
    build.mkdir()
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="", CCACHE_DISABLE="1", SCCACHE_DISABLE="1")
    source = source_path.read_bytes()
    cases = cases_from_source(source.decode("utf-8"))
    version = sys.getwindowsversion()
    windows = Path(os.environ["SystemRoot"])
    dlls = {view: {name: sha((windows / view / name).read_bytes())
                   for name in ("ntdll.dll", "KernelBase.dll", "kernel32.dll")}
            for view in ("System32", "SysWOW64")}
    corpus = {"schema": SCHEMA, "state": "capturing", "source_sha256": source_sha(source),
              "source_raw_sha256": sha(source),
              "source_commit": os.environ.get("GITHUB_SHA"), "native_machine": machine,
              "kernel": [version.major, version.minor, version.build], "reports": []}
    receipt = output / "observations.json"

    def save():
        receipt.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")

    save()
    native = "arm64" if machine == 0xAA64 else "x64"
    for arch in (native, "x86"):
        image = build / (arch + ".exe")
        triple = {"arm64": "aarch64", "x64": "x86_64", "x86": "i686"}[arch] + "-pc-windows-msvc"
        argv = ["rustc", "+1.95.0", "--edition=2024", "--target", triple, str(source_path),
                "-C", "opt-level=0", "-C", "debuginfo=0", "-C", "control-flow-guard=yes",
                "-C", "link-arg=/guard:cf", "-o", str(image)]
        execute(argv, root, env, output, arch + "-build")
        raw = image.read_bytes()
        pe = pe_info(raw)
        require(pe["machine"] == ARCHES[arch][1], "observer executable architecture")
        execute([str(image), "--all"], root, env, output, arch)
        stdout = (output / (arch + ".stdout")).read_bytes()
        stderr = (output / (arch + ".stderr")).read_bytes()
        require(sha(image.read_bytes()) == sha(raw), "observer executable changed")
        report = {"architecture": arch, "exit_code": 0, "stderr": stderr.decode("utf-8"),
                  "execution_view": "wow64" if arch == "x86" else "native",
                  "stdout": stdout.decode("utf-8"), "stdout_sha256": sha(stdout),
                  "image_sha256": sha(raw), "pe": pe,
                  "dll_sha256": dlls["SysWOW64" if arch == "x86" else "System32"]}
        validate_stdout(report["stdout"], arch, cases)
        corpus["reports"].append(report)
        save()
    require(source_path.read_bytes() == source, "observer source changed")
    for view, names in dlls.items():
        require(all(sha((windows / view / name).read_bytes()) == digest
                    for name, digest in names.items()), "native DLL changed")
    corpus["state"] = "complete"
    count = validate_corpus(corpus, source)
    save()
    require(build.resolve().is_relative_to(output) and temporary.resolve().is_relative_to(output),
            "build cleanup containment")
    shutil.rmtree(build)
    shutil.rmtree(temporary)
    print(json.dumps({"kernel": corpus["kernel"], "native_machine": machine, "cases": count}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--output", default="target/native-cfg-target-records-v1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "docs/specifications/windows/native-cfg-target-records" / SOURCE
    if args.verify:
        count = validate_corpus(json.loads(args.verify.read_text(encoding="utf-8")), source.read_bytes())
        print(json.dumps({"verified_cases": count}))
    else:
        capture(root, source, (root / args.output).resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, IndexError, OSError, struct.error) as error:
        print("NT target-record capture failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
