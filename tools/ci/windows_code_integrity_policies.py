#!/usr/bin/env python3
"""Verify retained SystemCodeIntegrityPoliciesFullInformation evidence or capture and replay fresh native cases."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/specifications/windows/native-code-integrity-policies"
SCHEMA = "rax-native-code-integrity-policies-v1"
INPUTS = {"native-code-integrity-policies/" + name for name in ("CMakeLists.txt", "probe-v1.c")}
MACHINES = {"arm64": (0xAA64, 8), "x64": (0x8664, 8), "x86": (0x14C, 4)}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate(raw, width):
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) == 3282, "native observation count")
    head, end = rows[0], rows[-1]
    require(head["kind"] == "host" and head["schema"] == SCHEMA and
            head["pointer_bytes"] == width, "native process identity")
    required = head["required"]
    returned_page = ((required + 4095) & ~4095) + 8192
    require(4 <= required <= 16 * 1024 * 1024 and
            head["returned_page"] == returned_page and
            head["arena"] == returned_page + 65536, "bounded native arena")
    require(end["kind"] == "finished" and end["records"] == 3280,
            "incomplete native campaign")
    lengths = [0, 1, 4, 8, 31, 32, 64, 4096, required - 1, required,
               required + 1, required + 4096, head["arena"] + 1, 0xFFFFFFFF]
    for index, row in enumerate(rows[1:-1]):
        require(row["kind"] == "case" and row["index"] == index and
                len(bytes.fromhex(row["returned_bytes"])) == 8 and
                len(row["protections"]) == 6 and row["exception"] == 0 and
                0 <= row["copy_prefix"] <= required and
                row["arena_reconstruction_verified"] is True,
                "native complete-arena observation shape")
        if index < 3276:
            require(row["length"] == lengths[index // 234] and
                    row["output"] == index % 234 // 13 and
                    row["returned"] == index % 13 and row["poison"] == 0xA5,
                    "native length/output/ReturnLength matrix")
        else:
            control = index - 3276
            poison = 0x5A if control & 2 else 0xA5
            expected = (required.to_bytes(4, "little") + bytes([poison]) * 4
                        if not control & 1 else bytes([poison]) * 8)
            require(row["output"] == 0 and row["returned"] == control & 1 and
                    row["length"] == required and row["poison"] == poison and
                    row["status"] == 0 and
                    bytes.fromhex(row["returned_bytes"]) == expected,
                    "native complete stable-payload controls")
    return head, end


def verify_sources():
    manifest = json.loads((SOURCE / "controls-v1.json").read_text(encoding="utf-8"))
    require(manifest["schema"] == SCHEMA and manifest["state"] == "complete",
            "incomplete retained corpus")
    hashes = manifest["source_hashes"]
    require(set(hashes) == INPUTS, "native producer set changed")
    for name, expected in hashes.items():
        require(sha((SOURCE.parent / name).read_bytes().replace(b"\r\n", b"\n")) == expected,
                "retained producer changed: " + name)
    require(len(manifest["reports"]) == 3 and
            {r["architecture"] for r in manifest["reports"]} == set(MACHINES),
            "retained native process ABI coverage")
    for report in manifest["reports"]:
        label = report["architecture"]
        machine, width = MACHINES[label]
        require(report["file"] == label + ".jsonl" and report["machine"] == machine,
                "retained native image identity")
        raw = (SOURCE / report["file"]).read_bytes()
        require(sha(raw) == report["stdout_sha256"], "retained native stdout changed")
        head, end = validate(raw, width)
        payload = (SOURCE / report["snapshot"]["file"]).read_bytes()
        require(report["snapshot"]["file"] == "policies.bin" and
                len(payload) == head["required"] == report["snapshot"]["bytes"] and
                sha(payload) == report["snapshot"]["sha256"],
                "retained opaque payload changed")
        require(report["kernel"] == head["kernel"] and report["records"] == 3280 and
                report["exit_code"] == 0 and report["pointer_bytes"] == width,
                "retained report binding")
        provider = report["provider"]
        require(provider["before_sha256"] == provider["after_sha256"] and
                bytes.fromhex(head["mapped_provider_utf16"]).decode("utf-16-le") ==
                provider["mapped_native_path"], "retained mapped provider binding")
    for source in json.loads((SOURCE / "sources.json").read_text(encoding="utf-8"))["sources"]:
        raw = (SOURCE / source["file"]).read_bytes()
        require(len(raw) == source["bytes"] and sha(raw) == source["sha256"],
                "retained primary source changed: " + source["file"])
    return hashes


def mapped_file(header):
    native = bytes.fromhex(header["mapped_provider_utf16"]).decode("utf-16-le")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel.QueryDosDeviceW.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = letter + ":"
        if not kernel.QueryDosDeviceW(drive, buffer, len(buffer)):
            continue
        prefix = buffer.value
        if native.casefold().startswith((prefix + "\\").casefold()):
            result = Path(drive + native[len(prefix):]).resolve()
            require(result.is_relative_to(Path(os.environ["SystemRoot"]).resolve()) and
                    result.name.casefold() == "ntdll.dll", "mapped provider leaves Windows")
            return result
    raise RuntimeError("cannot resolve the actual mapped NTDLL provider: " + native)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-code-integrity-policies-v1")
    args = parser.parse_args()
    normalized = verify_sources()
    if args.verify_corpus:
        print(json.dumps({"verified_inputs": len(normalized), "process_abis": 3,
                          "native_records": 9840}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    output = (ROOT / args.output).resolve()
    require(output != ROOT and output.is_relative_to(ROOT) and not output.exists(),
            "output must be new and inside the checkout")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-code-integrity-policies-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               SystemTemp=str(temporary), CCACHE_DISABLE="1", SCCACHE_DISABLE="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    target = (ROOT / env.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(ROOT), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    env.pop("RAX_CODE_INTEGRITY_POLICIES_CORPUS", None)
    spec = importlib.util.spec_from_file_location(
        "rax_code_integrity_policiesci_helpers", ROOT / "tools/ci/windows_command_processor.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    hashes = {name: sha((SOURCE.parent / name).read_bytes()) for name in normalized}
    native.run(["cargo", "test", "--locked", "--no-default-features", "--lib", "--no-run"],
               ROOT, env, output / "replay-build.log")
    require(platform.machine().lower() in ("amd64", "x86_64", "arm64", "aarch64"),
            "native controls require a 64-bit Windows host")
    architectures = [("x64", "x64"), ("x86", "Win32")]
    if platform.machine().lower() in ("arm64", "aarch64"):
        architectures.insert(0, ("arm64", "ARM64"))
    records = []
    native.run(["cargo", "test", "--locked", "--no-default-features", "--lib",
                "code_integrity_policies", "--", "--test-threads=1"],
               ROOT, env, output / "retained-replay.log")
    retained = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
                          (output / "retained-replay.log").read_text(encoding="utf-8", errors="replace"))
    require(retained and tuple(map(int, retained[-1])) == (11, 0, 0),
            "incomplete retained policy replay selection")
    for label, arch in architectures:
        machine, width = MACHINES[label]
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
        artifact = output / ("native-code-integrity-policies-" + label + ".exe")
        artifact.write_bytes(raw)
        result = subprocess.run([str(artifact), "--identity"], cwd=output, env=env,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        (output / (label + "-identity.json")).write_bytes(result.stdout)
        (output / (label + "-identity.stderr")).write_bytes(result.stderr)
        require(result.returncode == 0, "native provider identity failed: " + label)
        identity = json.loads(result.stdout)
        require(identity["kind"] == "identity" and identity["schema"] == SCHEMA and
                identity["pointer_bytes"] == width, "native identity process ABI")
        provider = mapped_file(identity)
        before = sha(provider.read_bytes())
        snapshot = output / ("policies-" + label + ".bin")
        result = subprocess.run([str(artifact), "--run", str(snapshot)], cwd=output, env=env,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=600)
        (output / (label + ".jsonl")).write_bytes(result.stdout)
        (output / (label + ".stderr")).write_bytes(result.stderr)
        require(result.returncode == 0, f"native {label} observer failed: {result.returncode}")
        head, end = validate(result.stdout, width)
        payload = snapshot.read_bytes()
        require(len(payload) == head["required"], "native payload length")
        after = sha(provider.read_bytes())
        require(mapped_file(head) == provider and before == after and
                head["kernel"] == identity["kernel"] and
                head["mapped_provider_utf16"] == identity["mapped_provider_utf16"],
                "native mapped provider changed")
        require(sha(image.read_bytes()) == sha(artifact.read_bytes()) == sha(raw),
                "native image changed")
        records.append({"architecture": label, "file": label + ".jsonl",
            "machine": machine, "pointer_bytes": width, "kernel": head["kernel"],
            "records": 3280, "exit_code": result.returncode,
            "image": {"bytes": len(raw), "sha256": sha(raw)},
            "stdout_sha256": sha(result.stdout),
            "snapshot": {"file": snapshot.name, "bytes": len(payload), "sha256": sha(payload)},
            "provider": {"path": str(provider),
                "logical_path": bytes.fromhex(head["provider_utf16"]).decode("utf-16-le"),
                "mapped_native_path": bytes.fromhex(head["mapped_provider_utf16"]).decode("utf-16-le"),
                "before_sha256": before, "after_sha256": after}})
        # Keep immutable per-ABI evidence; avoid replacing a file held by Windows readers.
        (output / (label + "-report.json")).write_text(
            json.dumps(records[-1], indent=2) + "\n", encoding="utf-8")
        require(build.resolve().is_relative_to(output), "native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((SOURCE.parent / n).read_bytes()) == h for n, h in hashes.items()),
            "native producer inputs changed")
    require(len({r["snapshot"]["sha256"] for r in records}) == 1,
            "native policy bytes differ across process ABIs; no width-independent snapshot")
    corpus = output / "observations.json"
    corpus.write_text(json.dumps({"schema": SCHEMA, "state": "complete",
        "source_hashes": hashes, "normalized_source_hashes": normalized,
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine()}, "reports": records}, indent=2) + "\n",
        encoding="utf-8")
    env["RAX_CODE_INTEGRITY_POLICIES_CORPUS"] = str(output)
    log = output / "replay.log"
    try:
        native.run(["cargo", "test", "--locked", "--no-default-features", "--lib",
                    "code_integrity_policies", "--", "--test-threads=1", "--nocapture"],
                   ROOT, env, log)
        summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
                               log.read_text(encoding="utf-8", errors="replace"))
        require(summaries and tuple(map(int, summaries[-1])) == (11, 0, 0),
                "incomplete native policy replay selection")
    finally:
        if log.exists():
            print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    for record in records:
        require(sha((output / record["file"]).read_bytes()) == record["stdout_sha256"] and
                sha((output / record["snapshot"]["file"]).read_bytes()) == record["snapshot"]["sha256"],
                "native corpus changed during guest replay")
    shutil.rmtree(temporary)
    print(json.dumps({"corpus": str(corpus), "process_abis": len(records),
                      "native_records": 3280 * len(records), "sha256": sha(corpus.read_bytes())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
