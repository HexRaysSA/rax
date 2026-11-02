#!/usr/bin/env python3
"""Verify retained bulk registry queries, or capture and replay native controls."""
import argparse
import ctypes
from ctypes import wintypes
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
_codec_spec = importlib.util.spec_from_file_location(
    "rax_query_multiple_codec", Path(__file__).with_name("windows_query_multiple_codec.py"))
codec = importlib.util.module_from_spec(_codec_spec)
_codec_spec.loader.exec_module(codec)


def write_json(path, value):
    path.write_bytes((json.dumps(value, indent=2) + "\n").encode("utf-8"))


def run(argv, env, log):
    with log.open("xb") as stream:
        result = subprocess.run(argv, cwd=codec.ROOT, env=env, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT)
    codec.require(result.returncode == 0, "command failed; inspect " + str(log))


def native_machine():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT),
                                     ctypes.POINTER(wintypes.USHORT)]
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process, native = wintypes.USHORT(), wintypes.USHORT()
    codec.require(kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process),
                                        ctypes.byref(native)), "IsWow64Process2 failed")
    codec.require(native.value in (0xAA64, 0x8664), "64-bit native Windows is required")
    return native.value


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
            path = Path(drive + native[len(prefix):]).resolve()
            codec.require(path.is_relative_to(Path(os.environ["SystemRoot"]).resolve()) and
                          path.name.casefold() == "ntdll.dll", "mapped provider leaves Windows")
            return path
    raise RuntimeError("cannot resolve the mapped NTDLL provider")


def owned_key(row, nonce, recover, overflow=False):
    import winreg
    codec.require(row["kind"] == "owned_key" and row["marker"] == nonce, "native fixture owner")
    path = bytes.fromhex(row["path" if overflow else "key_path_utf16"]).decode(
        "utf-16-be" if overflow else "utf-16-le")
    prefix = "Software\\RaxQmvOverflow_20261101_" if overflow else "Software\\RaxNativeQmv_20261030_"
    codec.require(path.startswith(prefix), "native fixture prefix")
    if recover:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                marker, kind = winreg.QueryValueEx(key, "_RaxProbeOwner")
                codec.require(marker == nonce and kind == winreg.REG_SZ, "native fixture marker")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except FileNotFoundError:
            pass
    for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_QUERY_VALUE | view):
                raise RuntimeError("native fixture key survives cleanup")
        except FileNotFoundError:
            pass


def capture(label, architecture, machine, output, env, overflow=False):
    expected_machine, width = codec.MACHINES[label]
    build = output / ("build-" + label)
    source = codec.overflow.SOURCE / "copy-v2" if overflow else codec.SOURCE
    run(["cmake", "-S", str(source), "-B", str(build), "-A", architecture],
        env, output / (label + "-configure.log"))
    run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
        env, output / (label + "-build.log"))
    paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
    codec.require(len(paths) == 1, "native target path count")
    image = Path(paths[0]).resolve()
    codec.require(image.is_relative_to(build.resolve()), "native image leaves build")
    raw = image.read_bytes()
    codec.require(raw[:2] == b"MZ" and len(raw) >= 64, "native DOS header")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    codec.require(pe <= len(raw) - 24 and raw[pe:pe+4] == b"PE\0\0" and
                  struct.unpack_from("<H", raw, pe+4)[0] == expected_machine, "native PE machine")
    artifact = output / ("native-query-multiple-values-" + label + ".exe")
    artifact.write_bytes(raw)
    image_hash = codec.sha(raw)
    headers = set()
    for log in build.rglob("CL.read.1.tlog"):
        for line in log.read_text(encoding="utf-16", errors="replace").splitlines():
            if line.casefold().endswith("winternl.h"):
                headers.add(Path(line).resolve())
    codec.require(len(headers) == 1, "actual compiler SDK header selection")
    header = headers.pop()
    header_bytes = header.read_bytes()
    # The primary observer has a read-only identity mode. Its mapped path must
    # equal the overflow observer's actual mapping recorded before key creation.
    identity_image = output.parent / artifact.name if overflow else artifact
    identity_hash = codec.sha(identity_image.read_bytes())
    identity = subprocess.run([str(identity_image), "--identity"], cwd=output, env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    (output / (label + "-identity.json")).write_bytes(identity.stdout)
    (output / (label + "-identity.stderr")).write_bytes(identity.stderr)
    codec.require(identity.returncode == 0, "native provider identity")
    identity = json.loads(identity.stdout)
    codec.require(identity["kind"] == "identity" and identity["schema"] == codec.NATIVE_SCHEMA and
                  identity["pointer_bytes"] == width, "native identity process ABI")
    provider = mapped_file(identity)
    before = codec.sha(provider.read_bytes())
    nonce = codec.sha((label + image_hash).encode("ascii"))[:16]
    arguments = [str(artifact), nonce] if overflow else [str(artifact), "--run", nonce]
    child = subprocess.Popen(arguments, cwd=output, env=env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    write_json(output / (label + "-launch.json"), dict(pid=child.pid, nonce=nonce, image_sha256=image_hash))
    # A transport/observation timeout must not be treated as child termination.
    stdout, stderr = child.communicate(timeout=600)
    (output / (label + ".jsonl")).write_bytes(stdout)
    (output / (label + ".stderr")).write_bytes(stderr)
    if child.returncode:
        owner = next((json.loads(line) for line in stdout.splitlines()
                      if json.loads(line).get("kind") == "owned_key"), None)
        if owner is not None:
            owned_key(owner, nonce, recover=True, overflow=overflow)
        raise RuntimeError("native observer failed: " + label + ": " + str(child.returncode))
    rows = codec.overflow.validate(stdout, width, 2) if overflow else codec.validate(stdout, width)
    owned_key(rows[1 if overflow else 0], nonce, recover=False, overflow=overflow)
    head = rows[0 if overflow else 1]
    after = codec.sha(provider.read_bytes())
    codec.require(mapped_file(head) == provider and before == after and
                  identity["kernel"] == head["kernel"] and
                  identity["mapped_provider_utf16"] == head["mapped_provider_utf16"],
                  "mapped provider changed")
    codec.require(codec.sha(image.read_bytes()) == codec.sha(artifact.read_bytes()) == image_hash,
                  "native image changed")
    codec.require(codec.sha(identity_image.read_bytes()) == identity_hash, "identity image changed")
    metadata = dict(architecture=label, native_machine=machine, machine=expected_machine,
                    pointer_bytes=width, kernel=head["kernel"], exit_code=0,
                    image=dict(bytes=len(raw), sha256=image_hash),
                    SDK_header=dict(path=str(header), bytes=len(header_bytes), sha256=codec.sha(header_bytes)),
                    provider=dict(path=str(provider), mapped_native_path=bytes.fromhex(
                        head["mapped_provider_utf16"]).decode("utf-16-le"),
                        before_sha256=before, after_sha256=after))
    write_json(output / (label + "-report.json"), metadata)
    codec.require(build.resolve().is_relative_to(output), "native build cleanup containment")
    shutil.rmtree(build)
    return metadata, stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-query-multiple-values-v1")
    args = parser.parse_args()
    hashes = codec.verify_sources()
    if args.verify_corpus:
        print(json.dumps(dict(verified_inputs=len(hashes), process_abis=3,
                              native_records=148956, overflow_records=123)))
        return 0
    codec.require(sys.platform == "win32", "native capture requires Windows")
    output = (codec.ROOT / args.output).resolve()
    codec.require(output != codec.ROOT and output.is_relative_to(codec.ROOT) and not output.exists(),
                  "output must be new and inside the checkout")
    output.mkdir(parents=True)
    (output / ".owner").write_bytes(b"native-query-multiple-values-ci-v1\n")
    temporary = output / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               SystemTemp=str(temporary), CCACHE_DISABLE="1", SCCACHE_DISABLE="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="", PYTHONDONTWRITEBYTECODE="1")
    target = (codec.ROOT / env.get("CARGO_TARGET_DIR", "target")).resolve()
    codec.require(target.is_relative_to(codec.ROOT), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    env.pop("RAX_NATIVE_QUERY_MULTIPLE_VALUE_KEY_CORPUS", None)
    env.pop("RAX_NATIVE_QUERY_MULTIPLE_VALUE_KEY_OVERFLOW_CORPUS", None)
    native = native_machine()
    architectures = [("x64", "x64"), ("x86", "Win32")]
    if native == 0xAA64:
        architectures.insert(0, ("arm64", "ARM64"))
    records = [capture(label, arch, native, output, env) for label, arch in architectures]
    overflow_output = output / "overflow"
    overflow_output.mkdir()
    (overflow_output / ".owner").write_bytes(b"native-query-multiple-values-overflow-ci-v1\n")
    overflow_records = [capture(label, arch, native, overflow_output, env, overflow=True)
                        for label, arch in architectures]
    overflow_corpus = codec.overflow.pack(overflow_records, codec.MACHINES)
    overflow_destination = overflow_output / "observations.json"
    write_json(overflow_destination, overflow_corpus)
    codec.require(codec.overflow.verify_sources(codec.MACHINES) == 123, "overflow sources changed")
    codec.require(all(codec.sha((codec.SOURCE / name).read_bytes()) == digest
                      for name, digest in hashes.items()), "native producer inputs changed")
    corpus = codec.pack(records)
    destination = output / "observations.json"
    write_json(destination, corpus)
    env["RAX_NATIVE_QUERY_MULTIPLE_VALUE_KEY_CORPUS"] = str(destination)
    env["RAX_NATIVE_QUERY_MULTIPLE_VALUE_KEY_OVERFLOW_CORPUS"] = str(overflow_destination)
    log = output / "replay.log"
    try:
        run(["cargo", "test", "--locked", "--no-default-features", "--lib",
             "native_query_multiple_value_key", "--", "--test-threads=1", "--nocapture"], env, log)
        summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
                               log.read_text(encoding="utf-8", errors="replace"))
        codec.require(summaries and tuple(map(int, summaries[-1])) == (4, 0, 0),
                      "incomplete native query replay selection")
    finally:
        if log.exists():
            print(log.read_text(encoding="utf-8", errors="replace"), flush=True)
    for metadata, raw in records:
        codec.require(codec.sha((output / (metadata["architecture"] + ".jsonl")).read_bytes()) == codec.sha(raw),
                      "native corpus changed during replay")
    for metadata, raw in overflow_records:
        codec.require(codec.sha((overflow_output / (metadata["architecture"] + ".jsonl")).read_bytes()) == codec.sha(raw),
                      "overflow corpus changed during replay")
    shutil.rmtree(temporary)
    print(json.dumps(dict(corpus=str(destination), process_abis=len(records),
                          native_records=corpus["native_calls"], sha256=codec.sha(destination.read_bytes()),
                          overflow_records=overflow_corpus["native_calls"],
                          overflow_sha256=codec.sha(overflow_destination.read_bytes()))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
