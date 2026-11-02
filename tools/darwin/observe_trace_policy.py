#!/usr/bin/env python3
"""Observe native PT_TRACE_ME policy without changing host policy or RAX."""

import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import time
import zipfile


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path("tests/fixtures/user/darwin/src")
CPU_TYPES = {"arm64": 0x0100000C, "x86_64": 0x01000007}
TIMEOUT_SECONDS = 120


def sha256(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            checksum.update(block)
    return checksum.hexdigest()


def contained_output(root, requested):
    root = root.resolve(strict=True)
    output = requested.resolve()
    if output == root or root not in output.parents:
        raise ValueError("output must be inside this repository")
    if requested.is_symlink() or output.exists():
        raise ValueError("output must be a new directory")
    return output


def macho_identity(path, architecture):
    with path.open("rb") as stream:
        header = stream.read(32)
    if len(header) != 32:
        raise ValueError("truncated Mach-O header")
    magic, cpu = struct.unpack("<II", header[:8])
    if magic != 0xFEEDFACF or cpu != CPU_TYPES[architecture]:
        raise ValueError("expected a thin 64-bit Mach-O for " + architecture)
    return {"cpu_type": cpu, "bytes": path.stat().st_size, "sha256": sha256(path)}


def parse_observation(fixture, output):
    if fixture == "ptrace_restrict":
        match = re.fullmatch(
            r"mark=(-?\d+) errno=(\d+) trace=(-?\d+) errno=(\d+) "
            r"before=([0-9a-f]{8}) after=([0-9a-f]{8})\n", output
        )
        if not match:
            raise ValueError("malformed restricted tracing observation")
        mark, mark_errno, trace, trace_errno, before, after = match.groups()
        return {
            "mark": int(mark), "mark_errno": int(mark_errno),
            "trace": int(trace), "trace_errno": int(trace_errno),
            "before": int(before, 16), "after": int(after, 16),
        }
    if fixture != "ptrace_cs_trace":
        raise ValueError("unknown fixture")
    match = re.fullmatch(
        r"parent_before=([0-9a-f]{8}) parent_after=([0-9a-f]{8}) "
        r"child_before=([0-9a-f]{8}) child_after=([0-9a-f]{8})\n"
        r"child_external=(-?\d+) errno=(\d+) flags=([0-9a-f]{8})\n", output
    )
    if not match:
        raise ValueError("malformed signing transition observation")
    fields = match.groups()
    result = dict(zip(
        ["parent_before", "parent_after", "child_before", "child_after"],
        [int(value, 16) for value in fields[:4]],
    ))
    result.update(child_external=int(fields[4]), child_external_errno=int(fields[5]),
                  child_external_flags=int(fields[6], 16))
    return result


def run(argv, scratch, required=False):
    environment = os.environ.copy()
    environment.update(TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch),
                       CCACHE_DISABLE="1", SCCACHE_DISABLE="1")
    started = time.monotonic()
    result = {"argv": [str(arg) for arg in argv]}
    try:
        with subprocess.Popen(
            result["argv"], cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            start_new_session=True,
        ) as child:
            try:
                stdout, stderr = child.communicate(timeout=TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                # Only this probe's process group; never an unrelated host process.
                os.killpg(child.pid, signal.SIGKILL)
                stdout, stderr = child.communicate()
                result["timed_out"] = True
            result.update(exit_code=child.returncode,
                          stdout=stdout.decode("utf-8", errors="replace"),
                          stderr=stderr.decode("utf-8", errors="replace"))
    except OSError as error:
        result["error"] = str(error)
    result["seconds"] = time.monotonic() - started
    if required and (result.get("exit_code") != 0 or result.get("timed_out")):
        raise RuntimeError(json.dumps(result))
    return result


def csr_policy():
    result = {}
    try:
        library = ctypes.CDLL(None, use_errno=True)
        active = library.csr_get_active_config
        active.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
        active.restype = ctypes.c_int
        flags = ctypes.c_uint32()
        ctypes.set_errno(0)
        status = active(ctypes.byref(flags))
        result["active_config"] = {"return_code": status, "errno": ctypes.get_errno(),
                                   "flags": flags.value if status == 0 else None}
        check = library.csr_check
        check.argtypes = [ctypes.c_uint32]
        check.restype = ctypes.c_int
        ctypes.set_errno(0)
        status = check(1 << 2)  # CSR_ALLOW_TASK_FOR_PID; observation, not a policy model.
        result["allow_task_for_pid"] = {"mask": 1 << 2, "return_code": status,
                                        "errno": ctypes.get_errno()}
    except (AttributeError, OSError) as error:
        result["unavailable"] = str(error)
    return result


def collect(output):
    scratch = output / "build"
    scratch.mkdir()
    report = {
        "schema": 1, "state": "collecting", "platform": sys.platform,
        "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "collector_sha256": sha256(Path(__file__)),
        "machine": platform.machine(), "pointer_bits": struct.calcsize("P") * 8,
        "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
        "csr": csr_policy(), "commands": [], "cases": [],
        "interpretation": "Native observations; no inferred mapping from CSR to MACF policy.",
    }
    sources = [FIXTURES / name for name in (
        "ptrace_cs_trace.c", "ptrace_restrict.c", "ptrace_get_task_allow.plist"
    )]
    report["source_hashes"] = {path.as_posix(): sha256(ROOT / path) for path in sources}
    try:
        for argv in [
            ["git", "rev-parse", "HEAD"],
            ["/usr/bin/sw_vers"], ["/usr/bin/uname", "-r"],
            ["/usr/sbin/sysctl", "-n", "kern.version"],
            ["/usr/sbin/sysctl", "-n", "kern.bootargs"],
            ["/usr/sbin/sysctl", "-n", "security.mac.proc_enforce"],
            ["/usr/bin/csrutil", "status"],
            ["/usr/bin/xcrun", "--show-sdk-version"],
            ["/usr/bin/xcrun", "clang", "--version"],
        ]:
            report["commands"].append(run(argv, scratch))
        sdk = run(["/usr/bin/xcrun", "--show-sdk-path"], scratch, required=True)
        report["commands"].append(sdk)
        run(["/usr/bin/arch", "-x86_64", "/usr/bin/true"], scratch, required=True)
        variants = [
            ("ptrace_cs_trace", "linker", [], []),
            ("ptrace_cs_trace", "adhoc", [], []),
            ("ptrace_cs_trace", "runtime", ["--options", "runtime"], []),
            ("ptrace_cs_trace", "entitled", ["--options", "runtime", "--entitlements",
                str(ROOT / sources[2])], []),
            ("ptrace_restrict", "mark", [], []),
            ("ptrace_restrict", "initial", ["--options", "restrict"], ["initial"]),
            ("ptrace_restrict", "entitled_mark", ["--entitlements", str(ROOT / sources[2])], []),
            ("ptrace_restrict", "entitled_initial", ["--options", "restrict", "--entitlements",
                str(ROOT / sources[2])], ["initial"]),
        ]
        for architecture in CPU_TYPES:
            for fixture, variant, signing, arguments in variants:
                binary = scratch / (fixture + "_" + variant + "_" + architecture)
                case = {"architecture": architecture, "fixture": fixture, "variant": variant}
                report["cases"].append(case)
                case["compile"] = run([
                    "/usr/bin/xcrun", "clang", "-isysroot", sdk["stdout"].strip(),
                    "-arch", architecture, "-O1", "-Wall", "-Wno-deprecated-declarations",
                    str(ROOT / FIXTURES / (fixture + ".c")), "-o", str(binary),
                ], scratch, required=True)
                if (fixture == "ptrace_cs_trace" and variant != "linker") or signing:
                    case["sign"] = run([
                        "/usr/bin/codesign", "--force", "--sign", "-", *signing, str(binary)
                    ], scratch, required=True)
                case["image"] = macho_identity(binary, architecture)
                case["signature"] = run(["/usr/bin/codesign", "-d", "--verbose=4", str(binary)], scratch)
                case["native"] = run([str(binary), *arguments], scratch, required=True)
                case["observation"] = parse_observation(fixture, case["native"]["stdout"])
                if sha256(binary) != case["image"]["sha256"]:
                    raise RuntimeError("fixture changed during observation")
        for path, expected in report["source_hashes"].items():
            if sha256(ROOT / path) != expected:
                raise RuntimeError("fixture source changed: " + path)
        report["state"] = "finished"
    except Exception as error:
        report.update(state="failed", error=str(error))
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    archive = output / "observations.zip"
    members = {"report.json": {"bytes": report_path.stat().st_size, "sha256": sha256(report_path)}}
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(report_path, "report.json")
        for source in sources:
            raw = (ROOT / source).read_bytes()
            name = source.as_posix()
            bundle.writestr(name, raw)
            members[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        bundle.writestr("manifest.json", json.dumps(members, indent=2) + "\n")
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise RuntimeError("archive CRC verification failed")
        for name, expected in members.items():
            raw = bundle.read(name)
            if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                raise RuntimeError("archive member verification failed: " + name)
    # All subprocesses were synchronously reaped, including timed-out process groups.
    if scratch.is_symlink() or scratch.resolve().parent != output:
        raise RuntimeError("build directory ownership changed")
    shutil.rmtree(scratch)
    # Keep every policy result visible even when a log reader caps a step's text.
    print(json.dumps({"trace_policy_summary": {
        "state": report["state"], "time_utc": report["time_utc"],
        "collector_sha256": report["collector_sha256"],
        "uid": report["uid"], "euid": report["euid"], "csr": report["csr"],
        "host_commands": report["commands"],
        "cases": [{key: case[key] for key in
                   ["architecture", "fixture", "variant", "image", "observation"]
                   if key in case} for case in report["cases"]],
    }}))
    print(json.dumps(report, indent=2))
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size,
                      "sha256": sha256(archive)}))
    return 0 if report["state"] == "finished" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new in-repository evidence directory")
    args = parser.parse_args(argv)
    if sys.platform != "darwin":
        print(json.dumps({"state": "unavailable", "reason": "requires native macOS csops/ptrace",
                          "platform": sys.platform}))
        return 2
    output = contained_output(ROOT, args.output)
    output.mkdir(parents=True)
    return collect(output)


if __name__ == "__main__":
    raise SystemExit(main())
