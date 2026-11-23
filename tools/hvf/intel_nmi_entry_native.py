#!/usr/bin/env python3
"""Build the signed SDK-only event-admission control and record its results."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import plistlib
import subprocess
from tempfile import TemporaryDirectory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compile-only", action="store_true")
    control = parser.add_mutually_exclusive_group()
    control.add_argument("--irq-vectoring", action="store_true",
                         help="run the interrupted external interrupt control")
    control.add_argument("--cr0-ne", action="store_true",
                         help="observe independent CR0.NE backing and guest read shadow")
    args = parser.parse_args()
    args.output.mkdir()
    source = Path(__file__).resolve().with_suffix(".c")
    result = {"compile_only": args.compile_only, "observations": {}, "success": False}
    result["source_sha256"] = {
        name: sha256(source.with_name(name).read_bytes()).hexdigest()
        for name in (source.name, "intel_ram_entry_native.c", "native_intel_availability.c")
    }
    try:
        with TemporaryDirectory(prefix="rax-intel-hvf-nmi-sdk-",
                                dir=os.environ.get("RUNNER_TEMP")) as directory:
            root = Path(directory)
            probe = root / "probe"
            entitlements = root / "hvf.plist"
            entitlements.write_bytes(plistlib.dumps({"com.apple.security.hypervisor": True}))
            subprocess.run(
                ["xcrun", "--sdk", "macosx", "clang", "-arch", "x86_64", "-std=c11",
                 "-O1", "-Wall", "-Wextra", "-Werror", str(source), "-framework", "Hypervisor",
                 "-o", str(probe)], check=True, timeout=60)
            subprocess.run(
                ["codesign", "--force", "--sign", "-", "--entitlements", str(entitlements),
                 "--timestamp=none", str(probe)], check=True, timeout=60)
            subprocess.run(["codesign", "--verify", "--strict", str(probe)], check=True, timeout=60)
            executable = probe.read_bytes()
            result["executable_sha256"] = sha256(executable).hexdigest()
            if not args.compile_only:
                if args.irq_vectoring or args.cr0_ne:
                    (args.output / "signed-probe").write_bytes(executable)
                if args.irq_vectoring:
                    events = ("irq-vectoring",)
                elif args.cr0_ne:
                    events = ("cr0-ne",)
                else:
                    events = ("none", "irq", "nmi", "nmi-with-if", "nmi-without-virtual-blocking")
                for event in events:
                    entry = subprocess.run([str(probe), event], capture_output=True, text=True,
                                           timeout=15)
                    row = {
                        "exit_code": entry.returncode,
                        "stdout": entry.stdout,
                        "stderr": entry.stderr,
                    }
                    result["observations"][event] = row
                for event, row in result["observations"].items():
                    lines = row["stdout"].splitlines()
                    if row["exit_code"] or len(lines) != 2:
                        raise RuntimeError(f"SDK observation lacked its control: {event}")
                    host, observation = map(json.loads, lines)
                    if observation["event"] != event:
                        raise RuntimeError(f"SDK observation used the wrong event: {event}")
                    row["host"] = host
                    row["observation"] = observation
        result["success"] = True
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    finally:
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return int(not result["success"])


if __name__ == "__main__":
    raise SystemExit(main())
