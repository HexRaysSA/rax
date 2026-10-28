"""Capture NtWriteFile pipe status/IOSB behavior on each Windows guest ABI."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler-env", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parents[3]
    output = args.output.resolve()
    assert output.is_relative_to(root.resolve())
    output.mkdir()
    source = folder / "probe-v2.c"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location(
        "profile", root / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
    )
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    result = {"pid": os.getpid(), "build": os.sys.getwindowsversion().build,
              "source_sha256": digest, "cases": [], "state": "running"}
    receipt = output / "receipt.json"
    receipt.write_text(json.dumps(result, indent=2))
    for arch in ["arm64", "x86", "x64"]:
        build = output / arch
        build.mkdir()
        env, compiler = profile.compiler_environment(arch, args.compiler_env, build)
        binary = build / "probe.exe"
        with (build / "build.log").open("wb") as log:
            subprocess.run([str(compiler), "/nologo", "/O1", "/MD", str(source),
                            "/Fe:" + str(binary)], cwd=build, env=env,
                           stdout=log, stderr=log, check=True)
        for case in range(18):
            start = time.monotonic()
            child = subprocess.run([str(binary), str(case)], cwd=build, env=env,
                                   capture_output=True, timeout=15)
            result["cases"].append({"arch": arch, "case": case, "exit_code": child.returncode,
                                    "stdout_hex": child.stdout.hex(),
                                    "stderr": child.stderr.decode("utf-8", errors="replace"),
                                    "seconds": time.monotonic() - start})
            receipt.write_text(json.dumps(result, indent=2))
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    result["state"] = "finished"
    receipt.write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
