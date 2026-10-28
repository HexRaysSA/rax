"""Record native loaded KERNEL32 paths and installed pure-x86 PE metadata."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


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
    spec = importlib.util.spec_from_file_location(
        "profile", root / "docs/specifications/windows/native-exception-entry-profile/run-v2.py"
    )
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    source = folder / "module-v1.c"
    result = {"pid": os.getpid(), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "build": os.sys.getwindowsversion().build, "cases": [], "state": "running"}
    receipt = output / "receipt.json"
    receipt.write_text(json.dumps(result, indent=2))
    for arch in ["arm64", "x86", "x64"]:
        build = output / arch
        build.mkdir()
        env, compiler = profile.compiler_environment(arch, args.compiler_env, build)
        binary = build / "module.exe"
        with (build / "build.log").open("wb") as log:
            subprocess.run([str(compiler), "/nologo", "/O1", "/MD", str(source),
                            "/Fe:" + str(binary)], cwd=build, env=env,
                           stdout=log, stderr=log, check=True)
        child = subprocess.run([str(binary)], cwd=build, env=env, capture_output=True, timeout=15)
        result["cases"].append({"arch": arch, "exit_code": child.returncode,
                                "stdout": child.stdout.decode("utf-8"),
                                "stderr": child.stderr.decode("utf-8", errors="replace")})
        receipt.write_text(json.dumps(result, indent=2))
    pure = Path(os.environ["SystemRoot"]) / "SysWOW64/kernel32.dll"
    data = pure.read_bytes()
    nt = int.from_bytes(data[60:64], "little")
    result["pure_x86"] = {"path": str(pure), "sha256": hashlib.sha256(data).hexdigest(),
                           "timestamp": int.from_bytes(data[nt + 8:nt + 12], "little"),
                           "image_size": int.from_bytes(data[nt + 80:nt + 84], "little")}
    assert hashlib.sha256(source.read_bytes()).hexdigest() == result["source_sha256"]
    result["state"] = "finished"
    receipt.write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
