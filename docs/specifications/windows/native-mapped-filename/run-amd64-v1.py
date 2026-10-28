"""Run the frozen filename probes on native AMD64 and its WoW64 substrate."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    assert os.name == "nt" and platform.machine().lower() in ("amd64", "x86_64")
    folder = Path(__file__).resolve().parent
    root = folder.parents[3]
    output = root / "target/native-mapped-filename-amd64-v1"
    assert output.resolve().is_relative_to(root.resolve())
    output.mkdir()
    compiler = load("profile", root / "docs/specifications/windows/native-exception-entry-profile/run-v2.py")
    projection = load("projection", folder / "project-v1.py")
    ranges = {1: range(48), 2: range(48, 66), 3: range(66, 77),
              4: range(77, 96), 5: range(96, 124), 6: range(124, 133)}
    for version, cases in ranges.items():
        source = folder / f"probe-v{version}.c"
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        receipt = {"pid": os.getpid(), "build": os.sys.getwindowsversion().build,
                   "source_sha256": source_hash, "binaries": {}, "cases": [], "state": "running"}
        raw_path = output / f"raw-v{version}.json"
        raw_path.write_text(json.dumps(receipt, indent=2))
        for arch in ["x64", "x86"]:
            build = output / f"mapped-filename-observation-v{version}" / arch
            build.mkdir(parents=True)
            env, cl = compiler.compiler_environment(arch, None, build)
            binary = build / "probe.exe"
            with (build / "build.log").open("wb") as log:
                subprocess.run(
                    [str(cl), "/nologo", "/O1", "/MD", str(source), "/Fe:" + str(binary)],
                    cwd=build, env=env, stdout=log, stderr=log, check=True,
                )
            binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
            receipt["binaries"][arch] = binary_hash
            for case in cases:
                result = subprocess.run([str(binary), str(case)], cwd=build, env=env,
                                        capture_output=True, timeout=15)
                row = {"arch": arch, "case": case, "exit_code": result.returncode,
                       "stdout": result.stdout.decode("utf-8", errors="replace"),
                       "stderr": result.stderr.decode("utf-8", errors="replace")}
                if result.returncode == 0:
                    row["observation"] = json.loads(row["stdout"])
                receipt["cases"].append(row)
                raw_path.write_text(json.dumps(receipt, indent=2))
                assert result.returncode == 0, (version, arch, case, result.returncode)
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash
        assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
        receipt["state"] = "finished"
        raw_path.write_text(json.dumps(receipt, indent=2))
        (output / f"observations-v{version}.json").write_text(
            json.dumps(projection.project(receipt), indent=2) + "\n"
        )
        print(f"version {version}: {len(receipt['cases'])} native observations", flush=True)


if __name__ == "__main__":
    main()
