"""Rebuild and replay recorded native campaigns in an owned in-tree directory.

The original acquisitions predate this runner. Their stored argument vectors
are the campaign templates; fresh outputs never replace the original records.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


CAMPAIGNS = {
    "edge": (3, 296, []),
    "fdinfo": (4, 32, ["-lproc"]),
    "spawn": (5, 32, []),
    "inherit": (6, 8, ["-lproc"]),
    "devfd": (7, 198, []),
    "devfd-directory": (8, 6, []),
    "devfd-alias": (9, 48, []),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def observations(case):
    if "stdout" in case:
        return [json.loads(line) for line in case["stdout"].splitlines()]
    if "records" in case:
        return case["records"]
    return [case["record"]]


def projection(records):
    # Exception packet delivery under Rosetta is independently recorded; its
    # absence does not establish an exception code and is not a syscall result.
    return [row for row in records
            if row["kind"] not in ("guard-exception", "guard-reply")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True,
                        help="Fresh directory below this checkout's target/")
    parser.add_argument("--campaign", choices=CAMPAIGNS, action="append")
    options = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Native acquisition requires macOS; use verify-extended-v3.py elsewhere")
    base = Path(__file__).resolve().parent
    root = base.parents[3]
    output = (root / options.output).resolve()
    if (root / "target").resolve() not in output.parents:
        parser.error("--output must resolve below this checkout's target/")
    output.mkdir(parents=True, exist_ok=False)
    (output / ".owner").write_text("native-guarded-extended-capture-v3\n")
    (output / "tmp").mkdir()
    environment = dict(os.environ)
    environment.update({key: str(output / "tmp")
                        for key in ("TMPDIR", "TMP", "TEMP")})
    compiler = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
    sdk = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
    receipt = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": platform.uname()._asdict(), "compiler": compiler, "sdk": sdk,
        "compiler_version": subprocess.check_output([compiler, "--version"], text=True),
        "sdk_version": subprocess.check_output(["xcrun", "--show-sdk-version"], text=True).strip(),
        "campaigns": [], "state": "running", "mismatches": [],
        "scope": "Fresh native controls; this runner does not execute the emulator.",
    }
    save(output / "receipt.json", receipt)
    for name in options.campaign or list(CAMPAIGNS):
        version, count, libraries = CAMPAIGNS[name]
        source = base / (name + "-probe-v" + str(version) + ".c")
        recorded = json.loads((base / (name + "-receipt-v" + str(version) + ".json")).read_text())
        if "inputs" in recorded:
            inputs = {relative: digest(root / relative) for relative in recorded["inputs"]}
            assert inputs == recorded["inputs"], (name, "producer inputs changed")
        else:
            assert digest(source) == recorded["source_sha256"]
            inputs = {str(path.relative_to(root)): digest(path)
                      for path in (source, base / "policy-probe-v2.c", base / "references/guarded.h")}
        for arch in ("arm64", "x86_64"):
            templates = base / (name + "-records-" + arch + "-v" + str(version) + ".json")
            cases = json.loads(templates.read_text())
            assert len(cases) == count
            directory = output / (name + "-" + arch)
            directory.mkdir()
            image = directory / Path(cases[0]["argv"][0]).name
            arguments = [compiler, "-isysroot", sdk, "-arch", arch, "-std=c11",
                         "-O0", "-Wall", "-Wextra", str(source), *libraries, "-o", str(image)]
            with (directory / "build.log").open("w") as log:
                subprocess.run(arguments, env=environment, stdout=log,
                               stderr=subprocess.STDOUT, check=True)
            capture = {"name": name, "architecture": arch, "version": version,
                       "inputs": inputs, "template_sha256": digest(templates),
                       "build_argv": arguments, "image_sha256": digest(image),
                       "completed_cases": 0}
            receipt["campaigns"].append(capture)
            results = []
            records_path = directory / "records.json"
            for index, case in enumerate(cases):
                old_directory = Path(case["argv"][0]).parent
                argv = [str(image)]
                for argument in case["argv"][1:]:
                    path = Path(argument)
                    if path.is_absolute() and old_directory in path.parents:
                        argument = str(directory / path.relative_to(old_directory))
                    argv.append(argument)
                started = time.monotonic()
                result = dict(case)
                for field in ("stdout", "records", "record", "stderr", "seconds"):
                    result.pop(field, None)
                result["argv"] = argv
                try:
                    native = subprocess.run(argv, env=environment, capture_output=True,
                                            text=True, timeout=30)
                    rows = [json.loads(line) for line in native.stdout.splitlines()]
                    result.update(exit_code=native.returncode, stderr=native.stderr)
                    if "stdout" in case:
                        result["stdout"] = native.stdout
                    elif "records" in case:
                        result["records"] = rows
                    else:
                        result["record"] = rows[0] if len(rows) == 1 else None
                    equal = (native.returncode == case["exit_code"] and
                             projection(rows) == projection(observations(case)))
                    result["matches_frozen_operation_results"] = equal
                    if not equal:
                        receipt["mismatches"].append([name, arch, index])
                except subprocess.TimeoutExpired:
                    result.update(timed_out_seconds=30, exit_code=None)
                    receipt["mismatches"].append([name, arch, index, "timeout"])
                result["seconds"] = time.monotonic() - started
                results.append(result)
                capture["completed_cases"] = len(results)
                save(records_path, results)
                save(output / "receipt.json", receipt)
            capture["records_sha256"] = digest(records_path)
            capture["inputs_unchanged"] = all(digest(root / path) == value
                                               for path, value in inputs.items())
            assert capture["inputs_unchanged"]
    receipt.update(state="finished", exit_code=int(bool(receipt["mismatches"])))
    save(output / "receipt.json", receipt)
    print(json.dumps({"campaigns": len(receipt["campaigns"]),
                      "cases": sum(row["completed_cases"] for row in receipt["campaigns"]),
                      "mismatches": receipt["mismatches"], "receipt": str(output / "receipt.json")}))
    return receipt["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
