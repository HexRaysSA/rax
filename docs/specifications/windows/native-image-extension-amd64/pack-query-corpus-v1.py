"""Preserve verified raw native stdout as UTF-8 inside a compressed replay corpus."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

SOURCES = {
    20348: (
        12773810183,
        "c9d5275bf8a8bddffd74e5f0d63457460688d8e8c601cb6ee1033fa9deb1e9b8",
        "9f9b75ac860efb286489b82b4a00f6c9e29a916fd18be55e73f3b5e3d2c1fcf3",
    ),
    26100: (
        12772358752,
        "1a4bd859d86ee0038fc2292148695163d513113d7c45cf5d2e3d442dc2acc547",
        "4d305bbbb579117a5404a64ffa56b6cd7676aca6c677548b08c38c600e1bea78",
    ),
}
COUNTS = {"query": 4200, "boundaries": 15480, "limits": 1092}


def project(paths):
    profiles = []
    builds = []
    for path in paths:
        raw = Path(path).read_bytes()
        capture = json.loads(raw)
        if (
            capture["schema"] != "native-image-extension-amd64-query-matrix-v2"
            or capture["state"] != "finished"
            or capture["exit_code"] != 0
            or capture["kernel"][:2] != [10, 0]
            or capture["machine"] != "AMD64"
        ):
            raise ValueError("Incomplete or foreign native capture")
        build = capture["kernel"][2]
        artifact, digest, expected_json = SOURCES[build]
        if hashlib.sha256(raw).hexdigest() != expected_json:
            raise ValueError("Raw captured JSON digest mismatch")
        builds.append(build)
        axes = []
        for sample in capture["samples"]:
            arch, kind = sample["arch"], sample["kind"]
            axes.append((arch, kind))
            if (
                sample["compile"]["exit_code"] != 0
                or sample["observation"]["exit_code"] != 0
                or sample["inputs_unchanged"] is not True
            ):
                raise ValueError("Native producer did not finish with stable inputs")
            observation = sample["observation"]
            stdout = base64.b64decode(observation["stdout_b64"], validate=True)
            if hashlib.sha256(stdout).hexdigest() != observation["stdout_sha256"]:
                raise ValueError("Raw stdout digest mismatch")
            text = stdout.decode("ascii", errors="strict")
            rows = [line for line in text.splitlines() if line.startswith("case=")]
            count = COUNTS[kind]
            if len(rows) != count:
                raise ValueError("Native case partition is incomplete")
            for ordinal, line in enumerate(rows):
                fields = dict(
                    part.split("=", 1) for part in line.split() if "=" in part
                )
                if int(fields["case"]) != ordinal or int(fields["exception"], 16) != 0:
                    raise ValueError("Native ordinal or exception differs")
            footer = dict(
                part.split("=", 1)
                for part in text.splitlines()[-1].split()
                if "=" in part
            )
            if int(footer["cases"]) != count:
                raise ValueError("Native terminal case count differs")
            if kind != "query" and footer["handles-before"] != footer["handles-after"]:
                raise ValueError("Native handle count was not restored")
            expected_pointer = 8 if arch == "x64" else 4
            if f"host pointer={expected_pointer} " not in text.splitlines()[0]:
                raise ValueError("Executed process ABI differs")
            del observation["stdout_b64"]
            observation["stdout"] = text
        expected = [(arch, kind) for arch in ("x64", "x86") for kind in COUNTS]
        if axes != expected:
            raise ValueError("Native architecture/family inventory differs")
        profiles.append(
            {
                "artifact_id": artifact,
                "archive_sha256": digest,
                "raw_json_sha256": hashlib.sha256(raw).hexdigest(),
                "capture": capture,
            }
        )
    if builds != [20348, 26100]:
        raise ValueError("Both independent native kernels are required in order")
    return {
        "schema": "native-image-extension-amd64-query-corpus-v1",
        "source_run": 40589099085,
        "source_commit": "c346c980dafae6f6f89fd308204a8a8ddf7da4bf",
        "profiles": profiles,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs=2, type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    data = json.dumps(project(arguments.inputs), separators=(",", ":")).encode()
    compressed = subprocess.run(
        ["zstd", "-q", "-19", "-c"], input=data, capture_output=True, check=True
    ).stdout
    with arguments.output.open("xb") as stream:
        stream.write(compressed)
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "decoded_bytes": len(data),
                "encoded_bytes": len(compressed),
                "sha256": hashlib.sha256(compressed).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
