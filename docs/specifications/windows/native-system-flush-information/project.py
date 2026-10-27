"""Create the lossless scalar replay from independently verified raw captures."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("flush_verifier", FOLDER / "verify.py")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def project(paths):
    profiles = []
    for path in paths:
        raw = path.read_bytes()
        data = json.loads(raw)
        VERIFIER.verify(data)
        profiles.append(
            {
                "kernel": data["kernel"],
                "source_sha256": data["source_sha256"],
                "source_lf_sha256": data["source_lf_sha256"],
                "driver_sha256": data["driver_sha256"],
                "capture_sha256": hashlib.sha256(raw).hexdigest(),
                "samples": data["samples"],
            }
        )
    result = {
        "schema": 1,
        "observer_commit": "1bd0c3725ccd04d6105f6f0b6fa213714f5863e9",
        "hosted_run": 40461812735,
        "profiles": profiles,
    }
    text = json.dumps(result, indent=2)
    # Only the ten-scalar observation tuples are folded onto one line. This
    # changes presentation while retaining every original byte and verdict.
    text = re.sub(
        r'\[\n(?:\s+(?:"[^"\n]*"|[0-9]+|true|false),?\n){10}\s*\]',
        lambda match: json.dumps(json.loads(match.group(0)), separators=(",", ":")),
        text,
    )
    return text + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("captures", type=Path, nargs="+")
    args = parser.parse_args()
    args.output.write_text(project(args.captures), encoding="utf-8")


if __name__ == "__main__":
    main()
