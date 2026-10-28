"""Project raw child receipts without duplicating their parsed JSON stdout."""

import argparse
import hashlib
import json
from pathlib import Path


def project(receipt):
    assert receipt["state"] == "finished"
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    rows = []
    identities = set()
    for row in receipt["cases"]:
        identity = (row["arch"], row["case"])
        assert identity not in identities
        identities.add(identity)
        assert row["exit_code"] == 0 and not row["stderr"]
        assert json.loads(row["stdout"]) == row["observation"]
        assert row["observation"]["case"] == row["case"]
        assert row["observation"]["raised"] == 0
        rows.append({key: row[key] for key in ("arch", "case", "exit_code", "observation")})
    return {
        "format": 1,
        "raw_canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        **{key: receipt[key] for key in ("build", "source_sha256", "binaries", "state")},
        "cases": rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(project(json.loads(args.receipt.read_text())), indent=2) + "\n")


if __name__ == "__main__":
    main()
