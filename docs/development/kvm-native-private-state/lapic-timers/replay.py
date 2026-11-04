#!/usr/bin/env python3
"""Replay native UAPI counterexamples without retaining build directories."""

import json
from pathlib import Path
import subprocess
import tempfile


def observe(source, binary):
    subprocess.run(
        [
            "gcc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        timeout=60,
    )
    observations = []
    for _ in range(5):
        result = subprocess.run(
            [str(binary)], check=True, capture_output=True, text=True, timeout=5
        )
        observations.append(json.loads(result.stdout))
    return observations


def main():
    directory = Path(__file__).resolve().parent
    results = {}
    with tempfile.TemporaryDirectory(prefix="rax-lapic-control-") as temporary:
        for stem in (
            "lapic-expired-pending-control-v1",
            "lapic-settled-phase-control-v4",
        ):
            results[stem] = observe(directory / (stem + ".c"), Path(temporary) / stem)
    for row in results["lapic-expired-pending-control-v1"]:
        assert row["source_destroyed_before_restore"]
        assert row["saved_current_count"] == 0
        assert row["source_delivered"] == row["restored_delivered"] == 1
    for row in results["lapic-settled-phase-control-v4"]:
        assert row["source_destroyed_before_restore"]
        assert row["saved_current_count"] == 0
        assert row["saved_rip"] == 0x2004
        assert row["source_final_rip"] == 0x1002
        assert row["completed_isr"] == 0
        assert row["source_first"] == 1
        assert row["source_extra"] == 0
        assert row["target_extra"] == 1
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
