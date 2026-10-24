#!/usr/bin/env python3
"""Run clock and CPU-boundary regressions before unrelated process profiles."""

from pathlib import Path
import os
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    target = (root / "target").resolve()
    if not target.is_relative_to(root):
        raise RuntimeError("clock validation requires in-worktree temporary storage")
    target.mkdir(exist_ok=True)
    environment = dict(os.environ)
    for name in (
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CCACHE_DIR",
        "SCCACHE_DIR",
    ):
        environment.pop(name, None)
    output = (root / environment.get("CARGO_TARGET_DIR", "target")).resolve()
    if not output.is_relative_to(root):
        raise RuntimeError("clock validation requires an in-worktree Cargo target")
    environment.update(CCACHE_DISABLE="1", SCCACHE_DISABLE="1")
    with tempfile.TemporaryDirectory(
        prefix="clock-validation-", dir=target
    ) as temporary:
        environment.update(TMPDIR=temporary, TMP=temporary, TEMP=temporary)
        for pattern in (
            "shared_time",
            "system_time",
            "a64_observation",
            "a64_exclusive_monitor",
            "windows_instruction_budget",
        ):
            command = [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--lib",
                pattern,
                "--",
                "--test-threads=1",
                "--nocapture",
            ]
            print("+ " + " ".join(command), flush=True)
            try:
                subprocess.run(command, cwd=root, env=environment, check=True)
            except subprocess.CalledProcessError as error:
                return error.returncode or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
