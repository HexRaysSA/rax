#!/usr/bin/env python3
"""Run portable process regressions, preserving the first failing exit status.

A single native command lets every CI shell propagate failure, including
PowerShell where a later successful cargo invocation can replace LASTEXITCODE.
"""
import subprocess

TARGETS = (
    ("--lib", "user::windows::process"),
    ("--test", "user_windows_memory"),
    ("--lib", "user::mm::"),
    ("--lib", "user::linux::"),
    ("--lib", "user::darwin::"),
    ("--lib", "user::readiness::"),
    ("--lib", "user::clock::"),
    ("--lib", "user::console"),
    ("--lib", "user::supplied_fs::"),
    ("--lib", "captured_"),
    ("--lib", "closed_"),
)


def main():
    for target in TARGETS:
        command = ["cargo", "test", "--locked", "--no-default-features", *target]
        print("+ " + " ".join(command), flush=True)
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as error:
            return error.returncode or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
