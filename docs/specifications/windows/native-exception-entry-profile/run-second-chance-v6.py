#!/usr/bin/env python3
"""Check the three original cases against qualified native kernel/view results."""

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "second_chance_observer_v5", Path(__file__).with_name("run-second-chance-v5.py")
)
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
OBSERVE = BASE.validate
BASE.MODES = ("last", "invalid-record", "invalid-context")


def expected_status(mode, arch, host):
    BASE.require(
        (host["build"], host["native_machine"])
        in ((20348, 0x8664), (26100, 0x8664), (29683, 0xAA64)),
        "unqualified second-chance kernel profile",
    )
    BASE.require(
        arch in ("x64", "x86") or host["native_machine"] == 0xAA64,
        "unqualified executable view for this native kernel",
    )
    if mode == "last":
        return None
    return (
        0x80000002
        if mode == "invalid-context"
        and arch == "x86"
        and host["build"] == 26100
        and host["native_machine"] == 0x8664
        else 0xC0000005
    )


def validate(mode, exit_code, rows, arch):
    OBSERVE(mode, exit_code, rows, arch)
    status = expected_status(mode, arch, rows[0])
    if status is None:
        BASE.require(
            exit_code & 0xFFFFFFFF == BASE.EXCEPTION and len(rows) == 1,
            "qualified second-chance termination",
        )
    else:
        BASE.require(
            exit_code == 0 and len(rows) == 2 and rows[1]["status"] == status,
            "qualified argument-copy failure",
        )


BASE.validate = validate

if __name__ == "__main__":
    BASE.main()
