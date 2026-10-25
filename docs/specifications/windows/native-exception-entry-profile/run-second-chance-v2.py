#!/usr/bin/env python3
"""Preserve bounded failed-child results without changing the native control."""

import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "second_chance_v1", Path(__file__).with_name("run-second-chance-v1.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)
ORIGINAL_VALIDATE = PROFILE.validate


def projected_rows(rows):
    allowed = {
        "ready": ("code",),
        "handler": ("ordinal",),
        "complete": ("seen", "caught", "call_returned", "status", "removed"),
    }
    result = []
    for row in rows[:4]:
        kind = row.get("kind") if isinstance(row, dict) else None
        fields = allowed.get(kind) if isinstance(kind, str) else None
        if fields is None:
            result.append({"kind": "unexpected"})
            continue
        item = {"kind": kind}
        for key in fields:
            value = row.get(key)
            if isinstance(value, bool) or (
                type(value) is int and 0 <= value <= 0xFFFFFFFF
            ):
                item[key] = value
        result.append(item)
    return result


def validate(mode, exit_code, rows):
    try:
        ORIGINAL_VALIDATE(mode, exit_code, rows)
    except RuntimeError:
        print(
            json.dumps(
                {
                    "kind": "failed_case",
                    "mode": mode if mode in PROFILE.MODES else "unknown",
                    "exit_code": exit_code & 0xFFFFFFFF,
                    "records": projected_rows(rows),
                }
            ),
            flush=True,
        )
        raise


def main():
    PROFILE.validate = validate
    try:
        PROFILE.main()
    finally:
        PROFILE.validate = ORIGINAL_VALIDATE


if __name__ == "__main__":
    main()
