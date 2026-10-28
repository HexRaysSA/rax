#!/usr/bin/env python3
"""Refresh two historical conversion expectations from qualified primary/oracle input.

This is a focused correction, not a full ARM corpus regeneration entry point.
The historical generator input/revision remain unknown.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "docs/development/a64-half-admission/legacy-conversion-correction.json"
MANIFEST = ROOT / "tests/generated/manifest.toml"


def qualified_input():
    record = json.loads(INPUT.read_text())
    primary = ROOT / record["primary_source"]
    if hashlib.sha256(primary.read_bytes()).hexdigest() != record["primary_sha256"]:
        raise ValueError("unqualified primary source")
    word = int(record["word"], 16)
    if word != 0x1e070000 or record["expected"] != "Undefined":
        raise ValueError("unqualified conversion correction")
    # The pinned fixed-point conversion decode rejects W forms with scale[5]=0.
    if word >> 31 != 0 or word & (1 << 15) != 0:
        raise ValueError("correction no longer describes the reserved W scale")
    profiles = set()
    for case in record["oracle_cases"]:
        if case["code"] != 0 or case["actual"] != "100I":
            raise ValueError("independent oracle did not report precise Undefined")
        profiles.add((case["el"], case["fpen"], case["model"]))
    expected = {(el, fpen, model) for el in (0, 1) for fpen in (0, 3)
                for model in ("cortex-a53", "cortex-a710")}
    if len(record["oracle_cases"]) != 8 or profiles != expected:
        raise ValueError("incomplete independent oracle profiles")
    return record


def corrected_source(record):
    output = ROOT / record["output"]
    source = output.read_text()
    for name in record["tests"]:
        pattern = rf"(?ms)^fn {re.escape(name)}\(\) \{{.*?^\}}"
        matches = list(re.finditer(pattern, source))
        if len(matches) != 1:
            raise ValueError(f"missing or duplicate historical case: {name}")
        match = matches[0]
        body = match.group()
        if "let encoding: u32 = 0x1E070000;" not in body:
            raise ValueError(f"historical encoding changed: {name}")
        old = '''!matches!(exit, Ok(CpuExit::Undefined(_)))
            && !matches!(exit, Err(ArmError::UndefinedInstruction(_))),
        "expected allocated encoding'''
        new = '''matches!(exit, Ok(CpuExit::Undefined(_)))
            || matches!(exit, Err(ArmError::UndefinedInstruction(_))),
        "expected unallocated encoding'''
        if old in body:
            body = body.replace(old, new, 1)
        elif new not in body:
            raise ValueError(f"unexpected historical assertion: {name}")
        source = source[:match.start()] + body + source[match.end():]
    return output, source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    record = qualified_input()
    output, expected = corrected_source(record)
    digest = hashlib.sha256(expected.encode()).hexdigest()
    if args.write:
        output.write_text(expected)
    elif output.read_text() != expected:
        raise ValueError("stale historical conversion expectations; use --write")
    manifest = MANIFEST.read_text()
    entry = f'conversion_correction_sha256 = "{digest}"'
    key = r'(?m)^conversion_correction_sha256 = "[0-9a-f]+"$'
    if not re.search(key, manifest):
        raise ValueError("missing focused correction in corpus manifest")
    if args.write:
        MANIFEST.write_text(re.sub(key, entry, manifest))
    elif entry not in manifest:
        raise ValueError("stale focused correction hash")
    print(json.dumps(dict(tests=len(record["tests"]), oracle_cases=8,
                          output=record["output"], sha256=digest)))


if __name__ == "__main__":
    main()
