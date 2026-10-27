"""Project raw native CSR observations without replacing pointer or status bytes."""

import base64
import hashlib
import json
from pathlib import Path
import re
import sys


def fields(line):
    values = {}
    for word in line.split()[1:]:
        if "=" in word:
            key, value = word.split("=", 1)
            if key in values:
                raise ValueError("Duplicate observation field")
            values[key] = value
    return values


def data_row(line):
    row = fields(line)
    if row.get("not-read") == "1":
        return {"protect": int(row["protected"], 16), "read": False}
    wanted, got = int(row["bytes"]), int(row["got"])
    raw = bytes.fromhex(row["hex"])
    if not 0 <= got <= wanted <= 1024 or len(raw) != got:
        raise ValueError("Invalid native data extent")
    return {"read": row["ok"] == "1", "bytes": wanted, "got": got, "hex": raw.hex()}


def project_sample(sample):
    stdout = base64.b64decode(sample["stdout_b64"], validate=True)
    if hashlib.sha256(stdout).hexdigest() != sample["stdout_sha256"]:
        raise ValueError("Native stdout identity mismatch")
    if sample["exit_code"] != 0:
        raise ValueError("Native observation failed")
    lines = stdout.decode("utf-8").splitlines()
    terminal = lines[-1] if lines else ""
    match = re.fullmatch(
        r"DONE installed=1 entered=(\d+) returned=(\d+) base-calls=(\d+) pending=0 exit=70",
        terminal,
    )
    expected = 2 if sample["mode"].startswith("retry-") else 1
    if (
        not match
        or int(match[1]) != expected
        or int(match[2]) != expected
        or not 1 <= int(match[3]) <= expected
    ):
        raise ValueError("Incomplete native terminal state")
    if sample["terminal"] != terminal:
        raise ValueError("Native terminal identity mismatch")
    before, steps = {}, []
    current = None
    for line in lines:
        if line.startswith("RETURN "):
            row = fields(line)
            if int(row["ordinal"]) != len(steps):
                raise ValueError("Native return ordinal mismatch")
            current = {
                "ordinal": len(steps),
                "status": row["status"],
                "data": {},
                "new_mappings": [],
                "peb_changes": [],
                "new_handles": [],
            }
            if not re.fullmatch("[0-9A-F]{8}", current["status"]):
                raise ValueError("Invalid native status")
            steps.append(current)
        elif line.startswith("DATA "):
            label = fields(line)["label"]
            if label.startswith("before-") and not steps:
                before[label.removeprefix("before-")] = data_row(line)
            elif label.startswith("after-") and current is not None:
                current["data"][label.removeprefix("after-")] = data_row(line)
        elif current is not None and line.startswith("PEB_DELTA "):
            row = fields(line)
            if "handles_before" in current:
                raise ValueError("Duplicate native PEB delta")
            old, new = map(int, row["handles"].split(":"))
            if new < old or (int(row["bytes64"]), int(row["bytes32"])) != (2048, 1280):
                raise ValueError("Invalid native resource delta")
            current.update(
                handles_before=old,
                handles_after=new,
                changed64=int(row["changed64"]),
                changed32=int(row["changed32"]),
            )
        elif current is not None and line.startswith("MAPPED_NEW "):
            row = fields(line)
            base, allocation = int(row["base"], 16), int(row["allocation"], 16)
            size, state = int(row["bytes"]), int(row["state"], 16)
            if (
                base < allocation
                or size <= 0
                or size % 4096
                or base - allocation + size > 1 << 20
                or state not in (0x1000, 0x2000)
            ):
                raise ValueError("Invalid native mapped region")
            current["new_mappings"].append(
                {
                    "base": base,
                    "allocation": allocation,
                    "bytes": size,
                    "state": state,
                    "protect": int(row["protect"], 16),
                    "type": int(row["type"], 16),
                }
            )
        elif current is not None and line.startswith("PEB_CHANGE "):
            row = fields(line)
            width, offset = int(row["width"]), int(row["offset"])
            if width not in (32, 64) or not 0 <= offset < (
                2048 if width == 64 else 1280
            ):
                raise ValueError("Invalid native PEB change extent")
            old, new = int(row["before"], 16), int(row["after"], 16)
            if not 0 <= old <= 255 or not 0 <= new <= 255 or old == new:
                raise ValueError("Invalid native PEB changed byte")
            current["peb_changes"].append(
                {"width": width, "offset": offset, "before": old, "after": new}
            )
        elif current is not None and line.startswith("HANDLE_NEW "):
            row = fields(line)
            current["new_handles"].append(
                {"access": int(row["access"], 16), "type": row.get("type"), "raw": line}
            )
    if len(steps) != expected:
        raise ValueError("Missing native return")
    for step in steps:
        if "handles_before" not in step:
            raise ValueError("Missing native PEB/resource delta")
        for width in (32, 64):
            changes = [row for row in step["peb_changes"] if row["width"] == width]
            if len(changes) != step["changed" + str(width)] or len(
                {row["offset"] for row in changes}
            ) != len(changes):
                raise ValueError("Native PEB change count mismatch")
        if len(step["new_handles"]) != step["handles_after"] - step["handles_before"]:
            raise ValueError("Native handle count mismatch")
    return {
        "mode": sample["mode"],
        "source": sample["source"],
        "before": before,
        "steps": steps,
        "stdout_sha256": sample["stdout_sha256"],
        "terminal": terminal,
    }


def project(report):
    if (
        report["schema"] != "native-wow64-csr-amd64-matrix-v1"
        or report["state"] != "finished"
        or report["exit_code"] != 0
    ):
        raise ValueError("Incomplete native report")
    if (
        report["kernel"][:2] != [10, 0]
        or report["kernel"][2] not in (20348, 26100)
        or report["machine"] != "AMD64"
    ):
        raise ValueError("Foreign native kernel or machine")
    if not report["inputs_unchanged"] or not report["build_outputs_removed"]:
        raise ValueError("Native source or lifecycle proof missing")
    if len(report["compilations"]) != 3 or any(
        row["exit_code"] != 0 for row in report["compilations"]
    ):
        raise ValueError("Incomplete native compilation")
    if (
        len(report["samples"]) != 31
        or len({row["mode"] for row in report["samples"]}) != 31
    ):
        raise ValueError("Incomplete native case matrix")
    expected_machines = {
        "child": 0x14C,
        "initial-v8.cpp": 0x8664,
        "initial-v9.cpp": 0x8664,
    }
    if set(report["binaries"]) != set(expected_machines) or any(
        report["binaries"][name]["machine"] != machine
        for name, machine in expected_machines.items()
    ):
        raise ValueError("Foreign compiled PE machine")
    samples = [project_sample(row) for row in report["samples"]]
    if sum(len(row["steps"]) for row in samples) != 38:
        raise ValueError("Incomplete native return matrix")
    return {
        "kernel": report["kernel"][:3],
        "native_machine": 0x8664,
        "case_count": 31,
        "return_count": 38,
        "samples": samples,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: project-matrix-v1.py RAW_JSON OUTPUT_JSON")
    result = project(json.loads(Path(sys.argv[1]).read_bytes()))
    with Path(sys.argv[2]).open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2)
        out.write("\n")
