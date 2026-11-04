#!/usr/bin/env python3
"""Replay the bounded native pending-timer capture controls."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def execute(binary, arguments):
    result = subprocess.run(
        [str(binary), *arguments], capture_output=True, text=True, timeout=5
    )
    record = {
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if result.returncode == 0:
        record["observation"] = json.loads(result.stdout)
    return record


def main():
    root = Path(__file__).resolve().parent
    records = {}
    with tempfile.TemporaryDirectory(prefix="rax-lapic-materialize-") as scratch:
        for stem in [
            "lapic-pending-signal-control-v1",
            "lapic-halted-signal-control-v3",
        ]:
            source = root / f"{stem}.c"
            binary = Path(scratch) / stem
            command = [
                "gcc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                "-Werror", "-O2", "-pthread", str(source), "-o", str(binary),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            record = {
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "build_argv": command,
                "runs": [],
            }
            records[stem] = record
            if stem == "lapic-pending-signal-control-v1":
                for _ in range(10):
                    result = execute(binary, [])
                    if result["exit_code"] != 0:
                        assert result["exit_code"] == 1, result
                        assert result["stderr"] == (
                            "materialization failed: regs=1 RAM=1 IRR=0\n"
                        ), result
                    record["runs"].append(result)
                continue
            for guest_if in [0, 1]:
                transitions = 0
                for _ in range(10):
                    result = execute(binary, ["if1"] if guest_if else [])
                    assert result["exit_code"] == 0, result
                    value = result["observation"]
                    assert value["guest_if"] == guest_if, value
                    assert value["saved_current_count"] == 0, value
                    assert value["materialized_irr"] == 2, value
                    for key in [
                        "registers_unchanged", "special_registers_unchanged",
                        "mp_state_unchanged", "ram_unchanged",
                        "source_destroyed_before_restore",
                    ]:
                        assert value[key] is True, (key, value)
                    assert value["source_delivered"] == 1, value
                    assert value["restored_delivered"] == 1, value
                    assert value["saved_vector_irr"] in [0, 2], value
                    transitions += value["saved_vector_irr"] == 0
                    record["runs"].append(result)
                assert transitions > 0, ("No hidden timer exercised", guest_if)
    print(json.dumps({"controls": records, "temporary_binaries_removed": True}, indent=2))


if __name__ == "__main__":
    main()
