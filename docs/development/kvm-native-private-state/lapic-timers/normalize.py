#!/usr/bin/env python3
"""Replay the bounded x2APIC expired one-shot restoration experiment."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    source = root / "lapic-expired-normalize-v2.c"
    records = []
    with tempfile.TemporaryDirectory(prefix="rax-lapic-normalize-") as scratch:
        binary = Path(scratch) / "control"
        command = [
            "gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2",
            "-pthread", str(source), "-o", str(binary),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        for case in ["settled", "pending"]:
            for mode in ["raw", "normalize"]:
                for trial in range(10):
                    result = subprocess.run(
                        [str(binary), case, mode], capture_output=True,
                        text=True, timeout=5,
                    )
                    assert result.returncode == 0, (result.stdout, result.stderr)
                    value = json.loads(result.stdout)
                    assert value["pending_case"] == (case == "pending"), value
                    assert value["normalized"] == (mode == "normalize"), value
                    expected = int(case == "pending" or mode == "raw")
                    assert value["target_delivery"] == expected, value
                    assert value["source_delivery"] == int(case == "pending"), value
                    assert value["source_extra"] == 0, value
                    assert value["saved_current_count"] == 0, value
                    assert value["saved_initial_count"] == 1_000_000, value
                    assert value["restored_initial_count"] == 1_000_000, value
                    for key in [
                        "registers_equal", "special_equal", "events_equal",
                        "mp_equal", "memory_equal", "source_destroyed_before_restore",
                    ]:
                        assert value[key] is True, (key, value)
                    if mode == "normalize":
                        assert value["lapic_equal"] is True, value
                        assert value["fake_nmi_pending"] == 1, value
                        assert value["target_extra"] == 0, value
                    records.append({
                        "case": case, "mode": mode, "trial": trial,
                        "observation": value,
                    })
    print(json.dumps({
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "kernel": platform.release(), "build_argv": command,
        "passed": len(records), "trials": records,
        "temporary_binaries_removed": True, "production_enabled": False,
    }, indent=2))


if __name__ == "__main__":
    main()
