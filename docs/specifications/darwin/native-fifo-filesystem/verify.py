#!/usr/bin/env python3
"""Check the paired native filesystem controls and unchanged model receipts."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def passed(row, count):
    assert row["exit_code"] == 0
    assert f"{count} passed; 0 failed; 0 ignored;" in row["stdout"]


def main():
    binding = load("bindings-v1.json")
    assert len(binding["files"]) == 10
    for name, expected in binding["files"].items():
        assert Path(name).name == name
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    assert binding["source_changes_for_resolution"] is False
    shared, tmpfs = load("native-shared-v1.json"), load("native-tmpfs-v1.json")
    assert shared["system"][0] == tmpfs["system"][0] == "Linux"
    assert shared["system"][2] == tmpfs["system"][2]
    assert shared["container_architecture"] == tmpfs["container_architecture"] == "amd64"
    assert shared["docker_daemon_architecture"] == tmpfs["docker_daemon_architecture"] == "aarch64"
    for receipt in (shared, tmpfs):
        assert len(receipt["records"]) == 4
        rows = {row["kind"]: row for row in receipt["records"]}
        for kind in ("anonymous-reader", "anonymous-writer"):
            assert rows[kind]["fstatfs_result"] == 0
            assert rows[kind]["fs_magic"] == "0x50495045"
            assert rows[kind]["proc_fd"].startswith("pipe:[")
        assert rows["named-linked"]["stat"]["links"] == 1
        assert int(rows["named-linked"]["stat"]["mode"], 8) & 0o170000 == 0o010000
        assert rows["named-unlinked"]["flags"] == rows["named-linked"]["flags"]
        assert rows["named-unlinked"]["proc_fd"].endswith(" (deleted)")
    bad = shared["records"][1]
    assert shared["records"][0]["fs_magic"] == "0x65735546"
    assert bad["kind"] == "named-unlinked" and bad["fstatfs_result"] == -1
    assert bad["fs_errno"] == 2 and bad["stat_error"]["errno"] == 9
    good = tmpfs["records"][1]
    assert good["kind"] == "named-unlinked" and good["fstatfs_result"] == 0
    assert good["fs_magic"] == "0x1021994" and good["stat"]["links"] == 0
    assert good["stat"]["inode"] == tmpfs["records"][0]["stat"]["inode"]
    shared_runtime = load("runtime-shared-current-v1.json")
    assert shared_runtime["image_sha256"] == binding["current_model_image_sha256"]
    current = shared_runtime["results"]
    baseline = load("runtime-shared-baseline-v1.json")["results"]
    assert len(current) == 2 and len(baseline) == 3
    passed(current[0], 7)
    passed(baseline[1], 1)
    passed(baseline[2], 7)
    for row, expected in zip(baseline, (binding["baseline_model_image_sha256"],
                                       binding["current_model_image_sha256"],
                                       binding["current_model_image_sha256"])):
        assert row["image_sha256"] == expected
    for row in (current[1], baseline[0]):
        assert row["exit_code"] == 101 and "2 passed; 8 failed; 0 ignored;" in row["stdout"]
    failed = lambda row: re.findall(r"^test (\S+) \.\.\. FAILED$", row["stdout"], re.M)
    assert len(failed(current[1])) == 8 and failed(current[1]) == failed(baseline[0])
    normalize = lambda text: re.sub(r"\(\d+\)", "(THREAD)", text)
    assert normalize(current[1]["stderr"]) == normalize(baseline[0]["stderr"])
    runtime = load("runtime-tmpfs-v1.json")
    assert len(runtime["results"]) == 5
    assert runtime["failed"] == runtime["ignored"] == 0
    assert runtime["current_passed"] == 25 and runtime["baseline_fifo_passed"] == 10
    for row, count in zip(runtime["results"], (7, 10, 1, 7, 10)):
        passed(row, count)
        expected = binding["baseline_model_image_sha256"] if row["label"] == "baseline-fifo" else binding["current_model_image_sha256"]
        assert row["image_sha256"] == expected
    print("verified: shared unlinked-FIFO metadata failure; unchanged current25 and baselineFIFO10 pass on in-worktree Linux tmpfs")


if __name__ == "__main__":
    main()
