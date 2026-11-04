#!/usr/bin/env python3
"""Verify frozen native evidence and source/image provenance, without running it."""
import hashlib
import json
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        state = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            state.update(chunk)
        return state.hexdigest()


def verify():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "manifest-v1.json").read_text())
    for item in manifest["files"]:
        path = (root / item["path"]).resolve()
        assert path.is_relative_to(root), item["path"]
        assert path.stat().st_size == item["bytes"], item["path"]
        assert digest(path) == item["sha256"], item["path"]

    primary = root / "primary"
    for item in json.loads((primary / "provenance-v1.json").read_text()):
        path = (primary / item["file"]).resolve()
        assert path.is_relative_to(root.parents[2]), item["file"]
        assert path.stat().st_size == item["bytes"], item["file"]
        assert digest(path) == item["sha256"], item["file"]
        assert len(item["commit"]) == 40

    scalar_results = []
    for arch in ["arm64", "x64"]:
        data = json.loads((root / f"native-{arch}-v5.json").read_text())
        assert data["wrapper_exit_code"] == 0
        assert data["invalid_pointer_probes"] is False
        assert digest(root / data["source_file"]) == data["source_sha256"]
        rows = data["rows"]
        queries = [row for row in rows if "id" in row]
        assert len(queries) == data["query_case_count"] == 337
        assert len({row["id"] for row in queries}) == 337
        assert rows[-1]["schema"] == "rax-native-directory-ordinary-v5-complete"
        setters = [row for row in rows if "ea_set_case" in row]
        assert len(setters) == data["ea_set_count"] == 3
        assert all(row["returned"] == 0 for row in setters)
        for row in queries:
            assert len(bytes.fromhex(row["data"])) == row["length"]
            assert row["trailing_untouched"] is True
        by_id = {row["id"]: row for row in queries}
        for index, expected in enumerate([12, 28, 48]):
            row = by_id[f"ea-directory-{index}"]
            raw = bytes.fromhex(row["data"])
            assert row["returned"] == 0
            assert int.from_bytes(raw[64:68], "little") == expected
        assert by_id["rename-retained-restart"]["returned"] == 0
        assert by_id["pattern-false-10-0"]["returned"] == 0
        assert by_id["pattern-false-11-0"]["returned"] == 0
        scalar_results.append({
            row["id"]: (row["returned"], row["io_status"], row["information"])
            for row in queries
        })
    assert scalar_results[0] == scalar_results[1]

    event_results = []
    poison = int.from_bytes(b"\xa5" * 8, "little")
    for arch in ["arm64", "x64"]:
        profile = json.loads((root / f"event-{arch}-v1.json").read_text())
        assert profile["wrapper_exit_code"] == 0
        assert profile["pointer_bytes"] == 8
        assert digest(root / profile["producer_file"]) == profile["source_sha256"]
        assert profile["image_bytes"] > 0 and len(profile["image_sha256"]) == 64
        rows = profile["rows"]
        assert len(rows) == profile["query_case_count"] == 12
        keys = {(row["legacy"], row["initial"], row["case"]) for row in rows}
        assert keys == {
            (legacy, initial, case)
            for legacy in [False, True]
            for initial in [False, True]
            for case in ["success", "overflow", "missing"]
        }
        for row in rows:
            if row["case"] == "missing":
                assert row["returned"] == 0xC000000F
                assert row["io_status"] == row["information"] == poison
                assert row["event_signaled"] is False
            else:
                status, information = (0, 112) if row["case"] == "success" else (0x80000005, 96)
                assert row["returned"] == status
                assert row["io_status"] == (poison & 0xFFFFFFFF00000000) | status
                assert row["information"] == information
                assert row["event_signaled"] is True
        event_results.append(rows)
    assert event_results[0] == event_results[1]

    ci = json.loads((root / "ci-event-profiles-v1.json").read_text())
    assert digest(root / ci["source_file"]) == ci["source_sha256"]
    assert len(ci["profiles"]) == 2
    for profile in ci["profiles"]:
        assert len(profile["host_system32_ntdll_sha256"]) == 64
        rows = profile["rows"]
        assert len(rows) == 12
        assert {(r["legacy"], r["initial"], r["case"]) for r in rows} == keys
        for row, frozen in zip(rows, event_results[0]):
            if profile["kernel_version"] == "10.0.20348.0" and row["case"] == "missing":
                assert row["returned"] == 0xC000000F
                assert row["io_status"] == (poison & 0xFFFFFFFF00000000) | 0xC000000F
                assert row["information"] == 0 and row["event_signaled"] is True
            else:
                assert row == frozen

    comparison = json.loads((root / "cmd-comparison-v1.json").read_text())
    assert len(comparison["cases"]) == 2
    for case in comparison["cases"]:
        assert case["native_exit"] == case["guest_exit"]
        assert case["native_stdout_hex"] == case["guest_stdout_hex"]
        assert case["native_stderr_hex"] == case["guest_stderr_hex"] == ""
        assert case["separate_sysroot"] is False
        assert case["library_sha256"] == comparison["library"]["sha256"]
    by_name = {case["name"]: case for case in comparison["cases"]}
    assert by_name["exit37"]["guest_exit"] == 37
    assert by_name["exit37"]["guest_stdout_hex"] == ""
    assert bytes.fromhex(by_name["echo"]["guest_stdout_hex"]) == b"RAX_PROCESS_MATRIX_A7F3C2\r\n"
    assert by_name["echo"]["guest_exit"] == 0
    print("verified 674 native directory queries, 48 event queries, 6 EA setters, and 2 CMD comparisons")


if __name__ == "__main__":
    verify()
