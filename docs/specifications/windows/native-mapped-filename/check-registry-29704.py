#!/usr/bin/env python3
"""Verify the defined registry-copy projection and optional raw native archive."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def native_identity(row):
    assert row["state"] == "finished"
    assert row["native_pid"] > 0
    assert row["creation_filetime"] == row["creation_filetime_after"] > 0
    assert row["native_exit_code"] == row["popen_returncode"] == 0


def expand(data):
    assert len(data["row_fields"]) == len(set(data["row_fields"]))
    assert data["row_fields"][-1] == "output"
    rows = []
    for values in data["rows"]:
        assert len(values) == len(data["row_fields"])
        assert 0 <= values[-1] < len(data["outputs"])
        row = dict(zip(data["row_fields"][:-1], values[:-1]))
        output = data["outputs"][values[-1]]
        assert not set(row).intersection(output)
        row.update(output)
        for prefix, full, size, fill in [
                ("buffer_prefix_hex", "buffer_hex", 384, 0xA5),
                ("result_prefix_hex", "result_hex", 32, 0xCC)]:
            if prefix in row:
                raw = bytes.fromhex(row.pop(prefix))
                assert len(raw) <= size
                row[full] = raw.ljust(size, bytes([fill])).hex()
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", nargs="?", type=Path)
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    provenance = json.loads((folder / "registry-copy-29704-v1.json").read_bytes())
    projection = provenance["defined_projection"]
    query_bytes = (folder / "registry-query-29704-v1.json").read_bytes()
    enum_bytes = (folder / "registry-enumeration-29704-v1.json").read_bytes()
    assert sha(query_bytes) == projection["query_sha256"]
    assert sha(enum_bytes) == projection["enumeration_sha256"]
    wrapper = (folder / "registry-enumeration-precondition-v2.c").read_bytes()
    assert sha(wrapper) == projection["wrapper_sha256"]
    query, enumeration = json.loads(query_bytes), json.loads(enum_bytes)
    for data in (provenance, query, enumeration):
        assert data["kernel"] == [10, 0, 29704]
        assert data["native_machine"] == 0xAA64
    query_runs = provenance["native_query_receipt"]["runs"]
    enum_runs = provenance["native_enumeration_receipt"]["runs"]
    assert len(query_runs) == 8 and len(enum_runs) == 7
    for row in query_runs + enum_runs:
        native_identity(row)
    labels = [row["label"] for row in query["rows"]]
    assert labels == ["arm64", "x64", "x86", "x86-laa"]
    query_cases = 0
    for process in query["rows"]:
        probe = process["probes"]["v5"]
        assert probe["build_returncode"] == probe["run_returncode"] == 0
        native_identity(probe["native_identity"])
        assert probe["exe_before_sha256"] == probe["exe_after_sha256"]
        assert probe["source_sha256"] == probe["source_after_sha256"]
        assert sha(probe["text"].encode()) == probe["text_projection"]["projected_text_sha256"]
        rows = [json.loads(line) for line in probe["text"].splitlines()]
        assert len(rows) == 3312
        assert len({(row["prefix"], row["length"], row["valid"], row["guard"])
                    for row in rows}) == 3312
        for row in rows:
            assert set(row) == set(probe["text_projection"]["fields"])
            assert row["kind"] == "copy_boundary" and row["exception"] == 0
            assert len(bytes.fromhex(row["head"])) == 4
        query_cases += len(rows)
    enum_cases = 0
    for kind, campaign in enumeration["campaigns"].items():
        assert kind in ("basic", "fault")
        assert [row["architecture"] for row in campaign["reports"]] == ["arm64", "x64", "x86"]
        for identity, data in campaign["datasets"].items():
            assert sha(canonical(data)) == identity
            expand(data)
        for report in campaign["reports"]:
            native_identity(report["native_identity"])
            assert report["handles_before"] == report["handles_after"]
            rows = expand(campaign["datasets"][report["dataset"]])
            assert len(rows) == (4860 if kind == "basic" else 5676)
            assert all(row["exception"] == 0 for row in rows)
            if kind == "basic":
                assert all(row["class"] not in (1, 2) for row in rows)
            enum_cases += len(rows)
    assert (query_cases, enum_cases) == (13248, 31608)
    if args.archive is None:
        print("Verified projected fixtures and native receipts; raw archive not checked.")
        return
    expected = provenance["archive"]
    assert args.archive.stat().st_size == expected["archive_bytes"]
    assert sha(args.archive.read_bytes()) == expected["archive_sha256"]
    with zipfile.ZipFile(args.archive) as bundle:
        names = bundle.namelist()
        manifest = json.loads(bundle.read("artifact-manifest.json"))["files"]
        assert len(names) == len(set(names)) == expected["payload_count"] + 1
        assert set(names) == set(manifest) | {"artifact-manifest.json"}
        assert bundle.testzip() is None
        for name, entry in manifest.items():
            raw = bundle.read(name)
            assert len(raw) == entry["bytes"] and sha(raw) == entry["sha256"]
        assert bundle.read("sources/registry-enumeration-precondition-v2.c") == wrapper
        native_query_bytes = bundle.read("corpora/registry-query-copy-29704-v2.json")
        native_enum_bytes = bundle.read("corpora/registry-enumeration-copy-29704-v2.json")
        assert sha(native_query_bytes) == query["projection"]["native_corpus_sha256"]
        assert sha(native_enum_bytes) == enumeration["projection"]["native_corpus_sha256"]
        native_query = json.loads(native_query_bytes)
        native_enum = json.loads(native_enum_bytes)
        assert len(native_query["rows"]) == 4
        source_hashes = {entry["original_checkout_relative_path"].replace("\\", "/"):
                         entry["sha256"] for entry in manifest.values()}
        for receipt in (provenance["native_query_receipt"],
                        provenance["native_enumeration_receipt"]):
            for name, value in receipt["input_hashes"].items():
                assert source_hashes[name.replace("\\", "/")] == value
        for actual, original in zip(query["rows"], native_query["rows"]):
            assert actual["label"] == original["label"]
            projected = actual["probes"]["v5"]
            text = original["probes"]["v5"]["text"]
            rows = [json.loads(line) for line in text.splitlines()
                    if json.loads(line).get("kind") == "copy_boundary"]
            assert len(rows) == 3312
            raw = bundle.read("raw/query-" + actual["label"] + "-native.stdout")
            assert sha(raw) == projected["native_identity"]["stdout_sha256"]
            assert raw.decode("utf-8").replace("\r\n", "\n") == text
            source = bundle.read("sources/docs/specifications/windows/native-query-key/probe-v5.cpp")
            assert sha(source) == projected["source_sha256"]
            for output, row in zip(projected["text"].splitlines(), rows):
                output = json.loads(output)
                assert all(output[key] == row[key] for key in output if key != "head")
                assert output["head"] == row["head"][:8]
            image = bundle.read("images/query-" + actual["label"] + ".exe")
            assert sha(image) == projected["exe_before_sha256"]
            offset = struct.unpack_from("<I", image, 0x3C)[0]
            machine = struct.unpack_from("<H", image, offset + 4)[0]
            assert image[offset:offset + 4] == b"PE\0\0"
            assert machine == {"arm64": 0xAA64, "x64": 0x8664,
                               "x86": 0x14C, "x86-laa": 0x14C}[actual["label"]]
            if machine == 0x14C:
                flags = struct.unpack_from("<H", image, offset + 22)[0]
                assert bool(flags & 0x20) == (actual["label"] == "x86-laa")
        for kind, campaign in enumeration["campaigns"].items():
            original = native_enum["campaigns"][kind]
            for actual, native in zip(campaign["reports"], original["reports"]):
                assert actual["architecture"] == native["architecture"]
                rows = expand(original["datasets"][native["dataset"]])
                if kind == "basic":
                    rows = [row for row in rows if row["class"] not in (1, 2)]
                assert expand(campaign["datasets"][actual["dataset"]]) == rows
                name = actual["architecture"] + "-" + kind
                image = bundle.read("images/enumeration-" + name + ".exe")
                assert sha(image) == actual["image"]["sha256"]
                offset = struct.unpack_from("<I", image, 0x3C)[0]
                assert image[offset:offset + 4] == b"PE\0\0"
                assert struct.unpack_from("<H", image, offset + 4)[0] == actual["image"]["machine"]
                receipt = actual["native_identity"]
                assert receipt["launched_image_sha256"] == receipt["image_sha256_after"] == sha(image)
                raw = bundle.read("raw/" + name + "-precondition-native-v9.stdout")
                assert sha(raw) == receipt["stdout_sha256"]
                report = json.loads(raw)
                assert report["handles_before"] == report["handles_after"]
                assert expand(original["datasets"][native["dataset"]]) == report["rows"]
                stderr = bundle.read("raw/" + name + "-precondition-native-v9.stderr")
                assert sha(stderr) == actual["precondition_stderr_sha256"]
                lines = stderr.decode("utf-8").splitlines()
                assert len(lines) >= 2 and all(line.startswith("PRECONDITION ") for line in lines)
                assert "stable_handles=" in lines[-1] and "interval_ms=1000" in lines[-1]
    print("Verified 142 raw payloads, 13248 projected query cases and 31608 enumeration cases.")


if __name__ == "__main__":
    main()
