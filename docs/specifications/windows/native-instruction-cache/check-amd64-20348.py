#!/usr/bin/env python3
"""Verify retained AMD64 controls; optionally bind every row to the CI ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    provenance = json.loads((HERE / "amd64-20348-v1.json").read_bytes())
    raw = (HERE / "observations-amd64-20348-v1.json").read_bytes()
    require(digest(raw) == provenance["corpus_sha256"], "corpus identity")
    corpus = json.loads(raw)
    require(corpus["state"] == "complete" and
            corpus["schema"] == "rax-native-instruction-cache-v1", "corpus schema")
    require(corpus["acquisition"]["native_kernel"] == "10.0.20348" and
            corpus["acquisition"]["native_machine"] == "AMD64", "native identity")
    require([p["architecture"] for p in corpus["profiles"]] == ["x64", "x86"],
            "captured caller architectures")
    specifications = HERE.parent
    for key in ("source_hashes", "retained_source_hashes"):
        for name, expected in corpus[key].items():
            source = specifications / name
            require(source.resolve().is_relative_to(specifications), "source containment")
            require(digest(source.read_bytes().replace(b"\r\n", b"\n")) == expected,
                    "producer source identity: " + name)
    total = 0
    for profile in corpus["profiles"]:
        x64 = profile["architecture"] == "x64"
        handles, calls = (32, 23040) if x64 else (31, 22320)
        require(profile["pointer_bytes"] == (8 if x64 else 4), "pointer width")
        require(len(profile["handles"]) == handles and
                len(profile["matrix_rows"]) == handles, "handle matrix")
        require(profile["address_kinds"] == 24 and
                len(profile["lengths_hex"]) == 15, "range matrix")
        require(profile["palette"] == [[0, 0, 0x12345678, 7, 1,
                                        0x12345678, 0x12345678, 7]], "native results")
        require(all(row == "0" * 360 for row in profile["matrix_rows"]),
                "native pair selections")
        require(profile["native_calls"] == calls == handles * 24 * 15 * 2,
                "native call count")
        require(profile["raw_report_sha256"] ==
                provenance["raw_reports"][profile["architecture"]], "raw report identity")
        total += calls
    require(total == provenance["native_calls"] == 45360, "campaign size")
    if args.archive:
        require(digest(args.archive.read_bytes()) == provenance["artifact_sha256"],
                "primary archive identity")
        with zipfile.ZipFile(args.archive) as archive:
            require(archive.read("observations.json") == raw, "primary corpus bytes")
            for profile in corpus["profiles"]:
                arch = profile["architecture"]
                require(archive.read(arch + ".stderr") == b"", "native stderr")
                report_raw = archive.read(arch + ".json")
                require(digest(report_raw) == profile["raw_report_sha256"],
                        "primary raw report hash")
                report = json.loads(report_raw)
                require(report["entry_hex"] == profile["entry_hex"] and
                        report["pointer_bytes"] == profile["pointer_bytes"],
                        "native entry identity")
                require(report["handles"] == profile["handles"] and
                        report["lengths_hex"] == profile["lengths_hex"], "raw inputs")
                require([report["handles_before"], report["handles_after"]] ==
                        provenance["producer_process_evidence"]["handle_counts"][arch],
                        "native handle ownership")
                require(len(report["rows"]) == report["rows_count"] ==
                        profile["native_calls"], "raw row count")
                for index, row in enumerate(report["rows"]):
                    pair, api = divmod(index, 2)
                    handle, cell = divmod(pair, 360)
                    kind, length = divmod(cell, 15)
                    require(row[:4] == [handle, kind, length, api], "raw case order")
                    symbol = profile["matrix_rows"][handle][cell]
                    measured = profile["palette"][ALPHABET.index(symbol)]
                    require(row[4:] == measured[api * 4:api * 4 + 4],
                            "raw result projection")
    print(json.dumps({"profile": "AMD64 Windows10.0.20348", "native_calls": total,
                      "producer_inputs_verified": 4,
                      "primary_archive_verified": args.archive is not None}))


if __name__ == "__main__":
    main()
