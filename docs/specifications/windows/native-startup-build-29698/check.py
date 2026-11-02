"""Verify finite build-29698 native controls and their lossless replay inputs."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import zipfile

FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[3]
KINDS = {"lifetime": 32, "admission": 184, "thread": 24, "flags": 208,
         "completion": 24, "completion_stores": 24}
MACHINES = {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def dataset(raw):
    return {k: v for k, v in raw.items()
            if k not in ("pointer_bytes", "handles_before", "handles_after")}


def dataset_identity(data):
    return digest(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(path, identity):
    require(path.stat().st_size == identity["bytes"]
            and file_digest(path) == identity["sha256"], "archive identity")
    reader = zipfile.ZipFile(path)
    manifest = json.loads(reader.read("archive-manifest.json"))
    require(len(reader.namelist()) == len(set(reader.namelist()))
            and set(reader.namelist()) == set(manifest) | {"archive-manifest.json"},
            "archive payload set")
    for name, expected in manifest.items():
        value = hashlib.sha256()
        size = 0
        with reader.open(name) as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                value.update(block)
                size += len(block)
        require(size == expected["bytes"] and value.hexdigest() == expected["sha256"],
                "archive payload: " + name)
    return reader, len(manifest)


def image(raw, expected, machine):
    require(len(raw) == expected["bytes"] and digest(raw) == expected["sha256"],
            "executed image identity")
    require(raw[:2] == b"MZ" and len(raw) >= 64, "DOS header")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    require(pe <= len(raw) - 6 and raw[pe:pe + 4] == b"PE\0\0"
            and struct.unpack_from("<H", raw, pe + 4)[0] == machine,
            "executed PE machine")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--supplement", type=Path)
    args = parser.parse_args()
    require(bool(args.archive) == bool(args.supplement), "supply both archives")
    inputs = json.loads((FOLDER / "inputs-v1.json").read_text(encoding="utf-8"))
    for name, expected in inputs["profiles"].items():
        require(file_digest(FOLDER / name) == expected, "replay input: " + name)
    for name, expected in inputs["sources"].items():
        raw = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        require(digest(raw) == expected, "frozen producer: " + name)
    prefetch = json.loads((FOLDER / "prefetch-v1.json").read_text(encoding="utf-8"))
    flush = json.loads((FOLDER / "flush-v1.json").read_text(encoding="utf-8"))
    notify = json.loads((FOLDER / "notify-v1.json").read_text(encoding="utf-8"))
    require(prefetch["state"] == "finished" and prefetch["build"] == 29698
            and prefetch["native_machine"] == 0xAA64, "prefetch component identity")
    require(len(prefetch["cases"]) == 1026 and
            {(r["arch"], r["case"]) for r in prefetch["cases"]}
            == {(a, n) for a in MACHINES for n in range(342)}, "prefetch coverage")
    require(all(r["exit_code"] == 0 and r["observation"]["id"] == r["case"]
                for r in prefetch["cases"]), "prefetch case verdict")
    control = load_module("flush_29698_control",
                          ROOT / "docs/specifications/windows/native-system-flush-information/run-v2.py")
    require(len(flush["profiles"]) == 1
            and flush["profiles"][0]["kernel"] == {"native_machine": 0xAA64, "build": 29698},
            "flush kernel identity")
    samples = flush["profiles"][0]["samples"]
    require(len(samples) == 3 and {s["arch"] for s in samples} == set(MACHINES),
            "flush architecture coverage")
    for sample in samples:
        control.validate_rows(sample["arch"], control.expand(sample))
        require(sample["identity"]["build"] == 29698
                and sample["identity"]["native_machine"] == 0xAA64, "flush identity")
    require(sum(len(s["rows"]) for s in samples) == 1056, "flush query count")
    require(notify["state"] == "complete" and notify["kernel"] == [10, 0, 29698]
            and notify["native_machine"] == 0xAA64, "notification identity")
    require(len(notify["reports"]) == 3
            and {r["architecture"] for r in notify["reports"]} == set(MACHINES),
            "notification architecture coverage")
    for key, data in notify["datasets"].items():
        require(dataset_identity(data) == key, "notification dataset identity")
    for report in notify["reports"]:
        require(set(report["datasets"]) == set(KINDS), "notification kind coverage")
        for kind, count in KINDS.items():
            require(len(notify["datasets"][report["datasets"][kind]]["rows"]) == count,
                    "notification row count")
            before, after = report["handles"][kind]
            require(before == after, "successful notification handle baseline")
    payloads = 0
    if args.archive:
        original, count = archive(args.archive, inputs["archives"]["original"])
        supplement, extra = archive(args.supplement, inputs["archives"]["supplement"])
        payloads = count + extra
        try:
            raw = original.read("native/receipt.json")
            receipt = json.loads(raw)
            packet = original.read("native/packet.zip")
            meta = json.loads(zipfile.ZipFile(io.BytesIO(packet)).read("manifest.json"))
            require(receipt["state"] == "failed" and receipt["commands"][-1]["exit_code"] == 11,
                    "preserve original capture failure")
            require(supplement.read("original/receipt.json") == raw
                    and supplement.read("original/packet.zip") == packet, "supplement origin binding")
            for name, expected in meta["files"].items():
                raw_source = original.read("native/source/" + name)
                require(len(raw_source) == expected["bytes"]
                        and digest(raw_source) == expected["sha256"]
                        and supplement.read("original-source/" + name) == raw_source,
                        "compiler input binding: " + name)
            for arch, expected in meta["providers"].items():
                require(digest(supplement.read("providers/" + arch + "-ntdll.dll"))
                        == expected["before_sha256"], "provider unchanged after supplement")
            for expected in receipt["images"]:
                relative = expected["path"].replace("\\", "/").split("/native-startup-profiles-29698-v1/")[1]
                image(original.read("native/" + relative), expected, MACHINES[expected["arch"]])
            failed_thread = json.loads(original.read("native/x86-notify-thread.log"))
            require([failed_thread["handles_before"], failed_thread["handles_after"]] == [70, 72]
                    and len(failed_thread["rows"]) == 24, "original failed counter observation")
            require(prefetch["source_sha256"] == meta["files"][
                    "docs/specifications/windows/native-memory-prefetch/probe-v4.c"]["sha256"],
                    "prefetch compiler input")
            require(prefetch["binaries"] == {i["arch"]: i["sha256"] for i in receipt["images"]
                    if i["kind"] == "prefetch"}, "prefetch executed image bindings")
            commands = {c["label"]: c for c in receipt["commands"]}
            for fresh, projected in zip(receipt["prefetch"], prefetch["cases"]):
                label = "%s-prefetch-%03d" % (fresh["arch"], fresh["case"])
                raw_row = original.read("native/" + label + ".log")
                require(commands[label]["exit_code"] == 0
                        and digest(raw_row) == fresh["stdout_sha256"]
                        and json.loads(raw_row) == fresh["observation"]
                        and dict(fresh, exit_code=0) == projected, "raw prefetch roundtrip")
            require(len(receipt["prefetch"]) == len(prefetch["cases"]), "prefetch raw count")
            for fresh, projected in zip(receipt["flush"], samples):
                executed = next(i for i in receipt["images"]
                                if i["arch"] == fresh["arch"] and i["kind"] == "flush")
                require(control.compact(fresh["arch"], fresh["rows"],
                        executed["compiler_sha256"], executed["sha256"], executed["bytes"])
                        == projected, "flush executed image and compiler bindings")
                label = fresh["arch"] + "-flush"
                raw_rows = original.read("native/" + label + ".log")
                require(commands[label]["exit_code"] == 0
                        and digest(raw_rows) == fresh["stdout_sha256"]
                        and [json.loads(line) for line in raw_rows.splitlines()] == fresh["rows"]
                        == control.expand(projected), "raw flush roundtrip")
            diagnostic = json.loads(supplement.read("diagnostic/receipt.json"))
            finish = json.loads(supplement.read("finish/receipt.json"))
            require(diagnostic["state"] == finish["state"] == "finished"
                    and diagnostic["inputs_unchanged"] and finish["inputs_unchanged"],
                    "supplement verdicts")
            repeated = [s for s in diagnostic["samples"] if s["kind"] == "unchanged-notify"]
            require(len(repeated) == 3 and all(s["exit_code"] == 0
                    and s["row"]["handles_before"] == s["row"]["handles_after"]
                    for s in repeated), "unchanged thread observer repeats")
            for sample in diagnostic["samples"]:
                label = ("frozen-notify-" if sample["kind"] == "unchanged-notify" else "baseline-") + str(sample["repeat"])
                raw_sample = supplement.read("diagnostic/" + label + ".log")
                require(json.loads(raw_sample) == sample["row"]
                        and digest(raw_sample) == sample["stdout_sha256"], "diagnostic raw sample")
                if sample["kind"] == "unchanged-notify":
                    require(dataset(sample["row"]) == dataset(repeated[0]["row"]),
                            "unchanged notification semantic repetitions")
            for expected in finish["images"]:
                image(supplement.read("executed/finish-" + expected["kind"] + ".exe"),
                      expected, MACHINES["x86"])
            image(supplement.read("executed/frozen_image.exe"), diagnostic["frozen_image"], MACHINES["x86"])
            baseline = supplement.read("executed/baseline_image.exe")
            require(digest(baseline) == diagnostic["baseline_image"]["sha256"],
                    "bare-thread observer image")
            for report in notify["reports"]:
                arch = report["architecture"]
                for kind in KINDS:
                    if arch == "x86" and kind == "thread":
                        item = next(s for s in repeated if s["repeat"] == 0)
                        raw_row = supplement.read("diagnostic/frozen-notify-0.log")
                        observed = item["row"]
                        executed = diagnostic["frozen_image"]
                    elif arch == "x86" and kind in ("flags", "completion", "completion_stores"):
                        item = next(r for r in finish["reports"] if r["kind"] == kind)
                        raw_row = supplement.read("finish/x86-" + kind + ".log")
                        observed = item["data"]
                        executed = next(i for i in finish["images"] if i["kind"] == kind)
                    else:
                        item = next(r for r in receipt["notify"] if r["arch"] == arch and r["kind"] == kind)
                        raw_row = original.read("native/" + arch + "-notify-" + kind + ".log")
                        observed = item["data"]
                        executed = next(i for i in receipt["images"] if i["arch"] == arch and i["kind"] == "notify-" + kind)
                    require(report["images"][kind] == {"machine": MACHINES[arch], "bytes": executed["bytes"], "sha256": executed["sha256"]}, "notification executed image binding")
                    require(json.loads(raw_row) == observed
                            and digest(raw_row) == report["raw_report_sha256"][kind]
                            and dataset(observed) == notify["datasets"][report["datasets"][kind]]
                            and report["handles"][kind] == [observed["handles_before"], observed["handles_after"]],
                            "raw notification roundtrip")
        finally:
            original.close()
            supplement.close()
    print(json.dumps({"kernel": [10, 0, 29698], "native_machine": 0xAA64,
                      "prefetch_observations": 1026, "prefetch_class0_and_invalid_class_rows": 822,
                      "flush_queries": 1056, "notification_observations": 1488,
                      "verified_archive_payloads": payloads,
                      "original_capture_remains_failed": True}))


if __name__ == "__main__":
    main()
