#!/usr/bin/env python3
"""Verify retained key-body tag controls, capture native results, and replay them."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from windows_command_processor import require, require_tests, run, sha
from windows_key_enumeration import native_machine

SOURCES = ("probe-v1.c", "post-v1.c", "CMakeLists.txt")
FIELDS = ("view", "handle_kind", "class", "scenario", "length", "value", "input_alignment")
POST_FIELDS = ("subject", "parent_view", "tag", "requested")


def compact(report):
    outputs, identities, rows = [], {}, []
    for row in report["rows"]:
        result = {k: v for k, v in row.items() if k not in FIELDS}
        identity = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if identity not in identities:
            identities[identity] = len(outputs)
            outputs.append(result)
        rows.append([row[k] for k in FIELDS] + [identities[identity]])
    data = {"page_size": report["page_size"], "opens": report["opens"],
            "row_fields": list(FIELDS) + ["output"], "outputs": outputs, "rows": rows}
    identity = sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    return identity, data


def validate(report, width):
    require(report["pointer_bytes"] == width and report["page_size"] == 4096,
            "native caller width or page size differs")
    require(report["handles_before"] == report["handles_after"], "native handle leak")
    require(len(report["rows"]) == 5372 and len(report["lifetime"]) == 28,
            "native case count differs")
    require(len(report["opens"]) == 10, "native handle grant set differs")
    require(all(row["before_hex"] == row["after_hex"] and row["exception"] == 0
                for row in report["rows"]), "native input mutation or caller exception")


def compact_post(report):
    names, outputs, identities, rows = [], [], {}, []
    for row in report["rows"]:
        result = {k: v for k, v in row.items() if k not in POST_FIELDS}
        for field in ("root_name_hex", "child_name_hex"):
            if field in result:
                if result[field] not in names:
                    names.append(result[field])
                result[field] = names.index(result[field])
        identity = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if identity not in identities:
            identities[identity] = len(outputs)
            outputs.append(result)
        rows.append([row[k] for k in POST_FIELDS] + [identities[identity]])
    data = {"row_fields": list(POST_FIELDS) + ["output"], "names": names,
            "outputs": outputs, "rows": rows}
    identity = sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    return identity, data


def validate_post(report, width):
    require(report["pointer_bytes"] == width, "relative-open caller width")
    require(report["handles_before"] == report["handles_after"], "relative-open handle leak")
    require(len(report["rows"]) == 11648, "relative-open case count")
    require(len(report["hives"]) == 12, "absolute hive spelling case count")
    for row in report["rows"]:
        if row["root_status"]:
            continue
        require(row["set_status"] == 0 and row["root_after_set"] == row["tag"] & 0xffff,
                "relative-open tag replacement")
        require(all(row[k] == row["root_after_set"] for k in
                    ("root_after_open", "root_after_write", "root_after_close")),
                "relative-open parent tag mutation")
        if row["open_status"] == 0:
            require(row["name_status"] == 0 and row["child_write_status"] == 0
                    and row["child_after_write"] == row["child_write_value"],
                    "relative-open child lifetime")


def verify_sources(source):
    corpus = json.loads((source / "controls-v1.json").read_text(encoding="utf-8"))
    require(corpus["schema"] == "rax-native-key-set-information-v1"
            and corpus["state"] == "complete", "retained corpus schema")
    expected = corpus["source_hashes"]
    require(set(expected) == set(SOURCES), "native producer input set")
    for name, digest in expected.items():
        require(sha((source / name).read_bytes().replace(b"\r\n", b"\n")) == digest,
                "native producer changed: " + name)
    require(len(corpus["reports"]) == 3, "retained ABI count")
    for identity, data in corpus["datasets"].items():
        require(sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
                == identity, "native dataset identity")
        require(data["row_fields"] == list(FIELDS) + ["output"]
                and len(data["rows"]) == 5372, "native matrix dimensions")
        require(all(len(row) == len(data["row_fields"])
                    and 0 <= row[-1] < len(data["outputs"]) for row in data["rows"]),
                "native dense row")
    for report in corpus["reports"]:
        require(report["dataset"] in corpus["datasets"]
                and report["handles_before"] == report["handles_after"]
                and len(report["lifetime"]) == 28, "native report metadata")
    post = json.loads((source / "post-controls-v1.json").read_text(encoding="utf-8"))
    require(post["schema"] == "rax-native-key-set-post-v1" and post["state"] == "complete"
            and post["source_hashes"] == expected and len(post["reports"]) == 3,
            "retained relative-open producer identity")
    for identity, data in post["datasets"].items():
        require(sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
                == identity, "relative-open dataset identity")
        require(data["row_fields"] == list(POST_FIELDS) + ["output"]
                and len(data["rows"]) == 11648, "relative-open matrix dimensions")
        require(all(len(row) == 5 and 0 <= row[-1] < len(data["outputs"])
                    for row in data["rows"]), "relative-open dense row")
        for output in data["outputs"]:
            require(all(0 <= output[field] < len(data["names"])
                        for field in ("root_name_hex", "child_name_hex") if field in output),
                    "relative-open name index")
    for report in post["reports"]:
        require(report["dataset"] in post["datasets"]
                and report["handles_before"] == report["handles_after"]
                and len(report["hives"]) == 12,
                "relative-open report metadata")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-corpus", action="store_true")
    parser.add_argument("--output", default="target/native-key-set-information-v1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "docs/specifications/windows/native-key-set-information"
    expected = verify_sources(source)
    if args.verify_corpus:
        print(json.dumps({"verified_producers": len(expected), "retained_process_abis": 3,
                          "matrix_cases": 16116, "lifetime_observations": 84,
                          "relative_open_cases": 34944, "hive_spelling_cases": 36}))
        return 0
    require(sys.platform == "win32", "native Windows is required")
    machine = native_machine()
    output = (root / args.output).resolve()
    require(output != root and output.is_relative_to(root), "output leaves checkout")
    require(not output.exists(), "preserve existing evidence")
    output.mkdir(parents=True)
    (output / ".owner").write_text("native-key-set-information-ci-v1\n", encoding="utf-8")
    temporary = output / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
               SystemTemp=str(temporary), CCACHE_DISABLE="1", SCCACHE_DISABLE="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    target = (root / env.get("CARGO_TARGET_DIR", "target")).resolve()
    require(target.is_relative_to(root), "Cargo target leaves checkout")
    env["CARGO_TARGET_DIR"] = str(target)
    original = {name: sha((source / name).read_bytes()) for name in expected}
    architectures = [("x64", "x64", 0x8664, 8), ("x86", "Win32", 0x14C, 4)]
    if machine == 0xAA64:
        architectures.insert(0, ("arm64", "ARM64", 0xAA64, 8))
    version = sys.getwindowsversion()
    corpus = {"schema": "rax-native-key-set-information-v1", "state": "complete",
              "kernel": [version.major, version.minor, version.build],
              "native_machine": machine, "source_hashes": expected,
              "raw_source_hashes": original, "datasets": {}, "reports": []}
    post_corpus = {**corpus, "schema": "rax-native-key-set-post-v1", "datasets": {}, "reports": []}
    for label, generator_arch, pe_machine, width in architectures:
        build = output / ("build-" + label)
        run(["cmake", "-S", str(source), "-B", str(build), "-A", generator_arch],
            root, env, output / (label + "-configure.log"))
        run(["cmake", "--build", str(build), "--config", "Release", "--", "/nr:false"],
            root, env, output / (label + "-build.log"))
        paths = (build / "probe-paths-Release.txt").read_text(encoding="utf-8").splitlines()
        require(len(paths) == 2, "native target path count")
        for kind, path in zip(("input", "post"), paths):
            image = Path(path).resolve()
            require(image.is_relative_to(build.resolve()), "native image leaves build")
            raw = image.read_bytes()
            require(raw[:2] == b"MZ", "native DOS header")
            pe = struct.unpack_from("<I", raw, 0x3C)[0]
            require(raw[pe:pe + 4] == b"PE\0\0"
                    and struct.unpack_from("<H", raw, pe + 4)[0] == pe_machine,
                    "native PE machine")
            result = subprocess.run([str(image)], cwd=build, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=True)
            (output / (label + "-" + kind + ".json")).write_bytes(result.stdout)
            (output / (label + "-" + kind + ".stderr")).write_bytes(result.stderr)
            report = json.loads(result.stdout)
            (validate if kind == "input" else validate_post)(report, width)
            require(sha(image.read_bytes()) == sha(raw), "native image changed")
            identity, data = (compact if kind == "input" else compact_post)(report)
            destination = corpus if kind == "input" else post_corpus
            destination["datasets"].setdefault(identity, data)
            record = {"architecture": label, "pointer_bytes": width,
                "handles_before": report["handles_before"], "handles_after": report["handles_after"],
                "dataset": identity, "image": {"machine": pe_machine, "bytes": len(raw),
                    "sha256": sha(raw), "report_sha256": sha(result.stdout)}}
            if kind == "input":
                record["lifetime"] = report["lifetime"]
            else:
                record["hives"] = report["hives"]
            destination["reports"].append(record)
        require(build.resolve().is_relative_to(output), "native cleanup containment")
        shutil.rmtree(build)
    require(all(sha((source / n).read_bytes()) == h for n, h in original.items()),
            "native producer inputs changed")
    corpus_path = output / "observations.json"
    corpus_path.write_text(json.dumps(corpus, separators=(",", ":")) + "\n", encoding="utf-8")
    env["RAX_KEY_SET_INFORMATION_CORPUS"] = str(corpus_path)
    post_path = output / "post-observations.json"
    post_path.write_text(json.dumps(post_corpus, separators=(",", ":")) + "\n", encoding="utf-8")
    env["RAX_KEY_SET_POST_CORPUS"] = str(post_path)
    log = output / "guest-replay.log"
    run(["cargo", "test", "--locked", "--no-default-features", "--lib",
         "registry_tests::key_set::", "--", "--test-threads=1", "--nocapture"], root, env, log)
    require_tests(log, 7)
    print(json.dumps({"native_process_abis": len(architectures),
                      "matrix_cases": 5372 * len(architectures),
                      "lifetime_observations": 28 * len(architectures),
                      "relative_open_cases": 11648 * len(architectures),
                      "hive_spelling_cases": 12 * len(architectures)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
