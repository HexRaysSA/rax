"""Lossless overflow controls with independent native experiment selection."""
import hashlib
import json
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "docs/specifications/windows/native-query-multiple-values/overflow"
SCHEMA = "rax-native-query-multiple-values-overflow-runs-v1"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate(raw, width, version):
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) >= 3, "incomplete overflow observer")
    head, owner, end = rows[0], rows[1], rows[-1]
    require(head["kind"] == "host" and head["pointer_bytes"] == width and
            head["entry_bytes"] == (16 if width == 4 else 24) and
            owner["kind"] == "owned_key", "overflow process ABI")
    require(end == dict(kind="finished", failed=0, closed=0, deleted=0, absence=2),
            "overflow observer cleanup")
    expected = ([(n, 0) for n in (1, 4094, 4095, 4096, 4097)] if version == 1 else
                [(n, c) for n in (1, 2, 4094, 4095, 4096, 4097)
                 for c in (0, 1, 1048575, 1048576, 1048577, 2097152)])
    cases = rows[2:-1]
    require(version in (1, 2) and len(cases) == len(expected), "overflow experiment count")
    for case, (count, capacity) in zip(cases, expected):
        require(case["kind"] == "case" and case["count"] == count and
                case.get("capacity", 0) == capacity and case["value_bytes"] == 1048576 and
                case["pointer_bytes"] == width and case["entry_bytes"] == head["entry_bytes"] and
                case["exception"] == 0, "overflow experiment selection")
        require(case["pointers_unchanged"] is True and case["padding_unchanged"] is True and
                len(case["fields"]) == 4098 and
                all(len(fields) == 3 and all(type(v) is int and 0 <= v <= 0xFFFFFFFF for v in fields)
                    for fields in case["fields"]), "overflow metadata capture")
        if version == 2:
            runs = case["data_runs"]
            require(all(len(run) == 2 and type(run[0]) is int and 0 <= run[0] <= 255 and
                        type(run[1]) is int and 0 < run[1] <= 2097152 for run in runs) and
                    sum(run[1] for run in runs) == 2097152, "overflow destination capture")
        else:
            require(case["data_unchanged"] is True, "length-only observer destination")
    return rows


def unpack(report):
    rows = list(report["prefix"])
    for packed in report["cases"]:
        case = {}
        for key, value in packed.items():
            if key == "fields_runs":
                require(all(len(run) == 2 and type(run[1]) is int and 0 < run[1] <= 4098
                            for run in value) and sum(run[1] for run in value) == 4098,
                        "overflow metadata runs")
                case["fields"] = [fields for fields, count in value for _ in range(count)]
            else:
                case[key] = value
        rows.append(case)
    rows.extend(report["suffix"])
    require(report["newline"] in ("\n", "\r\n"), "overflow stdout newline")
    return (report["newline"].join(json.dumps(row, separators=(",", ":")) for row in rows) +
            report["newline"]).encode("utf-8")


def pack(records, machines):
    corpus = dict(schema=SCHEMA, producer_version=2, native_calls=0, reports=[])
    native = {metadata["native_machine"] for metadata, _ in records}
    require(len(native) == 1, "overflow native machine changed")
    corpus["native_machine"] = native.pop()
    for metadata, raw in records:
        rows = validate(raw, machines[metadata["architecture"]][1], 2)
        cases = []
        for row in rows[2:-1]:
            packed = {}
            for key, value in row.items():
                if key == "fields":
                    runs = []
                    for fields in value:
                        if runs and runs[-1][0] == fields:
                            runs[-1][1] += 1
                        else:
                            runs.append([fields, 1])
                    packed["fields_runs"] = runs
                else:
                    packed[key] = value
            cases.append(packed)
        report = dict(metadata, prefix=rows[:2], cases=cases, suffix=rows[-1:],
                      stdout_sha256=sha(raw), newline="\r\n" if b"\r\n" in raw else "\n")
        require(unpack(report) == raw, "overflow native stdout round-trip")
        corpus["reports"].append(report)
        corpus["native_calls"] += len(cases)
    return corpus


def verify_sources(machines):
    total = 0
    for version in (1, 2):
        evidence = json.loads((SOURCE / ("evidence-v%d.json" % version)).read_bytes())
        for name, digest in evidence["source_hashes"].items():
            path = (SOURCE / name).resolve()
            require(path.is_relative_to(SOURCE.resolve()) and sha(path.read_bytes()) == digest,
                    "overflow native producer changed: " + name)
        raw = (SOURCE / ("controls-v%d.json" % version)).read_bytes()
        require(sha(raw) == evidence["controls_sha256"], "overflow retained corpus changed")
        corpus = json.loads(raw)
        require(corpus["schema"] == SCHEMA and corpus["producer_version"] == version and
                corpus["native_machine"] == evidence["native_machine"] and
                {r["architecture"] for r in corpus["reports"]} == set(machines),
                "overflow retained ABI coverage")
        count = 0
        for report in corpus["reports"]:
            raw = unpack(report)
            require(sha(raw) == report["stdout_sha256"], "overflow retained stdout changed")
            rows = validate(raw, machines[report["architecture"]][1], version)
            require(rows[0]["kernel"] == evidence["kernel"] and report["exit_code"] == 0 and
                    report["owner_key_deleted_both_views"] is True, "overflow retained frame")
            count += len(rows) - 3
        require(count == corpus["native_calls"] == (15 if version == 1 else 108),
                "overflow retained call count")
        total += count
    return total
