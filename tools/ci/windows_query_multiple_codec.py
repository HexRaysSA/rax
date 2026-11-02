"""Lossless native-query corpus codec and independent experiment selection."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/specifications/windows/native-query-multiple-values"
SCHEMA = "rax-native-query-multiple-values-columnar-v1"
NATIVE_SCHEMA = "rax-native-query-multiple-values-v6"
MACHINES = {"arm64": (0xAA64, 8), "x64": (0x8664, 8), "x86": (0x14C, 4)}
COUNTS = [0, 1, 1, 1, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3]
_overflow_spec = importlib.util.spec_from_file_location(
    "rax_query_multiple_overflow", Path(__file__).with_name("windows_query_multiple_overflow.py"))
overflow = importlib.util.module_from_spec(_overflow_spec)
_overflow_spec.loader.exec_module(overflow)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def selection(layout, phase, **fields):
    result = dict(input_layout=layout, phase=phase, plan=0, capacity=0,
                  entry_role=0, data_role=0, length_role=0, required_role=0,
                  handle=0, boundary=0, poison=0xA5, name_role=0, name_slot=0,
                  data_alias=0, second_name_role=0, second_name_slot=0)
    result.update(fields)
    result.setdefault("count", COUNTS[result["plan"]])
    result["initialized_entries"] = 3 if layout == 5 else max(3, min(256, result["count"]))
    return result


def expected_selection(width):
    product = itertools.product
    plans, capacities = [0, 1, 6, 9], [0, 1, 13, 64]
    for plan, capacity, returned, poison in product(
            range(15), list(range(25)) + [31, 32, 63, 64], [0, 1, 7], [0xA5, 0x5A]):
        yield selection(2, "packing", plan=plan, capacity=capacity,
                        required_role=returned, poison=poison)
    for handle, plan, capacity, returned in product(range(8), plans, [0, 1, 12, 13, 64], [0, 1, 7]):
        yield selection(2, "handles", handle=handle, plan=plan, capacity=capacity, required_role=returned)
    axes = ["entry_role", "data_role", "length_role", "required_role", "handle"]
    sizes = [16, 16, 13, 13, 8]
    for left in range(5):
        for right in range(left + 1, 5):
            for a, b, plan, capacity in product(range(sizes[left]), range(sizes[right]), plans, capacities):
                yield selection(2, "pointer_pairs", plan=plan, capacity=capacity,
                                **{axes[left]: a, axes[right]: b})
    bad = [9, 10, 11, 15]
    for boundary, role, plan, capacity, returned in product(
            range(1, 18), bad, [6, 7], [1, 7, 13, 15], [0, 1, 4, 5, 7]):
        yield selection(2, "data_boundaries", boundary=boundary, data_role=role,
                        plan=plan, capacity=capacity, required_role=returned)
    stride = 24 if width == 8 else 16
    for boundary, role, pair, plan, capacity in product(
            range(1, 3 * stride), bad, [(0, 0), (4, 0), (5, 5)], [1, 6], [0, 64]):
        yield selection(2, "entry_boundaries", boundary=boundary, entry_role=role,
                        length_role=pair[0], required_role=pair[1], plan=plan, capacity=capacity)
    for plan, capacity, role in product(plans, [8192, 0xFFFFFFFF], [0, 14]):
        yield selection(2, "large_capacity", plan=plan, capacity=capacity, data_role=role)
    for plan, slot, role, capacity, handle in product(
            [0, 1, 6, 9, 10, 11], range(3), range(31), [0, 13, 64], [0, 2]):
        yield selection(4, "names", plan=plan, name_slot=slot, name_role=role,
                        capacity=capacity, handle=handle)
    for slot, role, capacity, length, returned in product(
            range(3), range(31), [0, 13], [0, 4, 5], [0, 4, 5]):
        yield selection(4, "name_fault_order", plan=6, name_slot=slot, name_role=role,
                        capacity=capacity, length_role=length, required_role=returned)
    for plan, alias, capacity, length, returned in product(
            range(15), range(8), [0, 1, 4, 7, 13, 64], [0, 7, 8], [0, 7, 8]):
        yield selection(4, "aliases", plan=plan, data_alias=alias, capacity=capacity,
                        length_role=length, required_role=returned)
    for count, capacity, handle, returned in product(
            [0, 1, 2, 3, 4, 16, 64, 256], [0, 1, 13, 1021, 1024, 2048], [0, 2, 5, 6], [0, 1, 7]):
        yield selection(4, "counts", plan=8, count=count, capacity=capacity,
                        handle=handle, required_role=returned)
    for count, capacity, handle, role in product(
            [257, 4096, 0x10000000, 0xFFFFFFFF], [0, 64], [0, 2], [0, 7, 8]):
        yield selection(4, "count_boundaries", plan=8, count=count, capacity=capacity,
                        handle=handle, entry_role=role)
    roles = [1, 2, 5, 6, 11, 14, 15, 17, 18]
    for left in range(3):
        for right in range(left + 1, 3):
            for a, b, capacity, handle in product(roles, roles, [0, 13], [0, 2]):
                yield selection(5, "name_pairs", plan=6, name_slot=left, second_name_slot=right,
                                name_role=a, second_name_role=b, capacity=capacity, handle=handle)
    for count, length, returned, role, handle in product(
            [0x10000000, 0xFFFFFFFF], [0, 1, 4, 5, 6, 10, 11], [0, 5, 6], [0, 7], [0, 2]):
        yield selection(5, "resource_order", plan=8, count=count, capacity=13,
                        length_role=length, required_role=returned, entry_role=role, handle=handle)


def validate(raw, width):
    records = [json.loads(line) for line in raw.splitlines()]
    require(len(records) >= 3, "incomplete native output")
    owner, head, end = records[0], records[1], records[-1]
    require(owner["kind"] == "owned_key" and head["kind"] == "host" and
            head["schema"] == NATIVE_SCHEMA and head["pointer_bytes"] == width,
            "native process identity")
    require(head["entry_bytes"] == (24 if width == 8 else 16) and
            head["layout_offsets"] == ([0, 8, 12, 16] if width == 8 else [0, 4, 8, 12]) and
            head["arena"] == 65536 and head["arena_base"] in
            [0x30000000, 0x31000000, 0x32000000, 0x33000000, 0x34000000], "native SDK layout/arena")
    expected_count = 50036 if width == 8 else 48884
    require(end == dict(kind="finished", records=expected_count, run_status=0,
                        cleanup_status=0, key_deleted=True) and
            len(records) == expected_count + 3, "native completion/cleanup")
    expected_rows = list(expected_selection(width))
    require(len(expected_rows) == expected_count, "native experiment count")
    for index, (row, expected) in enumerate(zip(records[2:-1], expected_rows)):
        require(row["kind"] == "case" and row["index"] == index and
                row["exception"] == 0 and row["arena_reconstruction_verified"] is True,
                "native call completion")
        require(all(row[key] == value for key, value in expected.items()),
                "native experiment selection at " + str(index))
        require(len(row["protections"]) == 17 and row["protections"][-1] == 1 and
                set(row["protections"]) <= {1, 2, 4, 0x102, 0x104}, "native page state")
        sizes = {"entries": expected["initialized_entries"] * head["entry_bytes"],
                 "data": 128 if expected["input_layout"] == 2 else 2048,
                 "length": 8, "required": 8}
        require(all(len(bytes.fromhex(row[key])) == size for key, size in sizes.items()),
                "native output region extent")
        require(("arena_after" in row) == (row["count"] > 256), "native full-arena selection")
        if "arena_after" in row:
            require(len(bytes.fromhex(row["arena_after"])) == 65536, "native full-arena extent")
    return records


def unpack(corpus, report):
    shared = report
    if "case_set" in report:
        shared = next(r for r in corpus["reports"] if r["architecture"] == report["case_set"])
    columns, values = shared["columns"], shared["values"]
    require(len(columns) == len(values) and len(set(columns)) == len(columns), "corpus columns")
    lines = list(report["prefix"])
    for index, row in enumerate(shared["rows"]):
        require(len(row) == len(columns), "corpus row width")
        case = {"kind": "case", "index": index}
        for column, key in enumerate(columns):
            value = values[column][row[column]]
            if value is not None:
                case[key] = value
        lines.append(case)
    lines.extend(report["suffix"])
    return (report["newline"].join(encoded(line) for line in lines) + report["newline"]).encode("utf-8")


def pack(records):
    corpus = dict(schema=SCHEMA, producer_version=6, native_calls=0, reports=[])
    for metadata, raw in records:
        label = metadata["architecture"]
        rows = validate(raw, MACHINES[label][1])
        cases = rows[2:-1]
        report = dict(metadata, prefix=rows[:2], suffix=rows[-1:], host=rows[1],
                      records=len(cases), stdout_sha256=sha(raw),
                      newline="\r\n" if b"\r\n" in raw else "\n")
        columns = list(dict.fromkeys(key for row in cases for key in row if key not in ("kind", "index")))
        values, intern, packed = [[] for _ in columns], [{} for _ in columns], []
        for case in cases:
            row = []
            for column, key in enumerate(columns):
                value = case.get(key)
                signature = encoded(value)
                if signature not in intern[column]:
                    intern[column][signature] = len(values[column])
                    values[column].append(value)
                row.append(intern[column][signature])
            packed.append(row)
        report.update(columns=columns, values=values, rows=packed)
        corpus["reports"].append(report)
        corpus["native_calls"] += len(cases)
        require(unpack(corpus, report) == raw, "native stdout round-trip changed bytes")
    return corpus


def verify_sources():
    require(overflow.verify_sources(MACHINES) == 123, "retained ULONG overflow controls")
    manifest = json.loads((SOURCE / "evidence-v6.json").read_bytes())
    for name, expected in manifest["source_hashes"].items():
        require(Path(name).name == name and sha((SOURCE / name).read_bytes()) == expected,
                "retained producer changed: " + name)
    corpus = json.loads((SOURCE / "controls-v6.json").read_bytes())
    require(corpus["schema"] == SCHEMA and corpus["producer_version"] == 6 and
            corpus["native_calls"] == 148956 and len(corpus["reports"]) == 3 and
            {r["architecture"] for r in corpus["reports"]} == set(MACHINES), "retained ABI coverage")
    total = 0
    for report in corpus["reports"]:
        raw = unpack(corpus, report)
        require(sha(raw) == report["stdout_sha256"], "retained native stdout changed")
        validate(raw, MACHINES[report["architecture"]][1])
        require(report["native_machine"] in (0xAA64, 0x8664), "retained native kernel architecture")
        require(report["provider"]["before_sha256"] == report["provider"]["after_sha256"],
                "retained mapped provider changed")
        total += report["records"]
    require(total == corpus["native_calls"], "retained call count")
    for source in json.loads((SOURCE / "sources.json").read_bytes())["sources"]:
        raw = (SOURCE / source["file"]).read_bytes()
        require(len(raw) == source["bytes"] and sha(raw) == source["sha256"], "primary-source bytes changed")
    return manifest["source_hashes"]
