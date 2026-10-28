"""Observe native processor records and distinguish native/compatibility views."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "control", FOLDER.parent / "native-exception-entry-profile/run-second-chance-v1.py"
)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
APIS = ("NtQuerySystemInformation", "NtWow64GetNativeSystemInformation")
MODES = (
    "valid",
    "null_output",
    "misaligned_output",
    "null_return",
    "misaligned_return",
    "bad_return",
    "readonly_output",
    "guard_output",
    "readonly_guard_output",
    "cross12",
    "cross44",
    "alias_return",
    "guard_return",
    "both_guard",
    "readonly_return",
    "return_cross2",
)
ARCHITECTURES = {"x86": 0, "x64": 9, "arm64": 12}
MACHINES = {"x86": 0x14C, "x64": 0x8664, "arm64": 0xAA64}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def unsigned(value, bits=32):
    return type(value) is int and 0 <= value < 1 << bits


def matrix():
    return (
        {
            (cls, size, mode)
            for cls in (1, 63)
            for size in (0, 11, 12, 13, 64, 0xFFFFFFFF)
            for mode in MODES
        }
        | {
            (cls, size, "valid")
            for cls in (0, 62, 114)
            for size in (0, 12, 44, 63, 64, 65, 128)
        }
        | {
            (cls, size, "valid")
            for cls in (2, 50, 55, 0xFFFFFFFF)
            for size in (0, 12, 64)
        }
    )


def record(rows, api, cls):
    return next(
        row
        for row in rows
        if row.get("kind") == "query"
        and row["api"] == api
        and row["class"] == cls
        and row["length"] == 12
        and row["mode"] == "valid"
    )


def validate_rows(arch, rows):
    require(
        arch in ARCHITECTURES and rows and rows[0].get("kind") == "identity",
        "native identity must precede query rows",
    )
    identity = rows[0]
    require(
        identity["arch"] == arch
        and unsigned(identity["build"])
        and identity["native_machine"] in (0x8664, 0xAA64),
        "kernel identity",
    )
    expected_native_arch = {0x8664: 9, 0xAA64: 12}[identity["native_machine"]]
    require(
        identity["shared_native_architecture"] == expected_native_arch,
        "shared data must identify the captured kernel",
    )
    for name in ("system_info", "native_system_info"):
        value = identity[name]
        require(
            type(value) is list
            and len(value) == 4
            and all(unsigned(x, 16) for x in value[:3])
            and unsigned(value[3])
            and value[3] > 0,
            "system-info shape",
        )
    require(
        identity["system_info"][0] == ARCHITECTURES[arch], "process system-info view"
    )
    require(
        identity["native_system_info"][0]
        == (9 if arch == "x86" else ARCHITECTURES[arch]),
        "native-system-info compatibility view",
    )
    cpuid = identity["cpuid1"]
    require(
        (
            cpuid is None
            if arch == "arm64"
            else type(cpuid) is list
            and len(cpuid) == 4
            and all(unsigned(x) for x in cpuid)
        ),
        "CPUID shape",
    )
    features = identity["processor_features"]
    require(
        type(features) is list
        and len(features) == 24
        and len({x[0] for x in features}) == 24,
        "processor-feature coverage",
    )
    for item in features:
        require(
            type(item) is list
            and len(item) == 3
            and unsigned(item[0])
            and type(item[1]) is bool
            and type(item[2]) is int
            and item[2] in (0, 1),
            "processor-feature scalar types",
        )
    queries = [row for row in rows if row.get("kind") == "query"]
    unavailable = [row for row in rows if row.get("kind") == "unavailable_api"]
    apis = APIS if arch == "x86" else APIS[:1]
    require(len(rows) == 1 + len(queries) + len(unavailable), "unknown observation row")
    require(
        unavailable
        == ([] if arch == "x86" else [{"kind": "unavailable_api", "api": APIS[1]}]),
        "export availability",
    )
    keys = set()
    fields = {
        "kind",
        "api",
        "class",
        "length",
        "mode",
        "status",
        "raised",
        "returned",
        "guard",
        "return_guard",
        "output",
    }
    for row in queries:
        require(set(row) == fields and row["api"] in apis, "query fields")
        require(
            all(
                unsigned(row[k])
                for k in ("class", "length", "status", "raised", "returned")
            )
            and type(row["guard"]) is bool
            and type(row["return_guard"]) is bool,
            "query scalar types",
        )
        key = (row["api"], row["class"], row["length"], row["mode"])
        require(key not in keys, "duplicate query")
        keys.add(key)
        data = row["output"]
        require(
            type(data) is str
            and len(data) == (0 if row["mode"] == "null_output" else 160)
            and all(ch in "0123456789abcdef" for ch in data),
            "bounded output bytes",
        )
        if row["class"] in (1, 63) and data:
            require(
                bytes.fromhex(data)[12:] == bytes([0xA5]) * 68,
                "processor record wrote beyond 12 bytes",
            )
    require(
        keys == {(api, *key) for api in apis for key in matrix()},
        "incomplete query matrix",
    )
    for api in apis:
        for cls in (1, 63):
            row = record(rows, api, cls)
            require(
                row["status"] == row["raised"] == 0 and row["returned"] == 12,
                "successful processor query",
            )
            require(
                struct.unpack("<HHHHI", bytes.fromhex(row["output"])[:12])[3] > 0,
                "processor count",
            )
    ordinary = struct.unpack(
        "<HHHHI", bytes.fromhex(record(rows, APIS[0], 1)["output"])[:12]
    )
    require(
        list(ordinary[:3]) == identity["system_info"][:3], "ordinary processor identity"
    )
    return rows


def expand(sample):
    return (
        [sample["identity"]]
        + [
            {
                "kind": "query",
                "api": APIS[row[0]],
                "class": row[1],
                "length": row[2],
                "mode": row[3],
                "status": row[4],
                "raised": row[5],
                "returned": row[6],
                "guard": row[7],
                "return_guard": row[8],
                "output": row[9],
            }
            for row in sample["rows"]
        ]
        + [
            {"kind": "unavailable_api", "api": name}
            for name in sample["unavailable_api"]
        ]
    )


def compact(arch, rows, compiler_hash, binary_hash, binary_bytes):
    return {
        "arch": arch,
        "compiler_sha256": compiler_hash,
        "binary_sha256": binary_hash,
        "binary_bytes": binary_bytes,
        "identity": rows[0],
        "unavailable_api": [
            row["api"] for row in rows if row.get("kind") == "unavailable_api"
        ],
        "rows": [
            [
                APIS.index(row["api"]),
                row["class"],
                row["length"],
                row["mode"],
                row["status"],
                row["raised"],
                row["returned"],
                row["guard"],
                row["return_guard"],
                row["output"],
            ]
            for row in rows
            if row.get("kind") == "query"
        ],
    }


def validate_dataset(data, expected_source_sha=None):
    require(
        data["schema"] == 1 and data["inputs_unchanged"] is True, "capture provenance"
    )
    source_hash = data["source_sha256"]
    require(
        type(source_hash) is str
        and len(source_hash) == 64
        and all(x in "0123456789abcdef" for x in source_hash),
        "source hash",
    )
    require(
        expected_source_sha is None or source_hash == expected_source_sha,
        "unexpected producer source",
    )
    samples = data["samples"]
    require(
        len({sample["arch"] for sample in samples}) == len(samples),
        "duplicate architecture",
    )
    native = "arm64" if data["kernel"]["native_machine"] == 0xAA64 else "x64"
    require(
        {sample["arch"] for sample in samples}
        == ({"arm64", "x64", "x86"} if native == "arm64" else {"x64", "x86"}),
        "native and compatibility architecture coverage",
    )
    expanded = {
        sample["arch"]: validate_rows(sample["arch"], expand(sample))
        for sample in samples
    }
    for rows in expanded.values():
        require(
            rows[0]["build"] == data["kernel"]["build"]
            and rows[0]["native_machine"] == data["kernel"]["native_machine"],
            "mixed kernel identities",
        )
    for cls in (1, 63):
        require(
            record(expanded["x86"], APIS[1], cls)["output"]
            == record(expanded[native], APIS[0], cls)["output"],
            "WoW64 native query differs from the native kernel record",
        )
    require(
        record(expanded["x86"], APIS[0], 1)["output"]
        == record(expanded["x86"], APIS[0], 63)["output"],
        "x86 compatibility records differ",
    )
    return data


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_machine():
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.IsWow64Process2
    query.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort),
        ctypes.POINTER(ctypes.c_ushort),
    ]
    query.restype = ctypes.c_int
    process, native = ctypes.c_ushort(), ctypes.c_ushort()
    if not query(ctypes.c_void_p(-1), ctypes.byref(process), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    return native.value


def main():
    if sys.platform != "win32":
        raise RuntimeError("native Windows kernel required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment")
    parser.add_argument(
        "--output", default="target/native-system-processor-information-v1.json"
    )
    args = parser.parse_args()
    machine = native_machine()
    require(machine in (0x8664, 0xAA64), "native AMD64 or ARM64 kernel required")
    architectures = ("arm64", "x64", "x86") if machine == 0xAA64 else ("x64", "x86")
    root = FOLDER.parents[3]
    target = root / "target"
    target.mkdir(exist_ok=True)
    require(
        (root / "Cargo.toml").is_file() and target.resolve().is_relative_to(root),
        "in-tree control target required",
    )
    source = FOLDER / "native-system-processor-information-v1.cpp"
    inputs = [
        source,
        Path(__file__).resolve(),
        Path(CONTROL.__file__),
        Path(CONTROL.PROFILE.__file__),
    ]
    before = {path: sha(path) for path in inputs}
    output = Path(args.output).resolve()
    require(
        output.is_relative_to(target.resolve()) and output != target.resolve(),
        "capture output must stay inside the in-tree target directory",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema": 1,
        "source_sha256": before[source],
        "driver_sha256": before[Path(__file__).resolve()],
        "inputs_unchanged": True,
        "kernel": {"native_machine": machine},
        "samples": [],
        "captures": [],
    }
    with output.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
    for arch in architectures:
        with CONTROL.build_directory(target) as build:
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = CONTROL.PROFILE.compiler_environment(
                arch, args.environment, temporary
            )
            compiler = Path(compiler)
            compiler_hash = sha(compiler)
            executable = build / "probe.exe"
            built = subprocess.run(
                [
                    str(compiler),
                    "/nologo",
                    "/std:c++20",
                    "/MT",
                    "/EHsc",
                    "/utf-8",
                    "/W4",
                    "/WX",
                    str(source),
                    "/Fe:" + str(executable),
                    "/Fo:" + str(build / "probe.obj"),
                ],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if built.returncode:
                raise RuntimeError("compilation failed: " + built.stdout + built.stderr)
            binary = executable.read_bytes()
            pe = struct.unpack_from("<I", binary, 0x3C)[0]
            require(
                struct.unpack_from("<H", binary, pe + 4)[0] == MACHINES[arch],
                "compiled PE machine",
            )
            binary_hash = hashlib.sha256(binary).hexdigest()
            result = subprocess.run(
                [str(executable)],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            unchanged = (
                sha(executable) == binary_hash
                and sha(compiler) == compiler_hash
                and all(sha(path) == value for path, value in before.items())
            )
            print(
                json.dumps(
                    {
                        "kind": "native_capture_header",
                        "arch": arch,
                        "sources": {path.name: value for path, value in before.items()},
                        "compiler_sha256": compiler_hash,
                        "binary_sha256": binary_hash,
                        "binary_bytes": len(binary),
                        "exit_code": result.returncode,
                        "inputs_unchanged": unchanged,
                    }
                ),
                flush=True,
            )
            require(
                len(result.stdout) <= 512 * 1024 and not result.stderr,
                "bounded native output",
            )
            print(result.stdout, end="", flush=True)
            data["captures"].append(
                {
                    "arch": arch,
                    "exit_code": result.returncode,
                    "inputs_unchanged": unchanged,
                    "stdout": result.stdout,
                }
            )
            output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            sample = compact(arch, rows, compiler_hash, binary_hash, len(binary))
            data["samples"].append(sample)
            data["inputs_unchanged"] = data["inputs_unchanged"] and unchanged
            data["kernel"]["build"] = rows[0]["build"]
            output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            require(
                result.returncode == 0 and unchanged,
                "native observer failed or an executed input changed",
            )
            validate_rows(arch, rows)
            print(
                json.dumps({"kind": "validated", "arch": arch, "rows": len(rows)}),
                flush=True,
            )
    validate_dataset(data, before[source])
    print(
        json.dumps({"kind": "validated_set", "architectures": list(architectures)}),
        flush=True,
    )


if __name__ == "__main__":
    main()
