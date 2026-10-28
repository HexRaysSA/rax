"""Observe native SystemFlushInformation without changing system flush state."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
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
    "alternate_output",
    "readonly_output_bad_return",
    "null_output_bad_return",
    "misaligned_output_guard_return",
    "guard_output_bad_return",
    "alias_return4",
    "alias_return28",
    "alias_return32",
)
ARCHITECTURES = {"x86": 0, "x64": 9, "arm64": 12}
MACHINES = {"x86": 0x14C, "x64": 0x8664, "arm64": 0xAA64}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def unsigned(value, bits=32):
    return type(value) is int and 0 <= value < 1 << bits


def matrix():
    return {
        (192, size, mode)
        for size in (0, 1, 3, 4, 15, 16, 31, 32, 33, 64, 0xFFFFFFFF)
        for mode in MODES
    }


def validate_rows(arch, rows):
    require(
        arch in ARCHITECTURES and rows and rows[0].get("kind") == "identity",
        "native identity must precede query rows",
    )
    identity = rows[0]
    require(
        set(identity)
        == {
            "kind",
            "arch",
            "build",
            "process_machine",
            "native_machine",
            "shared_native_architecture",
            "system_info",
            "native_system_info",
            "maximum_processors",
            "active_processors",
            "cpuid1",
            "cpuid7",
            "processor_features",
        },
        "identity fields",
    )
    for name in (
        "process_machine",
        "native_machine",
        "maximum_processors",
        "active_processors",
    ):
        require(unsigned(identity[name]), "identity scalar")
    for name in ("system_info", "native_system_info"):
        v = identity[name]
        require(
            type(v) is list and len(v) == 4 and all(unsigned(x) for x in v),
            "system-info shape",
        )
    require(
        identity["arch"] == arch
        and unsigned(identity["build"])
        and identity["native_machine"] in (0x8664, 0xAA64),
        "kernel identity",
    )
    require(
        identity["shared_native_architecture"]
        == {0x8664: 9, 0xAA64: 12}[identity["native_machine"]],
        "kernel architecture",
    )
    features = identity["processor_features"]
    expected_features = {
        2,
        6,
        10,
        13,
        14,
        17,
        18,
        19,
        24,
        25,
        27,
        28,
        29,
        30,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
    }
    require(
        type(features) is list and len(features) == len(expected_features),
        "processor-feature coverage",
    )
    for v in features:
        require(
            type(v) is list
            and len(v) == 3
            and unsigned(v[0])
            and type(v[1]) is bool
            and type(v[2]) is int
            and v[2] in (0, 1),
            "processor-feature shape",
        )
    require({v[0] for v in features} == expected_features, "processor-feature indices")
    for name in ("cpuid1", "cpuid7"):
        value = identity[name]
        require(
            (
                value is None
                if arch == "arm64"
                else type(value) is list
                and len(value) == 4
                and all(unsigned(x) for x in value)
            ),
            "CPUID shape",
        )
    queries = [row for row in rows if row.get("kind") == "query"]
    unavailable = [row for row in rows if row.get("kind") == "unavailable_api"]
    available = {row["api"] for row in queries}
    absent = {row["api"] for row in unavailable}
    require(len(rows) == 1 + len(queries) + len(unavailable), "unknown observation row")
    require(
        APIS[0] in available
        and available | absent == set(APIS)
        and not available & absent
        and len(absent) == len(unavailable),
        "export coverage",
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
        require(set(row) == fields and row["api"] in APIS, "query fields")
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
        raw = row["output"]
        is_null = row["mode"] in ("null_output", "null_output_bad_return")
        require(
            type(raw) is str
            and len(raw) == (0 if is_null else 160)
            and all(ch in "0123456789abcdef" for ch in raw),
            "bounded output",
        )
        if raw:
            data = bytes.fromhex(raw)
            poison = 0x5A if row["mode"] == "alternate_output" else 0xA5
            tail = 36 if row["mode"] == "alias_return32" else 32
            require(data[tail:] == bytes([poison]) * (80 - tail), "record overrun")
        if row["status"] == row["raised"] == 0:
            require(
                row["returned"] == 32
                or row["mode"] == "null_return"
                or row["mode"].startswith("alias_return"),
                "successful extent",
            )
    require(
        keys == {(api, *key) for api in available for key in matrix()},
        "incomplete query matrix",
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
    require(
        expected_source_sha is None or data["source_sha256"] == expected_source_sha,
        "unexpected producer source",
    )
    native = data["kernel"]["native_machine"]
    require(native in (0x8664, 0xAA64), "native kernel identity")
    expected = {"x64", "x86"} if native == 0x8664 else {"arm64", "x64", "x86"}
    samples = data["samples"]
    require(
        len(samples) == len(expected) and {s["arch"] for s in samples} == expected,
        "native and compatibility architecture coverage",
    )
    for sample in samples:
        rows = validate_rows(sample["arch"], expand(sample))
        require(
            rows[0]["native_machine"] == native
            and rows[0]["build"] == data["kernel"]["build"],
            "mixed kernel identities",
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
        "--output", default="target/native-system-flush-information-v2.json"
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
    source = FOLDER / "native-system-flush-information-v1.cpp"
    inputs = [
        source,
        Path(__file__).resolve(),
        Path(CONTROL.__file__),
        Path(CONTROL.PROFILE.__file__),
    ]
    before = {path: sha(path) for path in inputs}
    libraries = {
        name: Path(os.environ["SystemRoot"]) / name / "ntdll.dll"
        for name in ("System32", "SysWOW64")
    }
    library_before = {name: sha(path) for name, path in libraries.items()}
    output = Path(args.output).resolve()
    require(
        output.is_relative_to(target.resolve()) and output != target.resolve(),
        "capture output must stay inside the in-tree target directory",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema": 1,
        "driver_version": 2,
        "source_sha256": before[source],
        "driver_sha256": before[Path(__file__).resolve()],
        "source_lf_sha256": hashlib.sha256(
            source.read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest(),
        "ntdll_sha256": library_before,
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
            )
            unchanged = (
                sha(executable) == binary_hash
                and sha(compiler) == compiler_hash
                and all(sha(path) == value for path, value in before.items())
                and all(
                    sha(path) == library_before[name]
                    for name, path in libraries.items()
                )
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
            for line in result.stdout.decode("utf-8").splitlines():
                print(line, flush=True)
            data["captures"].append(
                {
                    "arch": arch,
                    "binary_base64": base64.b64encode(binary).decode(),
                    "exit_code": result.returncode,
                    "inputs_unchanged": unchanged,
                    "stdout_base64": __import__("base64")
                    .b64encode(result.stdout)
                    .decode(),
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
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
