#!/usr/bin/env python3
"""Observe owned ProcessImageInformation and independent PE metadata."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    "control",
    Path(__file__).resolve().parents[1]
    / "native-exception-entry-profile/run-second-chance-v1.py",
)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


def width(arch):
    if arch not in ("arm64", "x64", "x86"):
        raise ValueError("unknown executable view")
    return 4 if arch == "x86" else 8


def record_size(arch):
    return 48 if width(arch) == 4 else 64


LENGTHS = (0, 1, 3, 4, 8, 16, 47, 48, 49, 63, 64, 65, 96, 0xFFFFFFFF)


def inputs(arch):
    size = record_size(arch)
    yield from ((37, "length", 0, 0, 0, 0, n, -1) for n in LENGTHS)
    yield from (
        (37, "buffer", 0, 0, a, b, size, -1)
        for a in (*range(14), 16)
        for b in range(14)
    )
    yield from (
        (37, "handle", h, 0, a, b, n, -1)
        for h in range(5)
        for n in (size - 1, size)
        for a in range(4)
        for b in range(3)
    )
    yield from (
        (37, "rights", 5, access, 0, 0, size, -1)
        for access in (0, 8, 0x20, 0x400, 0x1000, 0x1400, 0x1FFFFF)
    )
    yield from ((37, "alias", 0, 0, 0, 0, size, offset) for offset in range(size + 1))
    yield from (
        (37, "null-length", 0, 0, 1, returned, length, -1)
        for length in LENGTHS
        for returned in range(14)
    )
    yield from (
        (37, "upper-image", handle, 0, output, returned, length, -1)
        for handle in (0, 2)
        for length in (0, 1, size - 1, size, size + 1, 0xFFFFFFFF)
        for output in (14, 15)
        for returned in (0, 1, 6, 7)
    )


def pointer(role, offset):
    return {
        1: -100000,
        2: -99999,
        3: offset + 1,
        4: 4096 + offset,
        5: 8192 + offset,
        6: 12288 + offset,
        7: 12288 + offset,
        8: 4094,
        9: 4092,
        10: 4036,
        11: 4032,
        12: 4048,
        13: 4080,
        16: 4088,
        14: -99998,
        15: -99997,
    }.get(role, offset)


def projection_mask(arch, role, offset, count, output, alias=-1):
    at = 256 + alias if alias >= 0 else pointer(role, offset)
    if not 0 <= at <= 16384 - count:
        at = offset
    destination = pointer(output, 256)
    return "".join(
        (
            "1"
            if 0 <= at + i - destination < width(arch)
            or (width(arch) == 8 and 12 <= at + i - destination < 16)
            else "0"
        )
        for i in range(count)
    )


def validate(rows, arch, metadata=False):
    expected = [] if metadata else list(inputs(arch))
    if len(rows) != len(expected) + 3:
        raise ValueError("incomplete image-information observation")
    host, image = rows[:2]
    if (
        set(host)
        != {
            "kind",
            "build",
            "process_machine",
            "native_machine",
            "pointer_bytes",
            "query_class",
            "record_bytes",
        }
        or host["kind"] != "host"
    ):
        raise ValueError("unexpected host fields")
    for key in set(host) - {"kind"}:
        if type(host[key]) is not int or not 0 <= host[key] <= 0xFFFFFFFF:
            raise ValueError("invalid host integer")
    if (
        host["pointer_bytes"] != width(arch)
        or host["record_bytes"] != record_size(arch)
        or host["query_class"] != 37
        or host["native_machine"] not in (0x14C, 0x8664, 0xAA64)
    ):
        raise ValueError("incompatible native query view")
    if (
        set(image)
        != {
            "kind",
            "status",
            "returned",
            "preferred_entry_matches",
            "loaded_entry_matches",
            "mapped_header_matches_loaded",
            "mapped_header_matches_preferred",
            "preferred_rva_known",
            "preferred_rva",
            "loaded_rva_known",
            "loaded_rva",
            "file_bytes",
            "pe",
            "section",
        }
        or image["kind"] != "image"
    ):
        raise ValueError("unexpected image fields")
    for key in (
        "preferred_entry_matches",
        "loaded_entry_matches",
        "mapped_header_matches_loaded",
        "mapped_header_matches_preferred",
        "preferred_rva_known",
        "loaded_rva_known",
    ):
        if type(image[key]) is not bool:
            raise ValueError("invalid image Boolean")
    for key in ("status", "returned", "preferred_rva", "loaded_rva", "file_bytes"):
        if type(image[key]) is not int or not 0 <= image[key] < 1 << 64:
            raise ValueError("invalid image scalar")
    for key, count in (("pe", 14), ("section", 16)):
        if (
            not isinstance(image[key], list)
            or len(image[key]) != count
            or any(
                type(value) is not int or not 0 <= value < 1 << 64
                for value in image[key]
            )
        ):
            raise ValueError("invalid fixed image projection")
    if (
        image["status"] != 0
        or image["returned"] != record_size(arch)
        or image["pe"][0] != {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch]
        or image["section"][10] != image["pe"][0]
    ):
        raise ValueError("valid image query or independent PE machine differs")
    names = (
        "query_class",
        "family",
        "handle_kind",
        "access",
        "output_role",
        "return_role",
        "length",
        "alias",
    )
    for index, (row, identity) in enumerate(zip(rows[2:-1], expected)):
        if set(row) != {
            "kind",
            "ordinal",
            *names,
            "opened",
            "status",
            "exception",
            "guard_protection",
            "output",
            "output_mask",
            "returned",
            "returned_mask",
            "pointer_valid_mask",
            "pointer_changed_mask",
            "pointer_match_mask",
            "granted_access",
        }:
            raise ValueError("unexpected query fields")
        if (
            row["kind"] != "case"
            or type(row["ordinal"]) is not int
            or row["ordinal"] != index
            or tuple(row[n] for n in names) != identity
        ):
            raise ValueError("query identity/order differs")
        if type(row["opened"]) is not bool or type(row["alias"]) is not int:
            raise ValueError("invalid query identity scalar")
        for key in (
            "query_class",
            "handle_kind",
            "access",
            "output_role",
            "return_role",
            "length",
            "status",
            "exception",
            "guard_protection",
        ):
            if type(row[key]) is not int or not 0 <= row[key] <= 0xFFFFFFFF:
                raise ValueError("invalid query integer")
        for key in ("pointer_valid_mask", "pointer_changed_mask", "pointer_match_mask"):
            if type(row[key]) is not int or not 0 <= row[key] < 1 << width(arch):
                raise ValueError("invalid pointer predicate mask")
        if row["handle_kind"] == 5 and row["opened"]:
            if (
                type(row["granted_access"]) is not int
                or not 0 <= row["granted_access"] <= 0xFFFFFFFF
            ):
                raise ValueError("missing measured handle grant")
        elif row["granted_access"] is not None:
            raise ValueError("unmeasured handle grant must be null")
        for key, count, role, offset, alias in (
            ("output", 80, row["output_role"], 256, -1),
            ("returned", 16, row["return_role"], 512, row["alias"]),
        ):
            mask = projection_mask(arch, role, offset, count, row["output_role"], alias)
            if (
                not isinstance(row[key], str)
                or re.fullmatch("[0-9a-f]{" + str(count * 2) + "}", row[key]) is None
                or row[key + "_mask"] != mask
                or any(
                    row[key][i * 2 : i * 2 + 2] != "00"
                    for i, bit in enumerate(mask)
                    if bit == "1"
                )
            ):
                raise ValueError("malformed or unredacted fixed projection")
    if (
        rows[-1] != {"kind": "complete", "cases": len(expected)}
        or type(rows[-1].get("cases")) is not int
    ):
        raise ValueError("missing query cleanup receipt")
    return rows


def file_metadata(binary):
    pe = struct.unpack_from("<I", binary, 0x3C)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", binary, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unknown optional header")
    wide = magic == 0x20B
    u16 = lambda offset: struct.unpack_from("<H", binary, optional + offset)[0]
    u32 = lambda offset: struct.unpack_from("<I", binary, optional + offset)[0]
    word = lambda offset: struct.unpack_from(
        "<Q" if wide else "<I", binary, optional + offset
    )[0]
    base = word(24 if wide else 28)
    fields = [
        struct.unpack_from("<H", binary, pe + 4)[0],
        u32(16),
        u32(56),
        word(72),
        word(80 if wide else 76),
        u16(68),
        u16(50),
        u16(48),
        u16(40),
        u16(42),
        struct.unpack_from("<H", binary, pe + 22)[0],
        u16(70),
        u32(104 if wide else 88),
        u32(64),
    ]
    return base, fields


PROFILES = (
    "default",
    "stack",
    "versions-gui",
    "checksum",
    "loader-flags",
    "no-dynamic-base",
    "no-code-size",
    "no-section-code",
    "no-code-size-or-section-code",
    "no-relocations",
    "dynamic-base-no-relocations",
    "overlay",
)


def patched(binary, profile):
    data = bytearray(binary)
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    wide = struct.unpack_from("<H", data, optional)[0] == 0x20B
    u16 = lambda offset: struct.unpack_from("<H", data, optional + offset)[0]
    if profile == "stack":
        struct.pack_into("<Q" if wide else "<I", data, optional + 72, 0x300000)
        struct.pack_into(
            "<Q" if wide else "<I", data, optional + (80 if wide else 76), 0x5000
        )
    elif profile == "versions-gui":
        for offset, value in ((40, 10), (42, 0), (48, 10), (50, 0), (68, 2)):
            struct.pack_into("<H", data, optional + offset, value)
    elif profile == "checksum":
        struct.pack_into("<I", data, optional + 64, 0x12345678)
    elif profile == "loader-flags":
        struct.pack_into("<I", data, optional + (104 if wide else 88), 0x1234)
    elif profile in (
        "no-dynamic-base",
        "no-relocations",
        "dynamic-base-no-relocations",
    ):
        if profile != "dynamic-base-no-relocations":
            struct.pack_into("<H", data, optional + 70, u16(70) & ~0x60)
        if profile in ("no-relocations", "dynamic-base-no-relocations"):
            chars = struct.unpack_from("<H", data, pe + 22)[0]
            struct.pack_into("<H", data, pe + 22, chars | 1)
            struct.pack_into(
                "<II", data, optional + (112 if wide else 96) + 5 * 8, 0, 0
            )
    elif profile in ("no-code-size", "no-section-code", "no-code-size-or-section-code"):
        if profile != "no-section-code":
            struct.pack_into("<I", data, optional + 4, 0)
        if profile != "no-code-size":
            count = struct.unpack_from("<H", data, pe + 6)[0]
            size = struct.unpack_from("<H", data, pe + 20)[0]
            for i in range(count):
                at = optional + size + i * 40 + 36
                chars = struct.unpack_from("<I", data, at)[0]
                struct.pack_into("<I", data, at, chars & ~0x20)
    elif profile == "overlay":
        data.extend(b"OWNED-IMAGE-OVERLAY" * 7)
    elif profile != "default":
        raise ValueError("unknown image profile")
    return bytes(data)


def validate_unavailable(record):
    required = {
        "kind",
        "arch",
        "profile",
        "metadata_only",
        "pe_fields",
        "file_bytes",
        "source_sha256",
        "binary_sha256",
        "compiled_binary_sha256",
        "compiler_sha256",
        "available",
        "windows_error",
        "query_calls",
    }
    if (
        set(record) != required
        or record["kind"] != "unavailable"
        or record["arch"] != "arm64"
        or record["profile"]
        not in ("no-dynamic-base", "no-relocations", "dynamic-base-no-relocations")
        or record["available"] is not False
        or record["metadata_only"] is not True
        or type(record["windows_error"]) is not int
        or record["windows_error"] != 193
        or type(record["query_calls"]) is not int
        or record["query_calls"] != 0
    ):
        raise ValueError("unqualified image-loader rejection")
    fields = record["pe_fields"]
    if (
        not isinstance(fields, list)
        or len(fields) != 14
        or any(type(v) is not int or not 0 <= v < 1 << 64 for v in fields)
        or fields[0] != 0xAA64
        or (record["profile"] != "dynamic-base-no-relocations" and fields[11] & 0x40)
        or (record["profile"] == "dynamic-base-no-relocations" and fields[10] & 1 == 0)
    ):
        raise ValueError("rejected image has incompatible PE metadata")
    if type(record["file_bytes"]) is not int or record["file_bytes"] <= 0:
        raise ValueError("invalid rejected file size")
    for key in (
        "source_sha256",
        "binary_sha256",
        "compiled_binary_sha256",
        "compiler_sha256",
    ):
        if (
            not isinstance(record[key], str)
            or re.fullmatch("[0-9a-f]{64}", record[key]) is None
        ):
            raise ValueError("invalid rejected executable identity")


def main():
    if sys.platform != "win32":
        raise RuntimeError("native Windows required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment")
    parser.add_argument(
        "--architectures",
        nargs="+",
        choices=("arm64", "x64", "x86"),
        default=("x64", "x86"),
    )
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parents[3]
    target = root / "target"
    target.mkdir(exist_ok=True)
    if not (root / "Cargo.toml").is_file() or not target.resolve().is_relative_to(root):
        raise RuntimeError("in-tree compiler output required")
    source = folder / "native-image-information-v7.cpp"
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    for arch in args.architectures:
        with CONTROL.build_directory(target) as build:
            temporary = build / "tmp"
            temporary.mkdir()
            env, compiler = CONTROL.PROFILE.compiler_environment(
                arch, args.environment, temporary
            )
            executable = build / "probe.exe"
            result = subprocess.run(
                [
                    str(compiler),
                    "/nologo",
                    "/std:c++20",
                    "/Od",
                    "/EHsc",
                    "/W4",
                    "/WX",
                    "/MT",
                    str(source),
                    "/Fe:" + str(executable),
                    "/Fo:" + str(build / "probe.obj"),
                    "/link",
                    "/NXCOMPAT",
                ],
                cwd=build,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode:
                raise RuntimeError(
                    "image-information compilation failed: "
                    + result.stdout
                    + result.stderr
                )
            binary = executable.read_bytes()
            pe = struct.unpack_from("<I", binary, 0x3C)[0]
            if (
                struct.unpack_from("<H", binary, pe + 4)[0]
                != {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch]
            ):
                raise RuntimeError("unexpected control executable machine")
            for profile in PROFILES:
                candidate = build / (profile + ".exe")
                payload = patched(binary, profile)
                candidate.write_bytes(payload)
                digest = hashlib.sha256(payload).hexdigest()
                preferred_base, pe_fields = file_metadata(payload)
                metadata = profile != "default"
                identity = {
                    "arch": arch,
                    "profile": profile,
                    "metadata_only": metadata,
                    "pe_fields": pe_fields,
                    "file_bytes": len(payload),
                    "source_sha256": source_sha,
                    "binary_sha256": digest,
                    "compiled_binary_sha256": hashlib.sha256(binary).hexdigest(),
                    "compiler_sha256": hashlib.sha256(
                        compiler.read_bytes()
                    ).hexdigest(),
                }
                print(json.dumps({"kind": "producer", **identity}), flush=True)
                try:
                    result = subprocess.run(
                        [
                            str(candidate),
                            format(preferred_base, "x"),
                            *(["metadata"] if metadata else []),
                        ],
                        cwd=build,
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                except OSError as error:
                    if (
                        arch != "arm64"
                        or profile
                        not in (
                            "no-dynamic-base",
                            "no-relocations",
                            "dynamic-base-no-relocations",
                        )
                        or getattr(error, "winerror", None) != 193
                    ):
                        raise
                    record = {
                        "kind": "unavailable",
                        **identity,
                        "available": False,
                        "windows_error": 193,
                        "query_calls": 0,
                    }
                    print(json.dumps(record), flush=True)
                    validate_unavailable(record)
                    if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                        raise RuntimeError("rejected executable changed")
                    continue
                if len(result.stdout) > 1048576 or result.stderr:
                    raise RuntimeError("query output exceeds scalar contract")
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                print(
                    json.dumps(
                        {
                            "kind": "observation",
                            **identity,
                            "exit_code": result.returncode,
                            "rows": rows,
                        }
                    ),
                    flush=True,
                )
                validate(rows, arch, metadata)
                if rows[1]["pe"] != pe_fields or rows[1]["file_bytes"] != len(payload):
                    raise RuntimeError(
                        "loaded headers or reported file size differ from original PE"
                    )
                if (
                    result.returncode
                    or hashlib.sha256(candidate.read_bytes()).hexdigest() != digest
                ):
                    raise RuntimeError("query executable failed or changed")
    if hashlib.sha256(source.read_bytes()).hexdigest() != source_sha:
        raise RuntimeError("query source changed")


if __name__ == "__main__":
    main()
