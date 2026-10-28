"""Verify bounded native directory observations without predicting alias results."""

import hashlib
import json
from pathlib import Path
import struct
import sys

FOLDER = Path(__file__).resolve().parent


def require(value, reason):
    if not value:
        raise ValueError(reason)


def unsigned(value):
    return type(value) is int and 0 <= value < 1 << 32


def source_identities():
    raw = (FOLDER / "run-v2.py").read_bytes().replace(b"\r\n", b"\n")
    return {
        (hashlib.sha256(value).hexdigest(), len(value))
        for value in (raw, raw.replace(b"\n", b"\r\n"))
    }


def counted(value):
    require(
        type(value) is dict and set(value) == {"units", "text"}, "counted-string fields"
    )
    units = value["units"]
    require(
        type(units) is list
        and len(units) <= 32767
        and all(type(x) is int and 0 <= x <= 65535 for x in units),
        "counted-string bounds",
    )
    raw = struct.pack("<" + "H" * len(units), *units)
    require(
        raw.decode("utf-16-le", errors="strict") == value["text"],
        "raw units and rendered text disagree",
    )


def verify(value):
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "version",
            "pointer_bytes",
            "attributes_bytes",
            "unicode_bytes",
            "process_machine",
            "native_machine",
            "session",
            "paths",
            "rows",
            "distinct_type_status",
            "handle_count_before",
            "handle_count_after",
            "files_before",
            "files_after",
        },
        "capture fields",
    )
    require(
        value["schema"] == "native-session-windows-directory-v2",
        "executed observer version",
    )
    version = value["version"]
    require(
        type(version) is list
        and len(version) == 5
        and all(unsigned(x) for x in version[:4])
        and version[:2] == [10, 0]
        and type(version[4]) is str,
        "kernel identity",
    )
    require(
        value["pointer_bytes"] == 8
        and value["attributes_bytes"] == 48
        and value["unicode_bytes"] == 16
        and value["process_machine"] == 0
        and value["native_machine"] in (0x8664, 0xAA64),
        "native observer ABI",
    )
    require(unsigned(value["session"]), "primary-token session")
    session = value["session"]
    paths = {
        "directory": ["\\Windows", f"\\Sessions\\{session}\\Windows"],
        "section": [
            "\\Windows\\SharedSection",
            f"\\Sessions\\{session}\\Windows\\SharedSection",
        ],
    }
    require(value["paths"] == paths, "fixed current-session path selection")
    require(
        value["files_before"] == value["files_after"],
        "executed source/runtime identity changed",
    )
    files = value["files_before"]
    require(
        type(files) is dict
        and set(files) == {"observer", "python", "python_dll", "ntdll"},
        "source/runtime coverage",
    )
    for name, identity in files.items():
        require(
            type(identity) is dict
            and set(identity) == {"path", "bytes", "sha256", "pe_machine"},
            "file identity fields",
        )
        require(
            type(identity["path"]) is str
            and 0 < len(identity["path"]) <= 32768
            and unsigned(identity["bytes"])
            and identity["bytes"] > 0,
            "file identity bounds",
        )
        digest = identity["sha256"]
        require(
            type(digest) is str
            and len(digest) == 64
            and all(c in "0123456789abcdef" for c in digest),
            "file SHA-256",
        )
        if name == "observer":
            require(
                identity["pe_machine"] is None
                and (digest, identity["bytes"]) in source_identities(),
                "executed observer source differs",
            )
        else:
            require(
                identity["pe_machine"] == value["native_machine"],
                "native executable machine differs",
            )
    require(
        unsigned(value["handle_count_before"])
        and value["handle_count_before"] == value["handle_count_after"],
        "owned handle leaked",
    )
    require(
        unsigned(value["distinct_type_status"]) and value["distinct_type_status"] != 0,
        "distinct native objects compared equal",
    )
    rows = value["rows"]
    require(type(rows) is list and len(rows) == 32, "complete bounded query count")
    seen = set()
    fields = {
        "kind",
        "path_index",
        "path",
        "altered_case",
        "flags",
        "requested_access",
        "status",
        "information",
        "same_reference_status",
    }
    for row in rows:
        require(type(row) is dict and set(row) == fields, "query fields")
        kind, index, altered, flags = (
            row[k] for k in ("kind", "path_index", "altered_case", "flags")
        )
        require(
            kind in paths
            and type(index) is int
            and index in (0, 1)
            and type(altered) is bool
            and type(flags) is int
            and flags in (0, 0x40, 0x1000, 0x1040),
            "query selection",
        )
        key = (kind, index, altered, flags)
        require(key not in seen, "duplicate query")
        seen.add(key)
        expected = paths[kind][index]
        require(
            row["path"] == (expected.swapcase() if altered else expected),
            "guest-independent path differs",
        )
        require(
            row["requested_access"] == (0x02000000 if kind == "directory" else 4)
            and unsigned(row["status"]),
            "query access/status",
        )
        if row["status"] != 0:
            require(
                row["information"] is None and row["same_reference_status"] is None,
                "failed open published metadata",
            )
            continue
        info = row["information"]
        require(
            type(info) is dict
            and set(info) == {"name", "type", "granted_access"}
            and unsigned(info["granted_access"]),
            "successful object information",
        )
        counted(info["name"])
        counted(info["type"])
        require(
            info["name"]["text"].startswith("\\") and "\0" not in info["name"]["text"],
            "canonical native object name",
        )
        require(
            info["type"]["text"] == ("Directory" if kind == "directory" else "Section")
            and unsigned(row["same_reference_status"]),
            "native type/identity status",
        )
    for kind in paths:
        reference = next(
            row
            for row in rows
            if (row["kind"], row["path_index"], row["altered_case"], row["flags"])
            == (kind, 0, False, 0x40)
        )
        require(
            reference["status"] == 0 and reference["same_reference_status"] == 0,
            "fixed reference identity changed",
        )
    return value


if __name__ == "__main__":
    for argument in sys.argv[1:]:
        value = verify(json.loads(Path(argument).read_text(encoding="utf-8")))
        print(
            json.dumps(
                {
                    "path": argument,
                    "session": value["session"],
                    "queries": len(value["rows"]),
                }
            )
        )
