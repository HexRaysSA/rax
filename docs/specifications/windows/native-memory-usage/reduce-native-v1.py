"""Reduce the three raw native streams without discarding volatile payloads."""
import hashlib
import json
from pathlib import Path
import struct
import sys


def reduce(source, destination):
    profiles, palette, common = [], [], None
    for arch in ("arm64", "x64", "x86"):
        raw = (source / (arch + "-native-v2.bin")).read_bytes()
        header = struct.unpack("<8s6I64s", raw[:96])
        assert header[0] == b"RAXCIQ1\0" and header[4:7] == (2450, 112, 56)
        assert len(raw) == 274496
        rows, values, byte_palette = [], [], []
        for index in range(header[4]):
            row = struct.unpack("<12I64s", raw[96 + 112 * index:208 + 112 * index])
            assert row[0] == index and row[9] == 0x12345678
            result = list(row[6:8])
            if result not in palette:
                palette.append(result)
            rows.append(list(row[1:6]) + [palette.index(result), row[8], row[10], row[11]])
            value = row[12].hex()
            if value not in byte_palette:
                byte_palette.append(value)
            values.append(byte_palette.index(value))
        if common is None:
            common = rows
        else:
            assert common == rows, arch
        profiles.append(dict(architecture=arch, pointer_bytes=header[3], raw_bytes=len(raw),
                             raw_sha256=hashlib.sha256(raw).hexdigest(),
                             entry_bytes=header[7].hex(), bytes_palette=byte_palette,
                             row_bytes_indices=values))
    destination.mkdir(parents=True, exist_ok=True)
    for index, rows in enumerate((common[:1225], common[1225:])):
        text = "[\n" + ",\n".join("  " + json.dumps(row, separators=(",", ":"))
                                   for row in rows) + "\n]\n"
        (destination / f"cases-{index}-v1.json").write_text(text)
    metadata = dict(
        schema="rax-native-system-memory-usage-v1", information_class=182,
        kernel="10.0.29698.0", record_bytes=56,
        row_columns=["buffer_kind", "bytes", "offset", "return_kind", "pattern",
                     "status_palette", "returned", "buffer_guard", "return_guard"],
        last_error=0x12345678,
        palette=[dict(status=status, dos_error=error) for status, error in palette],
        profiles=profiles,
        success_replay="Inject captured output bytes 0..56 as the provider result. Before "
        "injection replace any four ReturnLength-aliased bytes with deadbeef; the captured "
        "final DWORD must still be 56. Volatile native counters are not asserted equal "
        "to guest-model counters.",
    )
    # Preserve readable scalar columns, grouping only the palette index vectors.
    lines, indices = [], None
    for line in json.dumps(metadata, indent=2).splitlines():
        if '"row_bytes_indices": [' in line:
            indices = []
            lines.append(line)
        elif indices is not None and line.strip() == "]":
            for start in range(0, len(indices), 80):
                suffix = "," if start + 80 < len(indices) else ""
                lines.append("        " + ",".join(indices[start:start + 80]) + suffix)
            lines.append(line)
            indices = None
        elif indices is not None:
            indices.append(line.strip().rstrip(","))
        else:
            lines.append(line)
    (destination / "observations-v1.json").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: reduce-native-v1.py RAW_DIRECTORY OUTPUT_DIRECTORY")
    reduce(Path(sys.argv[1]), Path(sys.argv[2]))
