"""Check the 2026-10-10 build29683 raw query matrix, without invoking RAX.

Values below belong to this retained oracle capture, not installed defaults.
Only defined aligned output is compared; allocator-dependent WoW64 role output
is excluded. Run with Python 3 from any directory; no external dependencies.
"""
from pathlib import Path
import re
import struct

VALUES = {
    "ACP": "1252\0", "OEMCP": "437\0", "MACCP": "10000\0",
    "1252": "c_1252.nls\0", "437": "c_437.nls\0", "10000": "c_10000.nls\0",
}
ROW = re.compile(
    r"query pointer=\d+ name=([^ ]+) class=(\d+) length=(\d+) "
    r"status=([0-9A-F]+) returned=([0-9A-F]+) bytes=([0-9A-F]+)"
)


def expected(key, kind, length):
    if kind > 4:
        return 0xC000000D, 0xA5A5A5A5, b""
    if key not in VALUES:
        return 0xC0000034, 0xA5A5A5A5, b""
    name, data = key.encode("utf-16le"), VALUES[key].encode("utf-16le")
    if kind == 0:
        result, header = struct.pack("<III", 0, 1, len(name)) + name, 12
    elif kind in (1, 3):
        offset = (20 + len(name) + 7) & ~7
        result = struct.pack("<IIIII", 0, 1, offset, len(data), len(name))
        result += name + bytes(offset - 20 - len(name)) + data
        header = 20
    elif kind == 2:
        result, header = struct.pack("<III", 0, 1, len(data)) + data, 12
    else:
        result, header = struct.pack("<II", 1, len(data)) + data, 8
    required = len(result)
    if length < header:
        return 0xC0000023, required, b""
    status = 0x80000005 if length < required else 0
    prefix = bytearray(result[:length])
    if kind in (0, 1, 3) and header < length < header + len(name) and length % 2:
        prefix[-1] = 0
    return status, required, bytes(prefix)


def main():
    root = Path(__file__).resolve().parent
    for arch in ("arm64", "x86", "x64"):
        count = 0
        for line in (root / f"native-registry-{arch}.log").read_text().splitlines():
            match = ROW.fullmatch(line)
            if not match:
                continue
            key, kind, length, status, returned, raw = match.groups()
            key = "ACP" if key == "aCp" else key
            wanted, size, prefix = expected(key, int(kind), int(length))
            actual = bytes.fromhex(raw)
            assert int(status, 16) == wanted, (arch, match.groups(), "status")
            assert int(returned, 16) == size, (arch, match.groups(), "ResultLength")
            assert actual == prefix + bytes([0xA5]) * (len(actual) - len(prefix)), (
                arch, match.groups(), "defined output/tail"
            )
            count += 1
        assert count == 1134, (arch, count)
        print(f"{arch}: {count} aligned native matrix rows verified")


if __name__ == "__main__":
    main()
