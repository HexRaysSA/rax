#!/usr/bin/env python3
"""Check the retained original fixed-root native oracle; no host access."""
from pathlib import Path
import re
import struct

BASE = Path(__file__).resolve().parent
VIEWS = ("000", "100", "200")
ROOT = r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
PATHS = {
    "": "00000000", "probe.exe": "C0000034",
    r"missing-rax-image.exe\child": "C0000034", r"\probe.exe": "C000003B",
    "missing-rax-image.exe\\": "C0000034",
    r"missing-rax-image.exe\\child": "C0000034", ".": "C0000034", "..": "C0000034",
    r".\probe.exe": "C0000034", "notepad.exe": "00000000",
    "notepad.exe\\": "00000000", r"notepad.exe\\foo": "C0000034",
    r"notepad.exe\missing-rax-filter": "C0000034",
    r"notepad.exe\missing-rax-filter\value": "C0000034", "/": "C0000034",
}


def full_record(fields):
    assert fields["status"] == "00000000"
    raw = bytes.fromhex(fields["bytes"])
    assert int(fields["returned"]) == len(raw) == 44
    words = struct.unpack("<Q9I", raw)
    assert words[1:4] == (0, 0xFFFFFFFF, 0)
    return raw, words


def check(arch, paths):
    suffix = "path-" if paths else ""
    lines = (BASE / f"native-ifeo-{suffix}{arch}.log").read_text().splitlines()
    records = {v: [] for v in VIEWS}
    for line in lines:
        if " view=" not in line:
            assert not any(x in line for x in ("status=", "open=")), line
            continue
        fields = dict(re.findall(r"([\w-]+)=([^ ]*)", line))
        view = fields["view"]
        assert view in records
        records[view].append((line.split()[0], fields))
    canonical = []
    for view, rows in records.items():
        assert len(rows) == (166 if paths else 155), (arch, view, len(rows))
        kind, fields = rows[0]
        assert kind in ("pointer=4", "pointer=8")
        assert fields["pointer"] == ("4" if arch == "x86" else "8")
        assert fields["open"] == "00000000"
        roots = dict((int(f["class"]), f) for k, f in rows if k == "root")
        assert set(roots) == {2, 3}
        raw, full = full_record(roots[2])
        assert (full[4], full[5], full[7]) == (49, 70, 0)
        named = roots[3]
        assert named["status"] == "00000000"
        name = bytes.fromhex(named["bytes"])
        assert int(named["returned"]) == len(name) == 186
        assert struct.unpack_from("<I", name)[0] == 182
        assert name[4:].decode("utf-16-le") == ROOT
        children = [(k, f) for k, f in rows if k.startswith("child")]
        assert len(children) == 147
        names = []
        for index in range(49):
            triplet = children[index * 3:index * 3 + 3]
            assert [k for k, f in triplet] == ["child", "child-open", "child-info"]
            for k, f in triplet:
                assert f["status"] == "00000000" and int(f["index"]) == index
            rawname = bytes.fromhex(triplet[0][1]["name"])
            assert 0 < len(rawname) <= 70 and len(rawname) % 2 == 0
            text = rawname.decode("utf-16-le")
            assert "\\" not in text and "\0" not in text
            childraw, info = full_record(triplet[2][1])
            assert info[4] == (4 if text == "notepad.exe" else 0)
            names.append((rawname, childraw))
        assert len({n for n, _ in names}) == 49
        end = [f for k, f in rows if k == "end"]
        assert len(end) == 1
        assert end[0]["count"] == "49" and end[0]["status"] == "8000001A"
        assert end[0]["returned"] == "A5A5A5A5"
        images = [f for k, f in rows if k == "image-open"]
        if paths:
            found = {bytes.fromhex(f["name-utf16"]).decode("utf-16-le"): f["status"] for f in images}
            assert len(images) == 15 and found == PATHS
        else:
            assert len(images) == 4
            assert {f["name"] for f in images} == {"probe.exe", "smoke.exe", "whoami.exe", "missing-rax-image.exe"}
            assert all(f["status"] == "C0000034" for f in images)
        canonical.append((raw, name, sorted(names)))
    assert canonical[0] == canonical[1] == canonical[2], (arch, "view drift")
    return canonical[0], sum(map(len, records.values()))


def main():
    counts = []
    for paths in (False, True):
        runs = [check(arch, paths) for arch in ("arm64", "x86", "x64")]
        assert runs[0][0] == runs[1][0] == runs[2][0], "ABI namespace drift"
        counts.append(sum(n for _, n in runs))
    assert counts == [1395, 1494]
    print("PASS: 1395 inventory + 1494 relative-path = 2889 native observations")
    print("PASS: all three ABIs/views; raw names/metadata, 49 children, notepad descendants, end status, 15 path statuses")
    print("Scope: one installed build/profile; first-level oracle plus child metadata, not whole-tree value validation")


if __name__ == "__main__":
    main()
