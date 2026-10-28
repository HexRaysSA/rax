"""Verify native region, image metadata and owner-lifetime capture partitions."""

from pathlib import Path
import copy
import hashlib
import json

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(line):
    return dict(p.split("=", 1) for p in line.split() if "=" in p)


def cases(lines):
    selected = []
    current = None
    sections = {}
    for line in lines:
        row = fields(line)
        if line.startswith("section "):
            sections[row["label"]] = int(row["bytes"])
        elif line.startswith("map "):
            if current:
                selected.append(current)
            current = {
                "map": row,
                "regions": [],
                "tail": [],
                "info": [],
                "extension": [],
            }
        elif current:
            for prefix, key in [
                ("region ", "regions"),
                ("tail ", "tail"),
                ("image_info ", "info"),
                ("extension ", "extension"),
            ]:
                if line.startswith(prefix):
                    current[key].append(row)
                    break
            else:
                if line.startswith("owner "):
                    current["owner"] = row
                elif line.startswith("unmap "):
                    current["unmap"] = row
                elif line.startswith("released "):
                    current["released"] = row
    if current:
        selected.append(current)
    return sections, selected


def verify_profile(lines, arch):
    sections, rows = cases(lines)
    require(len(sections) == 9 and len(rows) == 324, "case partition")
    expected = {
        (label, machine, flags, requested, unmap)
        for label, size in sections.items()
        for machine in [0, 0x14C, 0x8664]
        for flags in [0, 0x800000]
        for requested in [0, 4096, size]
        for unmap in [0, 1]
    }
    actual = {
        (
            r["map"]["label"],
            int(r["map"]["machine"], 16),
            int(r["map"]["flags"], 16),
            int(r["map"]["requested"]),
            int(r["map"]["unmap_tail"]),
        )
        for r in rows
    }
    require(actual == expected, "mapping selectors")
    successful = 0
    old_failures = 0
    for case in rows:
        row = case["map"]
        if int(row["status"], 16) & 0x80000000:
            require(not case["regions"] and not case["info"], "failed map has no view")
            continue
        successful += 1
        base = int(row["base"], 16)
        logical = int(row["bytes"])
        extent = int(case["owner"]["bytes"], 16)
        require(
            logical == int(case["owner"]["logical"], 16) and extent >= logical,
            "owner extent",
        )
        partial = int(row["requested"]) == 4096
        hybrid = row["label"].startswith("\\KnownDllsChpe32\\")
        native = row["label"].startswith("\\KnownDlls\\")
        expected_tail = 0 if partial or hybrid else 0x4000
        require(extent - logical == expected_tail, "physical owner tail")
        require(len(case["extension"]) == 2, "extension query partition")
        exposed = all(e["status"] == "00000000" for e in case["extension"])
        if not exposed:
            require(
                fields(lines[0])["bits"] == "32"
                and all(e["status"] == "C0000003" for e in case["extension"]),
                "WoW64 class14 capability",
            )
        if native and not partial and exposed:
            expected_extensions = [(f"{logical:X}", "1000"), ("0", "0")]
            if arch == "x64":
                expected_extensions[1] = (f"{logical + 4096:X}", "1000")
            require(
                [(e["rva"], e["bytes"]) for e in case["extension"]]
                == expected_extensions,
                "native code extension",
            )
        else:
            require(
                all(e["rva"] == "0" and e["bytes"] == "0" for e in case["extension"]),
                "absent code extensions",
            )
        for region in case["regions"]:
            offset = int(region["offset"], 16)
            length = int(region["bytes"], 16)
            require(
                int(region["base"], 16) == base + offset
                and int(region["allocation"], 16) == base
                and region["kind"] == "01000000",
                "region ownership",
            )
            if region["source_predicate"] == "0":
                old_failures += 1
                require(
                    row["label"] == "\\KnownDlls32\\kernel32.dll"
                    and not partial
                    and region["state"] == "00002000"
                    and region["protection"] == "00000000",
                    "old rejected span",
                )
                require(
                    offset == 0xE5000
                    and length == 0xF000
                    and logical - offset == 0xB000,
                    "coalesced reserved run",
                )
        require(len(case["info"]) == 3, "class6 query partition")
        for info in case["info"]:
            require(
                info["status"] == "00000000"
                and int(info["base"], 16) == base
                and int(info["bytes"], 16) == sections[row["label"]],
                "class6 identity",
            )
            expected_flags = 1 if partial else 0x40 if expected_tail else 0
            require(
                int(info["flags"], 16) & 0x43 == expected_flags,
                "class6 partial/extension flags",
            )
        require(
            case["unmap"]["status"] == "00000000"
            and case["released"]["base_state"] == "00010000"
            and case["released"]["allocation"] == "0",
            "complete owner release",
        )
        require(
            int(case["unmap"]["offset"], 16)
            == (logical if int(row["unmap_tail"]) and expected_tail else 0),
            "unmap target",
        )
    require(successful == 216 and old_failures == 16, "verdict partition")
    require(
        lines[-1] == "done cases=324 successful=216 source_predicate_violations=16",
        "terminal",
    )


def main():
    manifest = json.loads((HERE / "native-inputs.json").read_text())
    require(manifest["schema"] == "rax.native-image-view-reserved-tail.v1", "schema")
    source = HERE / manifest["source"]["file"]
    require(
        hashlib.sha256(source.read_bytes()).hexdigest() == manifest["source"]["sha256"],
        "producer source",
    )
    profiles = []
    for row in manifest["profiles"]:
        require(
            row["pe_machine"]
            == {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[row["arch"]],
            "producer PE machine",
        )
        raw = (HERE / row["file"]).read_bytes()
        require(
            len(raw) == row["bytes"]
            and hashlib.sha256(raw).hexdigest() == row["sha256"],
            "stdout identity",
        )
        require(
            row["source_sha256"] == manifest["source"]["sha256"]
            and row["exit_code"] == 0,
            "producer verdict",
        )
        lines = raw.decode().splitlines()
        verify_profile(lines, row["arch"])
        profiles.append(lines)
    require(len(profiles) == 3, "executable profiles")
    damaged = copy.deepcopy(profiles[0])
    index = next(
        i
        for i, line in enumerate(damaged)
        if line.startswith("owner bytes=F4000 logical=F0000")
    )
    damaged[index] = "owner bytes=F0000 logical=F0000"
    try:
        verify_profile(damaged, "arm64")
    except ValueError:
        pass
    else:
        raise ValueError("corrupted owner extent accepted")
    print(
        "verified972 native maps,648 successful views and48 old region rejections; corrupted owner rejected"
    )


if __name__ == "__main__":
    main()
