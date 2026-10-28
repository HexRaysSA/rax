"""Verify captured process-profile controls independently of RAX execution."""

from pathlib import Path
import copy
import hashlib
import json

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(line):
    return dict(part.split("=", 1) for part in line.split() if "=" in part)


def verify(corpus):
    require(corpus["schema"] == "rax.native-x86-chpe-profile.v1", "schema")
    require(
        corpus["kernel"]
        == {"major": 10, "minor": 0, "build": 29695, "native_machine": 0xAA64},
        "kernel",
    )
    require(corpus["provenance"]["inputs_unchanged"], "input identity")
    for name, digest in corpus["provenance"]["source_sha256"].items():
        source = HERE.parents[3] / name
        require(
            hashlib.sha256(source.read_bytes()).hexdigest() == digest,
            "producer identity",
        )
    require(
        [p["attribute_value"] for p in corpus["profiles"]] == [None, 1, 0],
        "profile partition",
    )
    total = 0
    for profile in corpus["profiles"]:
        lines = profile["stdout"]
        encoded = ("\n".join(lines) + "\n").encode()
        require(
            hashlib.sha256(encoded).hexdigest() == profile["stdout_sha256"],
            "stdout identity",
        )
        require(
            profile["identity"]
            == "identity bits=32 build=29695 process=014C native=AA64",
            "process identity",
        )
        require(
            profile["wow64"]
            == {
                "page_size": 4096,
                "cpu_flags": 2,
                "native_machine": 0xAA64,
                "guest_machine": 0x14C,
            },
            "WoW64 identity",
        )
        native_wow = fields(next(line for line in lines if line.startswith("wow64 ")))
        raw = bytes.fromhex(native_wow["information"])
        require(
            native_wow["status"] == "00000000"
            and native_wow["returned"] == "24"
            and len(raw) == 40,
            "WoW64 query",
        )
        require(
            [
                int.from_bytes(raw[a:b], "little")
                for a, b in [(0, 4), (4, 8), (32, 34), (34, 36)]
            ]
            == [4096, 2, 0xAA64, 0x14C],
            "WoW64 captured fields",
        )
        hybrid = profile["attribute_value"] == 1
        directory = "SyChpe32" if hybrid else "SysWOW64"
        sizes = {
            "ntdll.dll": 2494464 if hybrid else 1863680,
            "kernel32.dll": 1183744 if hybrid else 983040,
            "kernelbase.dll": 4067328 if hybrid else 3088384,
        }
        images = [
            fields(line)
            for line in lines
            if line.startswith(("image kind=loaded ", "image kind=relative "))
        ]
        require(len(images) == 6, "loaded/relative partition")
        seen = set()
        for row in images:
            name = row["label"].removeprefix("relative32:")
            key = (row["kind"], name)
            require(key not in seen and name in sizes, "image partition")
            seen.add(key)
            require(
                row["machine"] == "014C"
                and row["magic"] == "010B"
                and int(row["bytes"]) == sizes[name],
                "image profile",
            )
            require(row["backing_status"] == "00000000", "backing query")
            encoded_path = row["backing_utf16"]
            path = "".join(
                chr(int(encoded_path[i : i + 4], 16))
                for i in range(0, len(encoded_path), 4)
            )
            require(
                path.lower().endswith(
                    ("\\Windows\\" + directory + "\\" + name).lower()
                ),
                "process image selection",
            )
            if name == "ntdll.dll":
                require(
                    row["__C_specific_handler_rva"]
                    == ("000060F0" if hybrid else "00000000"),
                    "NTDLL export profile",
                )
        maps = [
            fields(line) for line in lines if line.startswith(("map ", "relative_map "))
        ]
        require(len(maps) == 39, "map count")
        absolute = [fields(line) for line in lines if line.startswith("map ")]
        expected = {
            (f"\\{root}\\{name}", machine)
            for root in ["KnownDlls", "KnownDlls32", "KnownDllsChpe32"]
            for name in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]
            for machine in [0, 0x14C, 0xAA64, 0x8664]
        }
        require(
            len(absolute) == 36
            and {(row["label"], int(row["request"], 16)) for row in absolute}
            == expected,
            "absolute map partition",
        )
        relative = [fields(line) for line in lines if line.startswith("relative_map ")]
        require(
            len(relative) == 3
            and {row["label"] for row in relative}
            == {"relative32:" + name for name in sizes},
            "relative map partition",
        )
        require(
            sum(not (int(row["status"], 16) & 0x80000000) for row in maps) == 24,
            "successful map count",
        )
        require(
            lines[-1] == profile["terminal"] == "done cases=39 successful=24",
            "terminal",
        )
        total += len(maps)
    require(total == 117, "total partition")
    return total


def main():
    corpus = json.loads((HERE / "local-29695-v1.json").read_text())
    total = verify(corpus)
    damaged = copy.deepcopy(corpus)
    profile = damaged["profiles"][2]
    profile["stdout"] = [
        line.replace(
            "0053007900730057004F005700360034", "00530079004300680070006500330032"
        )
        for line in profile["stdout"]
    ]
    profile["stdout_sha256"] = hashlib.sha256(
        ("\n".join(profile["stdout"]) + "\n").encode()
    ).hexdigest()
    try:
        verify(damaged)
    except ValueError:
        pass
    else:
        raise ValueError("corrupted disabled-profile backing accepted")
    print(f"verified {total} native map controls; corrupted profile rejected")


if __name__ == "__main__":
    main()
