"""Verify finite NLS qualification; optionally inspect the original result ZIPs.

With two ZIP arguments, emit the typed projection. With no arguments, verify
the published projection against its retained sources and prior native corpus.
Only relocated base-output bytes are normalized in initialization comparisons.
"""

from pathlib import Path
import hashlib
import json
import sys
import zipfile

HERE = Path(__file__).resolve().parent
WINDOWS = HERE.parent
REPO = HERE.parents[3]
ARCHES = ("arm64", "x64", "x86", "x86-laa")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fields(line):
    return dict(word.split("=", 1) for word in line.split() if "=" in word)


def signature(rows):
    return digest(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())


def initialize(text):
    lines, rows = text.splitlines(), []
    for index, line in enumerate(lines):
        if not line.startswith("case "):
            continue
        case = fields(line)
        view = fields(lines[index + 2])
        output = bytearray.fromhex(fields(lines[index + 3])["hex"])
        require(len(output) == 144, "exact scratch output extent")
        width = int(case["pointer-bytes"])
        variants = [
            (
                int(case["variant"])
                if argument == int(case["argument"])
                else int(case["other-variant"]) if argument == int(case["other"]) else 0
            )
            for argument in range(4)
        ]

        def offset(argument):
            variant = variants[argument]
            if variant in (0, 5):
                return 256 + argument * 32 + (variant == 5)
            return 384 if variant == 8 else None

        start, locale = offset(0), offset(1)
        if int(case["status"], 16) == 0 and start is not None:
            require(
                int(view["after"]) - int(view["before"]) == 1,
                "successful call owns one new view",
            )
            native_base = int(view["new"], 16).to_bytes(width, "little")
            for byte in range(width):
                address = start + byte
                # Native64 aliases retain the later locale store. WoW64 stores
                # the pointer last. All other observed output bytes stay exact.
                if width == 8 and locale is not None and locale <= address < locale + 4:
                    continue
                require(
                    output[address - 256] == native_base[byte],
                    "actual returned base matches enumerated new view",
                )
                output[address - 256] = 0
        rows.append(
            {
                "case": line,
                "guard": lines[index + 1],
                "new_views": int(view["after"]) - int(view["before"]),
                "outputs": output.hex(),
            }
        )
    require(len(rows) == 79, "complete initialization profile")
    require(
        [int(fields(row["case"])["ordinal"]) for row in rows] == list(range(79)),
        "ordinals",
    )
    require(
        all(fields(row["case"])["seh"] == "00000000" for row in rows), "no caller SEH"
    )
    return rows


def protection(text):
    rows = [fields(line) for line in text.splitlines() if line.startswith("case ")]
    require(len(rows) == 12, "complete protection/free profile")
    keys = (
        "ordinal",
        "operation",
        "requested",
        "status",
        "old",
        "state",
        "protection",
        "type",
    )
    return [{key: row[key] for key in keys} for row in rows]


def mui(text):
    rows = [line for line in text.splitlines() if line.startswith("row ")]
    require(len(rows) == 1680, "complete query-only MUI profile")
    return rows


def prior(arch, kind):
    if kind == "mui":
        name = "x86" if arch == "x86-laa" else arch
        return (
            WINDOWS / "native-mui-query" / f"native-mui-query-v2-{name}.log"
        ).read_text()
    suffix = "" if kind == "initialize" else "-protection"
    return (
        WINDOWS / "native-nls-initialize" / f"native-nls-initialize{suffix}-{arch}.log"
    ).read_text()


def collect(first, second):
    result = {
        "kernel": [10, 0, 29695],
        "scope": "One ARM64 kernel; native ARM64 and compatibility x64/x86/x86-LAA processes",
        "profiles": [],
        "sources": {},
        "samples": [],
    }
    with zipfile.ZipFile(first) as native, zipfile.ZipFile(second) as wow:
        receipts = [json.loads(z.read("receipt.json")) for z in (native, wow)]
        for receipt in receipts:
            require(receipt["kernel"][:3] == result["kernel"], "observed kernel")
            require(
                receipt["state"] == "finished" and receipt["exit_code"] == 0,
                "native controller terminal success",
            )
            require(
                all(
                    row["exit_code"] == 0 and row["inputs_unchanged"]
                    for row in receipt["samples"]
                ),
                "all immutable native inputs",
            )
            result["samples"].extend(receipt["samples"])
        require(len(result["samples"]) == 16, "sixteen native producers")
        for arch in ARCHES:
            for kind, canonicalize in (
                ("initialize", initialize),
                ("protect", protection),
                ("mui", mui),
            ):
                selected = wow if arch.startswith("x86") and kind != "mui" else native
                raw = selected.read(f"{arch}-{kind}-observe.log")
                text = raw.decode()
                fresh = canonicalize(text)
                old = canonicalize(prior(arch, kind))
                require(fresh == old, f"native semantic equality {arch}/{kind}")
                result["profiles"].append(
                    {
                        "arch": arch,
                        "kind": kind,
                        "rows": len(fresh),
                        "native_stdout_sha256": digest(raw),
                        "canonical_sha256": signature(fresh),
                    }
                )
            leaf = native.read(f"{arch}-leaf-observe.log").decode().splitlines()[0]
            if arch.startswith("x86"):
                require(
                    bytes.fromhex(fields(leaf)["hex"])[12:15] == b"\xc2\x0c\0",
                    "measured x86 RET12",
                )
        generation = receipts[1]["generation"]
        require(generation["kernel"][:3] == result["kernel"], "generation kernel")
        require(
            len(generation["rows"]) == 3
            and all(
                row["shared-before"]
                == row["payload-generation"]
                == row["shared-after"]
                == 1
                for row in generation["rows"]
            ),
            "stable shared language generation",
        )
        result["generation"] = generation
        result["locale_nls"] = receipts[1]["locale_nls"]
    for path in [
        HERE / "native-nls-initialize-v2.cpp",
        HERE / "native-nls-initialize-protection-v2.cpp",
        HERE / "capture-native-mui-generation-29695-v2.py",
        HERE / "observe-controller-v1.py",
        HERE / "wow64-controller-v1.py",
        WINDOWS / "native-nls-initialize/native-nls-initialize.cpp",
        WINDOWS / "native-nls-initialize/native-nls-initialize-protection.cpp",
        WINDOWS / "native-nls-initialize/native-nls-initialize-leaf.cpp",
        WINDOWS / "native-mui-query/native-mui-query-v2.cpp",
    ]:
        result["sources"][str(path.relative_to(REPO))] = digest(path.read_bytes())
    result["archives"] = [
        {
            "name": Path(path).name,
            "bytes": Path(path).stat().st_size,
            "sha256": digest(Path(path).read_bytes()),
        }
        for path in (first, second)
    ]
    return result


def main():
    require(__debug__, "optimized verification rejected")
    if len(sys.argv) == 3:
        print(json.dumps(collect(*sys.argv[1:]), indent=2))
        return
    require(
        len(sys.argv) == 1, "usage: check.py [native-results.zip wow64-results.zip]"
    )
    record = json.loads((HERE / "profile-29695-v1.json").read_text())
    for name, expected in record["sources"].items():
        require(
            digest((REPO / name).read_bytes()) == expected, "source identity " + name
        )
    for row in record["profiles"]:
        canonicalize = {"initialize": initialize, "protect": protection, "mui": mui}[
            row["kind"]
        ]
        old = canonicalize(prior(row["arch"], row["kind"]))
        require(
            len(old) == row["rows"] and signature(old) == row["canonical_sha256"],
            "retained native semantic signature",
        )
    require(len(record["profiles"]) == 12, "four profiles of three interfaces")
    print(
        "Verified29695sourceidentities,316initializationrows,48protectionrows,6720MUIrows,and3generationobservations"
    )


if __name__ == "__main__":
    main()
