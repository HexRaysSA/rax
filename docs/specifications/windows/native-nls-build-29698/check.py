"""Verify the finite 29698 NLS profile or project its retained native archive."""

import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
ARCHIVE_SHA256 = "1a408d63fc0fed369abec8bda84dd738ae6df24a4b134a77e612359414c53f4d"
ARCHES = ("arm64", "x64", "x86", "x86-laa")
SPEC = importlib.util.spec_from_file_location(
    "nls_29695_controls", HERE.parent / "native-nls-build-29695/check.py"
)
PRIOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRIOR)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def collect(path):
    require(digest(path.read_bytes()) == ARCHIVE_SHA256, "retained archive identity")
    with zipfile.ZipFile(path) as bundle:
        manifest = json.loads(bundle.read("archive-manifest.json"))
        names = bundle.namelist()
        require(len(names) == len(set(names)) == len(manifest) + 1, "unique payloads")
        require(set(names) == set(manifest) | {"archive-manifest.json"}, "complete manifest")
        for name, expected in manifest.items():
            member = PurePosixPath(name)
            require(not member.is_absolute() and ".." not in member.parts, "member path")
            raw = bundle.read(name)
            require(len(raw) == expected["bytes"] and digest(raw) == expected["sha256"], name)
        receipt = json.loads(bundle.read("receipt.json"))
        require(receipt["state"] == "finished" and receipt["inputs_unchanged"], "native completion")
        require(receipt["kernel"][:3] == [10, 0, 29698], "native kernel")
        require(len(receipt["samples"]) == 16, "sixteen native controls")
        for name, expected in receipt["source_inputs"].items():
            require(digest(bundle.read("source/" + name)) == expected, "frozen producer " + name)
            require(digest((REPO / name).read_bytes()) == expected, "retained source " + name)
        for arch in ARCHES:
            provider = receipt["providers"][arch]
            native_arch = "x86" if arch == "x86-laa" else arch
            require(
                digest(bundle.read("providers/" + native_arch + "-ntdll.dll"))
                == provider["before_sha256"] == provider["after_sha256"],
                "physical native provider",
            )
            require(
                digest(bundle.read("identity/" + native_arch + ".exe"))
                == provider["identity_image_sha256"], "identity producer",
            )
            before = json.loads(bundle.read(arch + "-identity-before.log"))
            after = json.loads(bundle.read(arch + "-identity-after.log"))
            require(before == after == provider["identity_before"], "live provider binding")
            mapped = bytes.fromhex(before["mapped_provider_utf16"]).decode("utf-16le")
            require(mapped == provider["mapped_native_path"], "mapped physical provider path")
            expected_directory = "sychpe32" if native_arch == "x86" else "system32"
            require("\\" + expected_directory + "\\" in provider["path"].lower(), "provider redirection")
        samples = {(row["arch"], row["kind"]): row for row in receipt["samples"]}
        require(len(samples) == 16, "unique process/control pairs")
        profiles, leaves, payloads = [], {}, []
        for arch in ARCHES:
            machine = {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C, "x86-laa": 0x14C}[arch]
            for kind in ("leaf", "initialize", "protect", "mui"):
                sample = samples[arch, kind]
                image = bundle.read("build-" + arch + "/Release/" + kind + ".exe")
                require(len(image) == sample["binary_bytes"] and digest(image) == sample["binary_sha256"], "native executable")
                pe = struct.unpack_from("<I", image, 0x3C)[0]
                require(image[pe:pe + 4] == b"PE\0\0", "native PE signature")
                require(struct.unpack_from("<H", image, pe + 4)[0] == machine == sample["machine"], "native PE machine")
                raw = bundle.read(arch + "-" + kind + "-observe.log")
                require(sample["exit_code"] == 0 and digest(raw) == sample["stdout_sha256"], "native stdout")
                text = raw.decode("ascii")
                if kind == "leaf":
                    rows = [PRIOR.fields(line) for line in text.splitlines() if line.startswith("leaf ")]
                    require(len(rows) == 3, "three actual installed leaves")
                    leaves[arch] = rows
                    if arch.startswith("x86"):
                        require(bytes.fromhex(rows[0]["hex"])[12:15] == b"\xc2\x0c\0", "x86 RET12")
                    continue
                canonicalize = {"initialize": PRIOR.initialize, "protect": PRIOR.protection, "mui": PRIOR.mui}[kind]
                fresh = canonicalize(text)
                require(fresh == canonicalize(PRIOR.prior(arch, kind)), "native semantic equality " + arch + "/" + kind)
                profiles.append({"arch": arch, "kind": kind, "rows": len(fresh),
                                 "canonical_sha256": PRIOR.signature(fresh),
                                 "native_stdout_sha256": digest(raw)})
                if kind == "mui":
                    payload = bundle.read(arch + "-mui/mui.bin")
                    require(len(payload) == sample["payload"]["bytes"] == 1232, "query payload width")
                    require(digest(payload) == sample["payload"]["sha256"], "query payload identity")
                    payloads.append(digest(payload))
        generation = receipt["generation"]
        require(generation["state"] == "finished" and generation["kernel"][:3] == [10, 0, 29698], "generation capture")
        require(len(generation["rows"]) == 3 and len(set(payloads)) == 1, "stable cross-ABI query bytes")
        for row in generation["rows"]:
            require(row["shared-before"] == row["payload-generation"] == row["shared-after"] == 1, "shared/payload generation")
            require(row["sha256"] == payloads[0] and row["bytes"] == 1232, "independent query capture")
        locale = bundle.read("installed/locale.nls")
        require(len(locale) == receipt["locale_nls"]["bytes"] and digest(locale) == receipt["locale_nls"]["sha256"], "installed locale file")
        return {"schema": 1, "kernel": [10, 0, 29698], "native_machine": 0xAA64,
                "scope": "One ARM64 kernel and four process profiles; no independent AMD64 kernel claim.",
                "profiles": profiles, "leaves": leaves, "generation": generation,
                "locale_nls": receipt["locale_nls"], "sources": receipt["source_inputs"],
                "samples": receipt["samples"], "providers": receipt["providers"],
                "archive": {"bytes": path.stat().st_size, "sha256": ARCHIVE_SHA256,
                            "payloads": len(manifest)}, "native_inputs_unchanged": True}


def main():
    require(__debug__, "optimized validation rejected")
    if len(sys.argv) == 2:
        print(json.dumps(collect(Path(sys.argv[1])), indent=2))
        return
    require(len(sys.argv) == 1, "usage: check.py [retained-native-results.zip]")
    record = json.loads((HERE / "profile-29698-v1.json").read_text())
    require(record["kernel"] == [10, 0, 29698] and record["native_machine"] == 0xAA64, "finite profile")
    for name, expected in record["sources"].items():
        require(digest((REPO / name).read_bytes()) == expected, "source identity " + name)
    require(len(record["profiles"]) == 12 and len(record["samples"]) == 16, "complete profile")
    require(record["native_inputs_unchanged"] is True, "native input stability")
    require(set(record["leaves"]) == set(ARCHES), "four export profiles")
    for arch, rows in record["leaves"].items():
        require(len(rows) == 3, "three retained exports")
        if arch.startswith("x86"):
            require(bytes.fromhex(rows[0]["hex"])[12:15] == b"\xc2\x0c\0", "retained x86 RET12")
    generation = record["generation"]
    require(generation["state"] == "finished" and len(generation["rows"]) == 3, "generation profile")
    for row in generation["rows"]:
        require(row["shared-before"] == row["payload-generation"] == row["shared-after"] == 1, "retained generation")
        require(row["bytes"] == 1232, "retained query extent")
    for row in record["profiles"]:
        canonicalize = {"initialize": PRIOR.initialize, "protect": PRIOR.protection, "mui": PRIOR.mui}[row["kind"]]
        old = canonicalize(PRIOR.prior(row["arch"], row["kind"]))
        require(len(old) == row["rows"] and PRIOR.signature(old) == row["canonical_sha256"], "retained native semantics")
    require(record["archive"]["sha256"] == ARCHIVE_SHA256, "archive provenance")
    print("Verified 29698: 316 initialization, 48 protection, 6720 MUI rows, 12 leaves and 3 generation captures")


if __name__ == "__main__":
    main()
