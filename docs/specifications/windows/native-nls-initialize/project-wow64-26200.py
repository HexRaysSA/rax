"""Verify Windows 26200 x86 initialization observations against the retained controls."""

import importlib.util
import json
import sys
from pathlib import Path, PureWindowsPath

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "retained_nls", HERE.parent / "native-nls-build-29695" / "check.py"
)
PRIOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRIOR)


def hashes(path):
    rows = json.loads(path.read_bytes())
    result = {PureWindowsPath(row["Path"]): row["Hash"].lower() for row in rows}
    assert len(result) == len(rows)
    return result


def selected(records, tail):
    matches = [value for path, value in records.items()
               if path.parts[-len(tail):] == tail]
    assert len(matches) == 1
    return matches[0]


def load_log(path, provider):
    raw = path.read_bytes()
    lines = raw.decode("ascii").splitlines()
    prefix = "installed-ntdll="
    assert lines[0].startswith(prefix)
    mapped = PureWindowsPath(lines[0][len(prefix):])
    assert mapped.parts[-2:] == (provider, "ntdll.dll")
    return raw, lines[1:]


def initialization(lines, reference, locale_bytes):
    rows = PRIOR.initialize("\n".join(lines))
    assert rows == reference
    extent = (locale_bytes + 4095) & ~4095
    mappings = [PRIOR.fields(line) for line in lines if line.startswith("mapping ")]
    unmapped = [PRIOR.fields(line)["status"] for line in lines if line.startswith("unmap ")]
    retained = sum(row["new_views"] for row in rows
                   if PRIOR.fields(row["case"])["status"] != "00000000")
    assert retained == 4
    assert len(mappings) == len(unmapped) == sum(row["new_views"] for row in rows) - retained
    assert all(status == "00000000" for status in unmapped)
    for mapping in mappings:
        assert mapping["base"] == mapping["allocation"]
        assert int(mapping["bytes"]) == extent
        assert (mapping["state"], mapping["protect"], mapping["allocation-protect"],
                mapping["type"]) == ("00001000", "00000002", "00000002", "00040000")
        assert PureWindowsPath(mapping["filename"]).parts[-2:] == ("System32", "locale.nls")
    return rows


def protection(lines, reference):
    rows = PRIOR.protection("\n".join(lines))
    assert rows == reference
    for line in lines:
        if line.startswith("case "):
            case = PRIOR.fields(line)
            assert case["base"] == case["result-base"]
            assert int(case["result-size"]) in (0, 4096)
        elif line.startswith("unmap "):
            assert PRIOR.fields(line)["status"] == "00000000"
    return rows


def leaves(lines):
    rows = [PRIOR.fields(line) for line in lines if line.startswith("leaf ")]
    assert len(rows) == 3 and lines[-1] == "complete leaves=3"
    for row, (name, number, cleanup) in zip(rows, (
        ("NtInitializeNlsFiles", 0x108, 12),
        ("NtGetNlsSectionPtr", 0x102, 20),
        ("NtUnmapViewOfSection", 0x2a, 8),
    ), strict=True):
        entry = bytes.fromhex(row["hex"])
        assert row["name"] == name and row["pointer-bytes"] == "4"
        assert entry[0] == 0xb8 and int.from_bytes(entry[1:5], "little") == number
        assert entry[12:15] == bytes((0xc2, cleanup, 0))
    return rows


def project(root):
    inputs = hashes(root / "before.json")
    assert inputs == hashes(root / "after.json")
    prior_arm64 = json.loads((HERE / "profile-arm64-26200-v1.json").read_text())
    locale = selected(inputs, ("System32", "locale.nls"))
    locale_bytes = int((root / "locale-length.txt").read_text(encoding="utf-8-sig"))
    assert locale == prior_arm64["locale_sha256"] and locale_bytes == prior_arm64["locale_bytes"]
    providers = {provider: selected(inputs, (provider, "ntdll.dll"))
                 for provider in ("System32", "SysWOW64", "SyChpe32")}
    assert providers["System32"] == prior_arm64["ntdll_sha256"]
    compilers = json.loads((root / "producers.json").read_bytes())
    executables = hashes(root / "executable-identities.json")
    records = []
    for kind, variant, arch in (
        ("initialize", "standard", "x86"),
        ("initialize", "large", "x86-laa"),
        ("initialize-protection", "standard", "x86"),
        ("initialize-leaf", "standard", "x86"),
    ):
        sources = compilers[kind]
        original = f"native-nls-{kind}.cpp"
        assert sources[original] == selected(inputs, (original,))
        assert sources[original] == PRIOR.digest((HERE / original).read_bytes())
        assert (sources["observer.cpp"] == selected(executables, (kind, "observer.cpp"))
                == PRIOR.digest((root / kind / "observer.cpp").read_bytes()))
        executable = sources[variant + ".exe"]
        assert executable == selected(executables, (kind, variant + ".exe"))
        for mode, provider in (("default", "SysWOW64"), ("disabled", "SysWOW64"),
                               ("enabled", "SyChpe32")):
            raw, lines = load_log(root / kind / variant / (mode + ".log"), provider)
            if kind == "initialize":
                reference = PRIOR.initialize(PRIOR.prior(arch, "initialize"))
                rows = initialization(lines, reference, locale_bytes)
            elif kind == "initialize-protection":
                reference = PRIOR.protection(PRIOR.prior(arch, "protect"))
                rows = protection(lines, reference)
            else:
                rows = leaves(lines)
            records.append({
                "kind": kind, "process": arch, "mode": mode, "provider": provider,
                "rows": len(rows), "canonical_sha256": PRIOR.signature(rows),
                "stdout_sha256": PRIOR.digest(raw), "executable_sha256": executable,
            })
    return {
        "kernel": [10, 0, 26200], "native_machine": 0xaa64, "run": 45156726419,
        "providers_sha256": providers,
        "locale_nls": {"bytes": locale_bytes, "sha256": locale},
        "launcher_sha256": selected(executables, ("launcher.exe",)),
        "source_sha256": compilers, "observations": records,
    }


if __name__ == "__main__":
    assert __debug__ and len(sys.argv) == 2
    print(json.dumps(project(Path(sys.argv[1])), indent=2))
