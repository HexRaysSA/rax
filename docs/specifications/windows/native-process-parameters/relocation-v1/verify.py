"""Verify frozen parameter-relocation evidence and optional live source identity."""

import argparse
import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rax-root", type=Path)
    args = parser.parse_args()
    if not __debug__:
        raise SystemExit("Evidence verification requires assertions enabled")
    manifest = json.loads((HERE / "manifest-v1.json").read_text())
    for name, expected in manifest["sha256"].items():
        path = HERE / name
        assert path.is_file(), name
        assert digest(path.read_bytes()) == expected, name
    for record in json.loads((HERE / "primary/provenance-v1.json").read_text()):
        data = (HERE / "primary" / record["file"]).read_bytes()
        assert len(data) == record["bytes"]
        assert digest(data) == record["sha256"]
    collectors = json.loads((HERE / "collector-sources-v1.json").read_text())
    for source in collectors.values():
        data = source["text"].encode()
        assert len(data) == source["bytes"]
        assert digest(data) == source["sha256"]
    source = json.loads((HERE / "implementation-source-v1.json").read_text())
    assert len(source["files"]) == len(source["source_sha256"]) == 7
    for path, text in source["files"].items():
        assert digest(text.encode()) == source["source_sha256"][path], path
        if args.rax_root is not None:
            assert digest((args.rax_root / path).read_bytes()) == source["source_sha256"][path], path

    captures = json.loads((HERE / "captures-v1.json").read_text())
    assert len(captures) == 7
    expected_dlls = {
        "ntdll_sha256": "e9943254a04813ede84d84b1be5fb4f41537d103d2771449db56a80cf6f301fd",
        "cmd_sha256": "d0424de0995177d23bae66f27d145e9981aa916de45a76af4d75eae2b3507409",
        "kernelbase_sha256": "0b77b8aad45ac9dba87ec0561a496bc1df734974ef04f1a46bbc17f756d075f1",
    }
    corrected = 0
    for capture in captures:
        text = capture["stdout"]
        assert capture["collector_sha256"] == collectors[capture["collector"]]["sha256"]
        assert capture["wrapper_exit_code"] == 0 and capture["stderr"] == ""
        assert f"probe_library_sha256={capture['core_archive_sha256']}" in text
        assert all(capture[key] == value for key, value in expected_dlls.items())
        assert capture["instruction_budget_bound"] == (capture["sample"] + 1) * capture["observation_slice_insns"]
        assert f"NATIVE_EXIT=Some({capture['native_exit_u32']})" in text
        assert "NATIVE_STDERR_HEX=\n" in text
        if capture["case"] == "echo":
            assert "NATIVE_STDOUT_HEX=5241585f50524f434553535f4d41545249585f4137463343320d0a\n" in text
        else:
            assert capture["native_exit_u32"] == 37
        if capture["phase"] == "baseline":
            assert "status=Complete(Exited(0))" in text
        elif capture["phase"] == "precise-fault":
            assert "INSTALLED_EXCEPTION" in text
            assert "params: [0, 55005c003a0043]" in text
            assert "config.slice_insns = 1;" in collectors[capture["collector"]]["text"]
        elif capture["phase"] == "corrected":
            corrected += 1
            assert "PARAMETER_MIGRATION" in text
            assert "active_exception_seen=false" in capture["observed_terminal"]
            assert "NtQueryDirectoryFileEx" in capture["observed_terminal"]
            assert "status=Complete(Exited(" not in capture["observed_terminal"]
            headers = re.findall(r"PARAMETER_HEADER phase=migration base=(0x[0-9a-f]+) length=Ok\(([0-9a-f]+)\)", text)
            assert len(headers) == 2
            for base, length in headers:
                strings = [line for line in text.splitlines() if line.startswith(f"PARAMETER_STRING phase=migration base={base} ")]
                assert len(strings) == 3
                for line in strings:
                    match = re.search(r"length=(\d+) pointer=(0x[0-9a-f]+)", line)
                    offset = int(match[2], 16) - int(base, 16)
                    assert offset >= 0x450
                    assert offset + int(match[1]) + 2 <= int(length, 16)
                    assert 'text=Ok("")' not in line
    assert corrected == 2
    print("verified: seven frozen captures, source/image/DLL bindings and corrected relocation; CMD completion remains unproven")


if __name__ == "__main__":
    main()
