"""Read-only verification of native fixture membership, hashes, and source binding."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

here = Path(__file__).resolve().parent
bindings = json.loads((here / "native-bindings-v1.json").read_text())["artifacts"]
expected = {f"{kind}-{arch}-v1.jsonl" for kind in ["pointer", "abi"] for arch in ["arm64", "x64", "x86"]}
assert {row["file"] for row in bindings} == expected
assert len(bindings) == 6
sources = json.loads((here / "probe-source-bindings-v1.json").read_text())
source_hashes = {}
for source in sources:
    if "file" in source:
        data = (here / source["file"]).read_bytes()
        assert len(data) == source["bytes"]
        assert hashlib.sha256(data).hexdigest() == source["sha256"]
        source_hashes[source["file"]] = source["sha256"]
for row in bindings:
    data = (here / row["file"]).read_bytes()
    assert len(data) == row["bytes"]
    assert hashlib.sha256(data).hexdigest() == row["sha256"]
    records = [json.loads(line) for line in data.splitlines()]
    kind = row["file"].split("-")[0]
    assert len(records) == (833 if kind == "pointer" else 451)
    assert records[0]["kind"] == "profile"
    expected_width = 4 if row["process_abi"] == "x86" else 8
    assert records[0]["pointer_bytes"] == expected_width
    source = "native-policy-pointer-v1.cpp" if kind == "pointer" else "native-policy-abi-v1.cpp"
    assert row["source_sha256"] == source_hashes[source]
    assert row["native_exit_code"] == 0
    if kind == "pointer":
        assert [record["index"] for record in records[1:]] == list(range(832))
        for record in records[1:]:
            assert record["exception"] == "0x00000000"
            assert len(record["protections"]) == 8
            for offset, value in record["changes"]:
                assert 0 <= offset < 32768
                assert offset + len(bytes.fromhex(value)) <= 32768
for mode in ["response", "input"]:
    subprocess.run([sys.executable, str(here / "generate-cipher-probe.py"), mode, "--check"], check=True)
cipher_binding = json.loads((here / "cipher-bindings-v1.json").read_text())
cipher_bytes = (here / cipher_binding["corpus_file"]).read_bytes()
assert hashlib.sha256(cipher_bytes).hexdigest() == cipher_binding["corpus_sha256"]
for producer in cipher_binding["native_producers"]:
    source = next(row for row in sources if row.get("mode") == producer["mode"])
    assert producer["source_sha256"] == source["source_sha256"]
    assert producer["native_exit"] == 0
cipher = json.loads(cipher_bytes)
assert cipher["schema"] == "rax-native-system-policy-cipher-controls-v1"
assert len(cipher["cases"]) == 296
assert sum(case["native_status"] == 0 for case in cipher["cases"]) == 266
for case in cipher["cases"]:
    assert len(bytes.fromhex(case["request_hex"])) <= 2 << 20
    assert case["native_returned"] == 32
    if case["native_status"] == 0:
        assert len(bytes.fromhex(case["reply_context"])) == 160
        assert len(bytes.fromhex(case["cipher_prefix"])) == len(bytes.fromhex(case["plain_prefix"]))
        assert len(case["reply_fields"]) == 6
print("verified: 1350 native ABI cases, 2496 complete native arenas, 296 cipher/query controls, 4 native source bindings")
