from pathlib import Path
import hashlib
import json

root = Path(__file__).resolve().parent
record = json.loads((root / "provenance-v1.json").read_text())
assert record["schema"] == "rax-native-chpe-context-ownership-29704-v1"
for name, identity in record["sources"].items():
    path = root / name
    assert path.resolve().is_relative_to(root)
    assert path.stat().st_size == identity["bytes"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == identity["sha256"]
assert record["native_kernel"] == "10.0.29704.0"
assert len(record["installed_images"]) == 7 and record["images_unchanged"]
assert len(record["runs"]) == 12
expected = {prefix + arch for prefix in
            ("termination-", "active-", "native-termination-", "native-active-")
            for arch in ("arm64", "x64", "x86")}
assert {run["label"] for run in record["runs"]} == expected
for run in record["runs"]:
    raw = run["stdout"].encode("utf-8")
    assert hashlib.sha256(raw).hexdigest() == run["stdout_sha256"]
    assert run["exit_code"] == 0 and run["stderr_bytes"] == 0
    if run["label"].startswith("native-termination-"):
        assert raw == b""
        continue
    if run["label"].startswith("native-active-"):
        parts = raw.decode("utf-8").split()
        assert parts[0] == "state" and len(parts) == 65
        values = [int(word, 16) for word in parts[1:]]
        assert (values[0], values[1], values[6], values[10], values[12]) == (
            0x52415854, 4, 0, 78, 1)
        continue
    lines = [line for line in raw.decode("utf-8").splitlines() if line.startswith("{")]
    assert len(lines) == 1
    guest = json.loads(lines[0])
    assert guest["terminal"] == "Exited(0)" and guest["threads"] == []
    assert guest["failure_index"] == 0
    active = run["label"].startswith("active-")
    assert (guest["assertions"], guest["completed_cases"]) == ((78, 4) if active else (97, 8))
    if active:
        assert guest["observations"][12] == 1
print("Verified six natural emulated exits and six independent native controls.")
