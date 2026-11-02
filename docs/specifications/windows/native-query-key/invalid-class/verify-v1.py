"""Verify retained invalid-class producer, images, receipt and native bytes."""
from pathlib import Path
import hashlib
import json
import struct

if not __debug__:
    raise RuntimeError("Verification requires Python without -O")

root = Path(__file__).resolve().parent
data = json.loads((root / "observations-v1.json").read_text())
assert data["schema"] == "rax-nt-query-key-invalid-class-v1"
assert data["kernel"] == [10, 0, 29698] and data["native_machine"] == 0xAA64
for name, expected in data["files"].items():
    path = root / name
    assert path.resolve().is_relative_to(root) and not path.is_symlink()
    raw = path.read_bytes()
    assert len(raw) == expected["bytes"]
    assert hashlib.sha256(raw).hexdigest() == expected["sha256"], name
receipt = json.loads((root / "native-receipt-v1.json").read_text())
assert receipt["state"] == "finished" and receipt["exit_code"] == 0 and receipt["inputs_unchanged"]
assert len(receipt["reports"]) == 3 and len(data["cases"]) == 30
for report in receipt["reports"]:
    label = report["architecture"]
    image = (root / "bin" / (label + ".exe")).read_bytes()
    offset = struct.unpack_from("<I", image, 0x3C)[0]
    assert image[:2] == b"MZ" and image[offset:offset + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", image, offset + 4)[0] == report["machine"]
    assert hashlib.sha256(image).hexdigest() == report["image_sha256"]
    assert report["provider_before"] == report["provider_after"]
    assert report["provider_before"]["native_machine"] == 0xAA64
    rows = [row for row in data["cases"] if row["architecture"] == label]
    assert {row["mode"] for row in rows} == set(range(10))
    for row in rows:
        raw = bytes.fromhex(row["stdout_hex"])
        assert len(raw) == 72 and struct.unpack_from("<II", raw) == (row["mode"], 0xC000000D)
        assert raw[8:] == b"\xA5" * 64
        expected = next(case for case in report["cases"] if case["mode"] == row["mode"])
        assert expected["exit_code"] == 0 and expected["arena_unchanged"]
        assert hashlib.sha256(raw).hexdigest() == row["stdout_sha256"] == expected["stdout_sha256"]
print(json.dumps({"verified_files": len(data["files"]), "native_calls": 30, "kernel": data["kernel"]}))
