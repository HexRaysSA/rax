"""Frozen native key-view controls and acquisition identity checks."""

import hashlib
import json
from pathlib import Path
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Provenance(unittest.TestCase):
    def test_frozen_inputs(self):
        manifest = json.loads((ROOT / "provenance.json").read_text())
        self.assertTrue(manifest["raw_bytes_frozen"])
        self.assertEqual(len(manifest["files"]), 3)
        for name, expected in manifest["files"].items():
            raw = (ROOT / name).read_bytes()
            self.assertEqual(len(raw), expected["bytes"])
            self.assertEqual(digest(raw), expected["sha256"])

    def test_references(self):
        rows = json.loads((ROOT / "references/provenance.json").read_text())
        self.assertEqual(len(rows), 2)
        for row in rows:
            raw = (ROOT / "references" / row["file"]).read_bytes()
            self.assertEqual(len(raw), row["bytes"])
            self.assertEqual(digest(raw), row["sha256"])
            self.assertTrue(row["url"].startswith("https://learn.microsoft.com/"))

    def test_native_acquisition(self):
        helper = ROOT.parent / "native-exception-entry-profile/run-v2.py"
        with zipfile.ZipFile(ROOT / "capture-v1.zip") as archive:
            self.assertIsNone(archive.testzip())
            receipt = json.loads(archive.read("capture/receipt.json"))
            self.assertEqual((receipt["state"], receipt["exit_code"]), ("finished", 0))
            self.assertEqual(receipt["kernel"][:3], [10, 0, 29695])
            self.assertEqual(receipt["native_machine"], 0xAA64)
            self.assertEqual(
                receipt["source_sha256"], digest((ROOT / "run-v1.py").read_bytes())
            )
            self.assertEqual(
                receipt["compiler_adapter_sha256"], digest(helper.read_bytes())
            )
            self.assertEqual(
                [r["label"] for r in receipt["rows"]],
                ["arm64", "x64", "x86", "x86-laa"],
            )
            for entry in receipt["rows"]:
                label = entry["label"]
                with self.subTest(label=label):
                    probe = entry["probes"]["v1"]
                    raw = archive.read(f"capture/{label}/stdout-v1.jsonl")
                    self.assertEqual(raw, probe["text"].encode())
                    self.assertEqual(digest(raw), probe["stdout_sha256"])
                    self.assertEqual(
                        archive.read(f"capture/{label}/stderr-v1.log"), b""
                    )
                    self.assertEqual(
                        probe["source_sha256"],
                        digest((ROOT / "probe-v1.cpp").read_bytes()),
                    )
                    self.assertEqual(
                        probe["source_after_sha256"], probe["source_sha256"]
                    )
                    self.assertEqual(
                        probe["exe_before_sha256"], probe["exe_after_sha256"]
                    )
                    self.assertEqual(
                        (probe["build_returncode"], probe["run_returncode"]), (0, 0)
                    )
                    pe = probe["pe_identity"]
                    self.assertEqual(
                        pe["machine"],
                        0xAA64
                        if label == "arm64"
                        else 0x8664
                        if label == "x64"
                        else 0x14C,
                    )
                    self.assertEqual(
                        pe["optional_magic"],
                        0x10B if label.startswith("x86") else 0x20B,
                    )
                    if label.startswith("x86"):
                        self.assertEqual(
                            bool(pe["characteristics"] & 0x20), label == "x86-laa"
                        )
                    rows = [json.loads(line) for line in raw.splitlines()]
                    self.assertEqual(len(rows), 66)
                    self.assertEqual(rows[0]["kind"], "machine")
                    self.assertEqual(rows[-1]["kind"], "complete")
                    self.assertEqual(rows[-1]["calls"], 64)
                    self.assertEqual(
                        rows[-1]["handles_before"], rows[-1]["handles_after"]
                    )
                    opened = rows[1:-1]
                    self.assertEqual([r["ordinal"] for r in opened], list(range(64)))
                    pairs = {}
                    for row in opened:
                        key = tuple(row[n] for n in ["path_kind", "root_view", "view"])
                        pairs.setdefault(key, {})[row["extended"]] = row
                    self.assertEqual(len(pairs), 32)
                    for paired in pairs.values():
                        for field in [
                            "status",
                            "name_status",
                            "tag_status",
                            "tags",
                            "name_units",
                        ]:
                            self.assertEqual(paired[0][field], paired[1][field])


if __name__ == "__main__":
    unittest.main()
