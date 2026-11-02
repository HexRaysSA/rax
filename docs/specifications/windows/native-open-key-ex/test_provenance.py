"""Frozen native inputs and observations; no emulator-derived expectations."""

import hashlib
import json
from pathlib import Path
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent
LABELS = ["arm64", "x64", "x86", "x86-laa"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Provenance(unittest.TestCase):
    def test_frozen_files(self):
        manifest = json.loads((ROOT / "provenance.json").read_text())
        self.assertTrue(manifest["raw_bytes_frozen"])
        self.assertEqual(len(manifest["files"]), 33)
        for name, expected in manifest["files"].items():
            with self.subTest(name=name):
                raw = (ROOT / name).read_bytes()
                self.assertEqual(len(raw), expected["bytes"])
                self.assertEqual(digest(raw), expected["sha256"])

    def test_reference_copies(self):
        for row in json.loads((ROOT / "references/provenance.json").read_text()):
            raw = (ROOT / "references" / row["file"]).read_bytes()
            self.assertEqual(digest(raw), row["sha256"])
            self.assertEqual(len(raw), row["bytes"])
            self.assertTrue(row["url"].startswith("https://learn.microsoft.com/"))
            self.assertNotEqual(row["title"], "unknown")

    def test_native_acquisition_chain(self):
        for version in range(1, 8):
            tag = f"v{version}"
            with (
                self.subTest(version=tag),
                zipfile.ZipFile(ROOT / f"capture-{tag}.zip") as archive,
            ):
                self.assertIsNone(archive.testzip())
                receipt = json.loads(archive.read("capture/receipt.json"))
                self.assertEqual(receipt["state"], "finished")
                self.assertEqual(receipt["exit_code"], 0)
                self.assertEqual(receipt["native_machine"], 0xAA64)
                self.assertEqual(receipt["kernel"][2], 29695)
                self.assertEqual(
                    receipt["source_sha256"],
                    digest((ROOT / f"run-{tag}.py").read_bytes()),
                )
                self.assertEqual([r["label"] for r in receipt["rows"]], LABELS)
                for row in receipt["rows"]:
                    label = row["label"]
                    probe = row["probes"][tag]
                    raw = archive.read(f"capture/{label}/stdout-{tag}.jsonl")
                    self.assertEqual(digest(raw), probe["stdout_sha256"])
                    self.assertEqual(raw, probe["text"].encode())
                    self.assertEqual(
                        probe["source_sha256"],
                        digest((ROOT / f"probe-{tag}.cpp").read_bytes()),
                    )
                    self.assertEqual(
                        probe["source_after_sha256"], probe["source_sha256"]
                    )
                    self.assertEqual(
                        probe["exe_before_sha256"], probe["exe_after_sha256"]
                    )
                    self.assertEqual(probe["build_returncode"], 0)
                    self.assertEqual(probe["run_returncode"], 0)
                    self.assertEqual(
                        archive.read(f"capture/{label}/stderr-{tag}.log"), b""
                    )
                    expected_machine = (
                        0xAA64
                        if label == "arm64"
                        else 0x8664
                        if label == "x64"
                        else 0x14C
                    )
                    pe = probe["pe_identity"]
                    self.assertEqual(pe["machine"], expected_machine)
                    self.assertEqual(
                        pe["optional_magic"],
                        0x10B if label.startswith("x86") else 0x20B,
                    )
                    if label.startswith("x86"):
                        self.assertEqual(
                            bool(pe["characteristics"] & 0x20), label == "x86-laa"
                        )
                    rows = [json.loads(line) for line in raw.splitlines()]
                    expected_rows = {
                        1: 1393,
                        2: 1393,
                        3: 6625,
                        4: 2565,
                        5: 4161 if label.startswith("x86") else 4689,
                        6: 80,
                        7: 1441,
                    }[version]
                    self.assertEqual(len(rows), expected_rows)
                    self.assertTrue(all(r.get("exception", 0) == 0 for r in rows))
                    if version == 3:
                        opens = [r for r in rows if r["kind"] == "open"]
                        deltas = [r for r in rows if r["kind"] == "handle_delta"]
                        self.assertEqual(len(opens), 3312)
                        self.assertEqual(
                            [r["ordinal"] for r in deltas], list(range(3312))
                        )
                        self.assertEqual(
                            sum(r["after"] - r["before"] for r in deltas),
                            20 if label.startswith("x86") else 0,
                        )
                    if version in [4, 5]:
                        profiles = [r for r in rows if r["kind"] == "privileges"]
                        self.assertEqual([r["profile"] for r in profiles], [0, 1, 2, 3])
                        for profile in profiles:
                            self.assertEqual(profile["adjust_error"], 0)
                            self.assertEqual(
                                profile["backup"] & 2,
                                2 if profile["profile"] & 1 else 0,
                            )
                            self.assertEqual(
                                profile["restore"] & 2,
                                2 if profile["profile"] & 2 else 0,
                            )


if __name__ == "__main__":
    unittest.main()
