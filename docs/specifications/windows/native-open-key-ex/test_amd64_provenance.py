"""Independent AMD64 acquisition identity and unchanged replay input checks."""

import hashlib
import json
from pathlib import Path
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent
SECTIONS = {3: "order", 5: "grants", 6: "link", 7: "views"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Amd64Provenance(unittest.TestCase):
    def test_frozen_files(self):
        manifest = json.loads((ROOT / "amd64-provenance.json").read_text())
        self.assertTrue(manifest["raw_bytes_frozen"])
        self.assertEqual(len(manifest["files"]), 20)
        for name, expected in manifest["files"].items():
            with self.subTest(name=name):
                raw = (ROOT / name).read_bytes()
                self.assertEqual(len(raw), expected["bytes"])
                self.assertEqual(digest(raw), expected["sha256"])

    def test_native_acquisition_chain(self):
        manifest = json.loads((ROOT / "amd64-provenance.json").read_text())
        self.assertEqual(
            [r["kernel_build"] for r in manifest["captures"]], [20348, 26100]
        )
        helper = ROOT.parent / "native-exception-entry-profile/run-v2.py"
        for capture in manifest["captures"]:
            build = capture["kernel_build"]
            with zipfile.ZipFile(ROOT / capture["archive"]) as archive:
                self.assertIsNone(archive.testzip())
                for version, section in SECTIONS.items():
                    tag = f"v{version}"
                    prefix = f"native-open-key-{section}-{tag}"
                    receipt = json.loads(archive.read(f"{prefix}/receipt.json"))
                    self.assertEqual(
                        (receipt["state"], receipt["exit_code"]), ("finished", 0)
                    )
                    self.assertEqual(receipt["kernel"][:3], [10, 0, build])
                    self.assertEqual(receipt["native_machine"], 0x8664)
                    self.assertEqual(receipt["process_machine"], 0)
                    self.assertEqual(
                        receipt["compiler_adapter_sha256"], digest(helper.read_bytes())
                    )
                    self.assertEqual(
                        receipt["source_sha256"],
                        digest((ROOT / f"run-{tag}.py").read_bytes()),
                    )
                    self.assertEqual(
                        [r["label"] for r in receipt["rows"]], ["x64", "x86", "x86-laa"]
                    )
                    for entry in receipt["rows"]:
                        label = entry["label"]
                        with self.subTest(build=build, version=version, label=label):
                            probe = entry["probes"][tag]
                            raw = archive.read(f"{prefix}/{label}/stdout-{tag}.jsonl")
                            self.assertEqual(raw, probe["text"].encode())
                            self.assertEqual(digest(raw), probe["stdout_sha256"])
                            self.assertEqual(
                                archive.read(f"{prefix}/{label}/stderr-{tag}.log"), b""
                            )
                            self.assertEqual(
                                probe["source_sha256"],
                                digest((ROOT / f"probe-{tag}.cpp").read_bytes()),
                            )
                            self.assertEqual(
                                probe["source_after_sha256"], probe["source_sha256"]
                            )
                            self.assertEqual(
                                probe["exe_after_sha256"], probe["exe_before_sha256"]
                            )
                            self.assertEqual(
                                (probe["build_returncode"], probe["run_returncode"]),
                                (0, 0),
                            )
                            pe = probe["pe_identity"]
                            self.assertEqual(
                                pe["machine"], 0x8664 if label == "x64" else 0x14C
                            )
                            self.assertEqual(
                                pe["optional_magic"], 0x20B if label == "x64" else 0x10B
                            )
                            if label.startswith("x86"):
                                self.assertEqual(
                                    bool(pe["characteristics"] & 0x20),
                                    label == "x86-laa",
                                )
                            rows = [json.loads(line) for line in raw.splitlines()]
                            self.assertTrue(
                                all(row.get("exception", 0) == 0 for row in rows)
                            )
                            self.assertEqual(
                                len(rows),
                                {
                                    3: 6625,
                                    5: 4689 if label == "x64" else 4161,
                                    6: 80,
                                    7: 1441,
                                }[version],
                            )
                            if version != 6:
                                retained = manifest["files"][
                                    f"amd64-{build}-{label}-{tag}.jsonl.zst"
                                ]
                                self.assertEqual(
                                    retained["decoded_sha256"], digest(raw)
                                )
                                self.assertEqual(retained["decoded_bytes"], len(raw))
                                self.assertEqual(retained["rows"], len(rows))
                            if version == 5:
                                self.assertEqual(
                                    (
                                        rows[0]["original_backup"],
                                        rows[0]["original_restore"],
                                    ),
                                    (0, 0),
                                )


if __name__ == "__main__":
    unittest.main()
