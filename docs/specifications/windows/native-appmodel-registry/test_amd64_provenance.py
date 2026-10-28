"""Physical AMD64 observations, independent of compatible execution on ARM64."""

import hashlib
import json
from pathlib import Path
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Amd64Provenance(unittest.TestCase):
    def test_physical_amd64_acquisition_and_canonical_view_controls(self):
        manifests = json.loads((ROOT / "amd64-provenance.json").read_text())
        self.assertEqual([m["kernel_build"] for m in manifests], [20348, 26100])
        observed = 0
        for manifest in manifests:
            raw = (ROOT / manifest["file"]).read_bytes()
            self.assertEqual(len(raw), manifest["bytes"])
            self.assertEqual(digest(raw), manifest["sha256"])
            with zipfile.ZipFile(ROOT / manifest["file"]) as archive:
                self.assertIsNone(archive.testzip())
                receipt = json.loads(archive.read("receipt.json"))
                self.assertEqual(
                    (receipt["state"], receipt["exit_code"]), ("finished", 0)
                )
                self.assertEqual(receipt["native_machine"], 0x8664)
                self.assertEqual(
                    receipt["kernel"][:3], [10, 0, manifest["kernel_build"]]
                )
                self.assertEqual(
                    receipt["source_sha256"], digest((ROOT / "run-v1.py").read_bytes())
                )
                self.assertEqual(
                    receipt["compiler_adapter_sha256"],
                    digest(
                        (
                            ROOT.parent / "native-exception-entry-profile/run-v2.py"
                        ).read_bytes()
                    ),
                )
                self.assertEqual(
                    [r["label"] for r in receipt["rows"]], ["x64", "x86", "x86-laa"]
                )
                for entry in receipt["rows"]:
                    label = entry["label"]
                    with self.subTest(build=manifest["kernel_build"], label=label):
                        probe = entry["probes"]["v1"]
                        stdout = archive.read(f"{label}/stdout-v1.jsonl")
                        self.assertEqual(stdout, probe["text"].encode())
                        self.assertEqual(digest(stdout), probe["stdout_sha256"])
                        self.assertEqual(archive.read(f"{label}/stderr-v1.log"), b"")
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
                            pe["machine"], 0x8664 if label == "x64" else 0x14C
                        )
                        self.assertEqual(
                            pe["optional_magic"], 0x20B if label == "x64" else 0x10B
                        )
                        self.assertEqual(
                            bool(pe["characteristics"] & 0x20), label != "x86"
                        )
                        rows = [json.loads(line) for line in stdout.splitlines()]
                        self.assertEqual(len(rows), 66)
                        self.assertEqual(rows[0]["native_machine"], 0x8664)
                        self.assertEqual(rows[-1]["calls"], 64)
                        self.assertEqual(
                            rows[-1]["handles_before"], rows[-1]["handles_after"]
                        )
                        self.assertEqual(
                            [r["ordinal"] for r in rows[1:-1]], list(range(64))
                        )
                        pairs = {}
                        for row in rows[1:-1]:
                            key = tuple(
                                row[n] for n in ["path_kind", "root_view", "view"]
                            )
                            pairs.setdefault(key, {})[row["extended"]] = row
                            observed += 1
                            if row["path_kind"] == 1:
                                self.assertEqual(
                                    row["status"],
                                    0xC000000D
                                    if label != "x64" and row["view"] == 0x300
                                    else 0xC0000034,
                                )
                            elif row["status"] == 0:
                                self.assertEqual(
                                    (row["name_status"], row["tag_status"]), (0, 0)
                                )
                                name = "".join(map(chr, row["name_units"])).upper()
                                redirected = label != "x64" and (
                                    (row["path_kind"] == 0 and row["view"] != 0x100)
                                    or (
                                        row["path_kind"] in (2, 3)
                                        and (
                                            row["root_view"] != 0x100
                                            or row["view"] == 0x200
                                        )
                                    )
                                )
                                self.assertEqual("WOW6432NODE" in name, redirected)
                        self.assertEqual(len(pairs), 32)
                        for pair in pairs.values():
                            for field in [
                                "status",
                                "name_status",
                                "tag_status",
                                "tags",
                                "name_units",
                            ]:
                                self.assertEqual(pair[0][field], pair[1][field])
        self.assertEqual(observed, 384)

    def test_sibling_user_native_arm64_control_preserves_source_and_absence(self):
        raw = (ROOT / "user-capture-v1.zip").read_bytes()
        self.assertEqual(len(raw), 1763)
        self.assertEqual(
            digest(raw),
            "c588a8ae4d62ec32da23dbbb09214803551e3077f32dd02a8270da4a894427c5",
        )
        with zipfile.ZipFile(ROOT / "user-capture-v1.zip") as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(set(archive.namelist()), {"probe-v1.py", "receipt.json"})
            producer = archive.read("probe-v1.py")
            self.assertEqual(producer, (ROOT / "probe-user-v1.py").read_bytes())
            receipt = json.loads(archive.read("receipt.json"))
        self.assertEqual(receipt["source_sha256"], digest(producer))
        output = receipt["output"]
        self.assertEqual(output["kernel"], [10, 0, 29695])
        self.assertEqual(output["native_machine"], 0xAA64)
        self.assertEqual(output["process_machine"], 0)
        self.assertEqual(output["pointer_bytes"], 8)
        self.assertEqual(output["handles_before"], output["handles_after"])
        expected = {
            (leaf, api, view): status
            for leaf in ["machine", "user"]
            for api, views, status in [
                ("NtOpenKey", [0, 0x100, 0x200, 0x300], 0xC0000034),
                ("RegOpenKeyExW", [0, 0x100, 0x200], 2),
            ]
            for view in views
        }
        observed = {
            (row["leaf"], row["api"], row["view"]): row["status"]
            for row in output["rows"]
        }
        self.assertEqual(len(output["rows"]), 14)
        self.assertEqual(observed, expected)


if __name__ == "__main__":
    unittest.main()
