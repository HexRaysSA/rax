"""Validate retained native artifact identity and producer/record integrity."""

import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).parent


class Provenance(unittest.TestCase):
    def test_query_records_bind_to_compiled_sources_and_binaries(self):
        receipt = json.loads((ROOT / "build-controls-v2.json").read_text())
        self.assertEqual(receipt["state"], "complete")
        self.assertEqual(
            hashlib.sha256((ROOT / "controller-v2.py").read_bytes()).hexdigest(),
            receipt["controller_sha256"],
        )
        survey = json.loads((ROOT / "arm64-29695-v1.json").read_text())
        self.assertEqual(
            hashlib.sha256((ROOT / "probe-v1.py").read_bytes()).hexdigest(),
            survey["source_sha256"],
        )
        source = hashlib.sha256((ROOT / "probe-v2.cpp").read_bytes()).hexdigest()
        identities = json.loads((ROOT / "pe-identities-v1.json").read_text())
        expected = dict(arm64=0xAA64, x64=0x8664, x86=0x14C, **{"x86-laa": 0x14C})
        for row in receipt["rows"]:
            self.assertEqual(row["source_before_sha256"], source)
            self.assertEqual(row["source_after_sha256"], source)
            self.assertEqual(row["build_returncode"], 0)
            self.assertEqual(row["run_returncode"], 0)
            self.assertEqual(row["exe_before_sha256"], row["exe_after_sha256"])
            identity = next(
                x
                for x in identities
                if x["directory"] == "nt-query-key-probe-v2"
                and x["label"] == row["label"]
            )
            self.assertEqual(identity["pe_machine"], expected[row["label"]])
            self.assertEqual(identity["sha256"], row["exe_before_sha256"])
            raw = (ROOT / (row["label"] + "-29695-v2.jsonl")).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["stdout_sha256"])
            records = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual(len(records), 2690)
            queries = [x for x in records if x["kind"] == "query"]
            self.assertEqual(len(queries), 2688)
            self.assertEqual(sum(x["class"] == 7 for x in queries), 1632)
            self.assertTrue(all(x["exception"] == 0 for x in queries))

    def test_view_controls_keep_exact_producer_and_duplication_results(self):
        receipt = json.loads((ROOT / "view-controls-v4.json").read_text())
        self.assertEqual(receipt["state"], "complete")
        self.assertEqual(
            hashlib.sha256((ROOT / "controller-v4.py").read_bytes()).hexdigest(),
            receipt["controller_sha256"],
        )
        source = hashlib.sha256((ROOT / "probe-v4.cpp").read_bytes()).hexdigest()
        self.assertEqual(receipt["source_sha256"], source)
        for row in receipt["rows"]:
            self.assertEqual(row["source_before_sha256"], source)
            self.assertEqual(row["source_after_sha256"], source)
            self.assertEqual(row["exe_before_sha256"], row["exe_after_sha256"])
            records = receipt["observations"][row["label"]]
            opens = [x for x in records if x["kind"] == "view"]
            duplicates = [x for x in records if x["kind"] == "duplicate"]
            self.assertEqual(len(opens), 28)
            self.assertEqual(len(duplicates), sum(x["open_status"] == 0 for x in opens))
            for duplicate in duplicates:
                opened = next(
                    x
                    for x in opens
                    if x["access"] == duplicate["access"]
                    and x["view"] == duplicate["view"]
                )
                self.assertEqual(duplicate["query_status"], opened["query_status"])
                self.assertEqual(duplicate["tags"], opened["tags"])
                self.assertEqual(duplicate["returned"], 4)

    def test_copy_profiles_bind_every_frozen_record_to_its_native_producer(self):
        profiles = json.loads((ROOT / "copy-provenance-v1.json").read_text())
        self.assertEqual(len(profiles), 10)
        for profile in profiles:
            raw = (ROOT / profile["file"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), profile["sha256"])
            version = "v5" if profile["file"].endswith("-v5.jsonl") else "v2"
            self.assertEqual(
                hashlib.sha256(
                    (ROOT / ("probe-" + version + ".cpp")).read_bytes()
                ).hexdigest(),
                profile["producer_source_sha256"],
            )
            self.assertEqual(
                profile["producer_source_sha256"], profile["source_after_sha256"]
            )
            self.assertEqual(profile["exe_sha256"], profile["exe_after_sha256"])
            self.assertEqual(profile["pe_identity"]["machine"], 0x14C)
            rows = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual(len(rows), 3314 if version == "v5" else 2690)
            self.assertEqual(rows[0]["pointer_bytes"], 4)
            self.assertEqual(rows[0]["process_machine"], 0x14C)
            self.assertEqual(rows[0]["native_machine"], profile["native_machine"])
            self.assertTrue(all(row.get("exception", 0) == 0 for row in rows))


if __name__ == "__main__":
    unittest.main()
