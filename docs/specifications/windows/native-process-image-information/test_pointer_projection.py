import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("pointer_control", FOLDER / "run-v9.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
RECORDS = json.loads((FOLDER / "local-29683-v9.json").read_text())
PREVIOUS = json.loads((FOLDER / "local-29683-v6.json").read_text())
OBSERVATIONS = [r for r in RECORDS if r["kind"] == "observation"]


class PointerProjection(unittest.TestCase):
    def test_all_profiles_and_producer_identities_are_complete(self):
        self.assertEqual(len(RECORDS), 72)
        self.assertEqual(len(OBSERVATIONS), 33)
        source = (
            (FOLDER / "native-image-information-v7.cpp")
            .read_bytes()
            .replace(b"\r\n", b"\n")
        )
        for producer, result in zip(RECORDS[::2], RECORDS[1::2]):
            self.assertEqual(producer["kind"], "producer")
            self.assertEqual(
                producer["source_sha256"], hashlib.sha256(source).hexdigest()
            )
            self.assertEqual(
                {k: v for k, v in producer.items() if k != "kind"},
                {k: result[k] for k in producer if k != "kind"},
            )
            if result["kind"] == "unavailable":
                CONTROL.validate_unavailable(result)
            else:
                CONTROL.validate(
                    result["rows"], result["arch"], result["metadata_only"]
                )
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["rows"][1]["pe"], result["pe_fields"])
                self.assertEqual(result["rows"][1]["file_bytes"], result["file_bytes"])
        self.assertEqual(sum(len(r["rows"]) - 3 for r in OBSERVATIONS), 2108)
        self.assertEqual(sum(len(r["rows"]) - 2 for r in OBSERVATIONS), 2141)

    def test_existing_2066_status_guard_and_input_observations_are_preserved(self):
        names = (
            "query_class",
            "family",
            "handle_kind",
            "access",
            "output_role",
            "return_role",
            "length",
            "alias",
        )
        previous = {
            r["arch"]: {tuple(row[k] for k in names): row for row in r["rows"][2:-1]}
            for r in PREVIOUS
            if r["kind"] == "observation" and not r["metadata_only"]
        }
        compared = 0
        for record in OBSERVATIONS:
            if record["metadata_only"]:
                continue
            for row in record["rows"][2:-1]:
                old = previous[record["arch"]].get(tuple(row[k] for k in names))
                if old is None:
                    self.assertEqual(row["output_role"], 16)
                    continue
                for key in (
                    "status",
                    "exception",
                    "guard_protection",
                    "opened",
                    "output_mask",
                    "returned_mask",
                ):
                    self.assertEqual(row[key], old[key], (record["arch"], key, row))
                compared += 1
        self.assertEqual(compared, 2066)

    def test_partial_pointer_writes_and_measured_grants_are_retained(self):
        for record in OBSERVATIONS:
            if record["metadata_only"]:
                continue
            width = CONTROL.width(record["arch"])
            full = (1 << width) - 1
            rows = record["rows"][2:-1]
            corner = next(
                row
                for row in rows
                if row["family"] == "buffer"
                and row["output_role"] == 16
                and row["return_role"] == 0
            )
            expected = full if width == 8 else 0
            self.assertEqual(corner["status"], 0xC0000005)
            self.assertEqual(corner["pointer_valid_mask"], full)
            self.assertEqual(corner["pointer_changed_mask"], expected)
            self.assertEqual(corner["pointer_match_mask"], expected)
            for row in rows:
                if row["family"] != "rights":
                    continue
                requested = row["access"]
                if not row["opened"]:
                    self.assertEqual(requested, 0)
                    self.assertIsNone(row["granted_access"])
                else:
                    self.assertEqual(
                        row["granted_access"],
                        0x1400 if requested == 0x400 else requested,
                    )

    def test_malformed_predicates_and_false_grant_measurements_are_rejected(self):
        base = OBSERVATIONS[0]["rows"]
        for key, value in (
            ("pointer_valid_mask", 256),
            ("pointer_changed_mask", True),
            ("pointer_match_mask", -1),
            ("granted_access", 0),
        ):
            rows = copy.deepcopy(base)
            rows[2][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64")
        rows = copy.deepcopy(base)
        row = next(
            row
            for row in rows[2:-1]
            if row["family"] == "rights" and row["access"] == 0x400
        )
        row["granted_access"] = None
        with self.assertRaises(ValueError):
            CONTROL.validate(rows, "arm64")


if __name__ == "__main__":
    unittest.main()
