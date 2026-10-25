import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("image_information", FOLDER / "run-v6.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
RECORDS = json.loads((FOLDER / "local-29683-v6.json").read_text())
OBSERVATIONS = [r for r in RECORDS if r["kind"] == "observation"]
UNAVAILABLE = [r for r in RECORDS if r["kind"] == "unavailable"]


class Projection(unittest.TestCase):
    def setUp(self):
        self.rows = copy.deepcopy(OBSERVATIONS[0]["rows"])

    def test_all_matrix_and_metadata_profiles_retain_their_identities(self):
        self.assertEqual(len(CONTROL.PROFILES), 12)
        self.assertEqual(len(OBSERVATIONS), 33)
        self.assertEqual(len(UNAVAILABLE), 3)
        expected = {
            (arch, profile)
            for arch in ("arm64", "x64", "x86")
            for profile in CONTROL.PROFILES
        }
        self.assertEqual(
            {(r["arch"], r["profile"]) for r in [*OBSERVATIONS, *UNAVAILABLE]}, expected
        )
        source = (
            (FOLDER / "native-image-information-v4.cpp")
            .read_bytes()
            .replace(b"\r\n", b"\n")
        )
        self.assertEqual(len(RECORDS), 72)
        for producer, result in zip(RECORDS[::2], RECORDS[1::2]):
            self.assertEqual(producer["kind"], "producer")
            self.assertEqual(
                result["kind"],
                "unavailable" if result.get("available") is False else "observation",
            )
            self.assertEqual(
                {k: v for k, v in producer.items() if k != "kind"},
                {k: result[k] for k in producer if k != "kind"},
            )
            self.assertEqual(
                producer["source_sha256"], hashlib.sha256(source).hexdigest()
            )
            for key in (
                "source_sha256",
                "binary_sha256",
                "compiled_binary_sha256",
                "compiler_sha256",
            ):
                self.assertRegex(producer[key], "^[0-9a-f]{64}$")
        calls = 0
        matrix = 0
        for record in OBSERVATIONS:
            rows = record["rows"]
            CONTROL.validate(rows, record["arch"], record["metadata_only"])
            self.assertEqual(record["exit_code"], 0)
            self.assertEqual(rows[1]["pe"], record["pe_fields"])
            self.assertEqual(rows[1]["file_bytes"], record["file_bytes"])
            self.assertTrue(rows[1]["loaded_entry_matches"])
            self.assertEqual(rows[1]["loaded_rva"], record["pe_fields"][1])
            matrix += len(rows) - 3
            calls += len(rows) - 2
        self.assertEqual(matrix, 2066)
        self.assertEqual(calls, 2099)

    def test_missing_duplicate_reordered_and_wrong_mode_are_rejected(self):
        for change in ("missing", "duplicate", "reordered", "mode"):
            rows = copy.deepcopy(self.rows)
            if change == "missing":
                del rows[20]
            elif change == "duplicate":
                rows[20] = copy.deepcopy(rows[19])
            elif change == "reordered":
                rows[20], rows[21] = rows[21], rows[20]
            with self.subTest(change=change), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64", change == "mode")

    def test_extra_fields_invalid_scalars_width_and_cleanup_are_rejected(self):
        for row, field, value in (
            (0, "pointer_bytes", 4),
            (0, "native_machine", 0),
            (1, "status", True),
            (1, "loaded_entry_matches", 1),
            (2, "status", -1),
            (2, "exception", 1 << 32),
            (2, "opened", 1),
            (2, "alias", False),
            (2, "address", "unknown"),
            (2, "output", "a5" * 79),
            (2, "returned", "A5" * 16),
            (-1, "cases", 693),
        ):
            rows = copy.deepcopy(self.rows)
            rows[row][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64")

    def test_pointer_and_padding_redaction_is_exact_for_aliases_and_fallbacks(self):
        for record in OBSERVATIONS:
            if record["metadata_only"]:
                continue
            rows = record["rows"]
            aliases = [r for r in rows[2:-1] if r["family"] == "alias"]
            self.assertEqual(len(aliases), CONTROL.record_size(record["arch"]) + 1)
            for row in rows[2:-1]:
                for key in ("output", "returned"):
                    for i, bit in enumerate(row[key + "_mask"]):
                        if bit == "1":
                            self.assertEqual(row[key][2 * i : 2 * i + 2], "00")
        for change in ("mask", "pointer", "padding"):
            rows = copy.deepcopy(self.rows)
            row = next(
                r for r in rows[2:-1] if r["family"] == "length" and r["length"] == 64
            )
            if change == "mask":
                row["output_mask"] = "0" * 80
            else:
                offset = 0 if change == "pointer" else 12
                row["output"] = (
                    row["output"][: offset * 2] + "01" + row["output"][offset * 2 + 2 :]
                )
            with self.subTest(change=change), self.assertRaises(ValueError):
                CONTROL.validate(rows, "arm64")

    def test_native_metadata_agrees_with_independent_pe_fields_and_eof(self):
        mapping = (
            (3, 1),
            (4, 2),
            (5, 3),
            (6, 4),
            (7, 5),
            (8, 6),
            (9, 7),
            (10, 8),
            (11, 9),
            (0, 10),
            (12, 13),
            (13, 15),
        )
        for record in OBSERVATIONS:
            image = record["rows"][1]
            for pe, section in mapping:
                self.assertEqual(record["pe_fields"][pe], image["section"][section])
            self.assertEqual(image["section"][0], 0)
            self.assertEqual(image["section"][11], 1)
            self.assertEqual(image["section"][14], record["file_bytes"])
            self.assertEqual(
                image["section"][12],
                (
                    0
                    if record["profile"]
                    in (
                        "no-dynamic-base",
                        "no-relocations",
                        "dynamic-base-no-relocations",
                    )
                    else 4
                ),
            )
            if record["profile"] == "stack":
                self.assertEqual(image["section"][1:3], [0x300000, 0x5000])
            if record["profile"] == "checksum":
                self.assertEqual(image["section"][15], 0x12345678)
            if record["profile"] == "loader-flags":
                self.assertEqual(image["section"][13], 0x1234)

    def test_loader_rejections_are_qualified_and_contribute_zero_queries(self):
        self.assertEqual(
            {r["profile"] for r in UNAVAILABLE},
            {"no-dynamic-base", "no-relocations", "dynamic-base-no-relocations"},
        )
        for record in UNAVAILABLE:
            CONTROL.validate_unavailable(record)
        for field, value in (
            ("arch", "x64"),
            ("available", True),
            ("metadata_only", False),
            ("windows_error", 5),
            ("query_calls", 1),
            ("source_sha256", "unknown"),
            ("rows", []),
        ):
            record = copy.deepcopy(UNAVAILABLE[0])
            record[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CONTROL.validate_unavailable(record)


if __name__ == "__main__":
    unittest.main()
