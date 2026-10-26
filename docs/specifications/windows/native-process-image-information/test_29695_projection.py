"""Validate the fresh native records without executing a Windows process."""

import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("image_profile", FOLDER / "run-v9.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
SPEC = importlib.util.spec_from_file_location(
    "image_models", FOLDER / "test_model_profiles.py"
)
MODELS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODELS)


def validate(records):
    expected = list(
        itertools.product(("arm64", "x64", "x86", "x86-laa"), CONTROL.PROFILES)
    )
    if [(row["view"], row["profile"]) for row in records] != expected:
        raise ValueError("complete ordered native view/profile set required")
    queries = profiles = rejected = 0
    for record in records:
        view = record["view"]
        arch = "x86" if view == "x86-laa" else view
        if record["arch"] != arch or record["inputs_unchanged"] is not True:
            raise ValueError("view or immutable-input identity differs")
        if (
            record["source_sha256"]
            != hashlib.sha256(
                (FOLDER / "native-image-information-v7.cpp").read_bytes()
            ).hexdigest()
        ):
            raise ValueError("unrecognized executed source")
        original = {
            key: value
            for key, value in record.items()
            if key not in ("view", "inputs_unchanged")
        }
        if record["kind"] == "unavailable":
            CONTROL.validate_unavailable(original)
            rejected += 1
            continue
        if record["kind"] != "observation" or record["exit_code"] != 0:
            raise ValueError("native observation failed")
        rows = CONTROL.validate(record["rows"], arch, record["metadata_only"])
        if rows[0]["build"] != 29695 or rows[0]["native_machine"] != 0xAA64:
            raise ValueError("unqualified captured kernel")
        if (
            record["pe_fields"] != rows[1]["pe"]
            or record["file_bytes"] != rows[1]["file_bytes"]
        ):
            raise ValueError("original file and mapped metadata differ")
        if view == "x86-laa" and not record["pe_fields"][10] & 0x20:
            raise ValueError("large-address-aware executable required")
        queries += len(rows) - 3
        profiles += 1
    if (queries, profiles, rejected) != (2800, 45, 3):
        raise ValueError("native coverage differs")
    return queries, profiles, rejected


class Native29695(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads((FOLDER / "local-29695-v1.json").read_text())

    def test_complete_native_matrices_and_metadata(self):
        self.assertEqual(validate(self.records), (2800, 45, 3))

    def test_rejects_missing_reordered_or_wrong_kernel_views(self):
        wrong = copy.deepcopy(self.records)
        wrong[0]["rows"][0]["build"] = 29694
        swapped = copy.deepcopy(self.records)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        for records in (self.records[:-1], swapped, wrong):
            with self.assertRaises(ValueError):
                validate(records)

    def test_rejects_changed_source_or_invalid_pointer_projection(self):
        wrong_source = copy.deepcopy(self.records)
        wrong_source[0]["source_sha256"] = "0" * 64
        wrong_pointer = copy.deepcopy(self.records)
        wrong_pointer[0]["rows"][2]["pointer_valid_mask"] = 256
        for records in (wrong_source, wrong_pointer):
            with self.assertRaises(ValueError):
                validate(records)

    def test_suspended_directory_profiles_and_source_byte_bindings(self):
        records = json.loads(
            (FOLDER / "local-relocation-directory-29695-v1.json").read_text()
        )
        MODELS.validate_directory(records)
        self.assertEqual(sum(record["query_calls"] for record in records), 13)
        bindings = json.loads((FOLDER / "inputs-29695-v1.json").read_text())
        root = FOLDER.parents[3]
        for name, identity in bindings["files"].items():
            data = (root / name).read_bytes()
            self.assertEqual(
                (len(data), hashlib.sha256(data).hexdigest()),
                (identity["bytes"], identity["sha256"]),
                name,
            )


if __name__ == "__main__":
    unittest.main()
