"""Check fresh 29698 controls and their immutable native source bindings."""

import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("image_control", FOLDER / "run-v9.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
SPEC = importlib.util.spec_from_file_location("image_models", FOLDER / "test_model_profiles.py")
MODELS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODELS)


def validate(records):
    expected = list(itertools.product(("arm64", "x64", "x86", "x86-laa"), CONTROL.PROFILES))
    if [(row["view"], row["profile"]) for row in records] != expected:
        raise ValueError("complete ordered native view/profile set required")
    source_hash = hashlib.sha256((FOLDER / "native-image-information-v7.cpp").read_bytes()).hexdigest()
    queries = admitted = rejected = 0
    for record in records:
        arch = "x86" if record["view"] == "x86-laa" else record["view"]
        if record["arch"] != arch or record["inputs_unchanged"] is not True:
            raise ValueError("view or immutable input identity differs")
        if record["source_sha256"] != source_hash:
            raise ValueError("unrecognized executed source")
        if record["kind"] == "unavailable":
            original = {k: v for k, v in record.items() if k not in ("view", "inputs_unchanged")}
            CONTROL.validate_unavailable(original)
            rejected += 1
            continue
        if record["kind"] != "observation" or record["exit_code"] != 0:
            raise ValueError("failed native observation")
        rows = CONTROL.validate(record["rows"], arch, record["metadata_only"])
        if rows[0]["build"] != 29698 or rows[0]["native_machine"] != 0xAA64:
            raise ValueError("unqualified captured kernel")
        if rows[1]["pe"] != record["pe_fields"] or rows[1]["file_bytes"] != record["file_bytes"]:
            raise ValueError("original file and mapped metadata differ")
        if record["view"] == "x86-laa" and not record["pe_fields"][10] & 0x20:
            raise ValueError("large-address-aware executable required")
        queries += len(rows) - 3
        admitted += 1
    if (queries, admitted, rejected) != (2800, 45, 3):
        raise ValueError("native coverage differs")
    return queries, admitted, rejected


class Native29698(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads((FOLDER / "local-29698-v1.json").read_text())

    def test_complete_native_matrices_and_metadata(self):
        self.assertEqual(validate(self.records), (2800, 45, 3))
        for record in self.records:
            if record["profile"] != "default" or record["arch"] == "x86":
                continue
            witness = next(row for row in record["rows"][2:-1]
                           if row["family"] == "buffer" and row["output_role"] == 16
                           and row["return_role"] == 0)
            self.assertEqual(witness["status"], 0xC0000005)
            self.assertEqual(witness["pointer_changed_mask"], witness["pointer_valid_mask"])
            self.assertEqual(witness["pointer_match_mask"], witness["pointer_valid_mask"])
            self.assertNotEqual(witness["pointer_valid_mask"], 0)

    def test_rejects_missing_reordered_or_wrong_kernel_views(self):
        wrong = copy.deepcopy(self.records)
        wrong[0]["rows"][0]["build"] = 29699
        machine = copy.deepcopy(self.records)
        machine[0]["rows"][0]["native_machine"] = 0x8664
        reordered = copy.deepcopy(self.records)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        for records in (self.records[:-1], reordered, wrong, machine):
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
        directory = json.loads((FOLDER / "local-relocation-directory-29698-v1.json").read_text())
        MODELS.validate_directory(directory)
        self.assertEqual(sum(row["query_calls"] for row in directory), 13)
        bindings = json.loads((FOLDER / "inputs-29698-v1.json").read_text())
        self.assertEqual(bindings["kernel"], [10, 0, 29698])
        self.assertEqual(bindings["native_machine"], 0xAA64)
        for name, identity in bindings["files"].items():
            data = (FOLDER.parents[3] / name).read_bytes()
            self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                             (identity["bytes"], identity["sha256"]), name)


if __name__ == "__main__":
    unittest.main()
