import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("image_control", FOLDER / "run-v9.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


def source_hashes(name):
    data = (FOLDER / name).read_bytes().replace(b"\r\n", b"\n")
    return {
        hashlib.sha256(data).hexdigest(),
        hashlib.sha256(data.replace(b"\n", b"\r\n")).hexdigest(),
    }


def validate_directory(records):
    arches = [r["arch"] for r in records if r["kind"] == "metadata-baseline"]
    if len(set(arches)) != len(arches) or not arches:
        raise ValueError("duplicate or absent executable views")
    profiles = (
        "default",
        "no-relocation-directory",
        "no-directory-no-dynamic-base",
        "stripped-with-directory",
    )
    if len(records) != len(arches) * 5:
        raise ValueError("incomplete directory profile set")
    for at, arch in enumerate(arches):
        baseline, *rows = records[at * 5 : at * 5 + 5]
        if baseline["kind"] != "metadata-baseline" or baseline["query_calls"] != 1:
            raise ValueError("invalid original metadata query")
        CONTROL.validate(baseline["rows"], arch, True)
        for row, profile in zip(rows, profiles):
            if (
                row["kind"] != "section-metadata"
                or row["arch"] != arch
                or row["profile"] != profile
                or row["host"] != baseline["rows"][0]
            ):
                raise ValueError("mismatched directory profile identity")
            if row["source_sha256"] not in source_hashes(
                "native-image-information-v7.cpp"
            ) or row["driver_sha256"] not in source_hashes(
                "run-relocation-directory-v1.py"
            ):
                raise ValueError("unknown producer source")
            pe = row["pe_fields"]
            if (
                len(pe) != 14
                or pe[0] != {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[arch]
            ):
                raise ValueError("invalid PE field identity")
            directory = row["relocation_directory"]
            if len(directory) != 2 or any(
                type(x) is not int or not 0 <= x <= 0xFFFFFFFF for x in directory
            ):
                raise ValueError("invalid relocation directory")
            if (directory == [0, 0]) != (
                profile in ("no-relocation-directory", "no-directory-no-dynamic-base")
            ):
                raise ValueError("directory mutation missing")
            if not row["available"]:
                if (
                    arch != "arm64"
                    or profile
                    not in ("no-directory-no-dynamic-base", "stripped-with-directory")
                    or row["windows_error"] != 193
                    or row["query_calls"] != 0
                ):
                    raise ValueError("false unavailable claim")
                continue
            flags = 4 if pe[11] & 0x40 and not pe[10] & 1 else 0
            expected = [
                0,
                pe[3],
                pe[4],
                pe[5],
                pe[6],
                pe[7],
                pe[8],
                pe[9],
                pe[10],
                pe[11],
                pe[0],
                1,
                flags,
                pe[12],
                row["file_bytes"],
                pe[13],
            ]
            if (
                row["section"] != expected
                or row["status"] != 0
                or row["returned"] != 64
                or row["query_calls"] != 1
                or row["child_suspended"] is not True
                or row["parent_pointer_bytes"] != 8
            ):
                raise ValueError("native section metadata mismatch")


class ModelProfiles(unittest.TestCase):
    def test_hosted_rows_qualify_both_kernel_copy_profiles(self):
        count = 0
        for build in (20348, 26100):
            records = json.loads((FOLDER / f"hosted-{build}-v9.json").read_text())
            self.assertEqual(len(records), 48)
            for producer, result in zip(records[::2], records[1::2]):
                self.assertEqual(
                    producer["source_sha256"]
                    in source_hashes("native-image-information-v7.cpp"),
                    True,
                )
                self.assertEqual(
                    {k: v for k, v in producer.items() if k != "kind"},
                    {k: result[k] for k in producer if k != "kind"},
                )
                self.assertEqual(result["exit_code"], 0)
                CONTROL.validate(
                    result["rows"], result["arch"], result["metadata_only"]
                )
                self.assertEqual(result["rows"][0]["build"], build)
                self.assertEqual(result["rows"][0]["native_machine"], 0x8664)
                count += len(result["rows"]) - 3
                if not result["metadata_only"]:
                    case = next(
                        r
                        for r in result["rows"]
                        if r["kind"] == "case"
                        and r["family"] == "buffer"
                        and r["output_role"] == 16
                        and r["return_role"] == 0
                    )
                    self.assertEqual(case["status"], 0xC0000005)
                    self.assertEqual(case["pointer_changed_mask"], 0)
                    self.assertEqual(case["pointer_match_mask"], 0)
        self.assertEqual(count, 2800)

    def test_suspended_children_separate_flags_from_directory_presence(self):
        records = json.loads(
            (FOLDER / "local-relocation-directory-29683-v1.json").read_text()
        )
        validate_directory(records)
        self.assertEqual(len(records), 15)
        self.assertEqual(sum(r["query_calls"] for r in records), 13)

    def test_directory_projection_rejects_false_metadata_or_availability(self):
        records = json.loads(
            (FOLDER / "local-relocation-directory-29683-v1.json").read_text()
        )
        for key, value in (
            ("status", 1),
            ("returned", 48),
            ("query_calls", 0),
            ("child_suspended", False),
            ("parent_pointer_bytes", 4),
            ("source_sha256", "0" * 64),
            ("driver_sha256", "0" * 64),
            ("relocation_directory", [0, 0]),
        ):
            changed = copy.deepcopy(records)
            changed[1][key] = value
            with self.assertRaises(ValueError, msg=key):
                validate_directory(changed)
        changed = copy.deepcopy(records)
        changed[1]["section"][12] ^= 4
        with self.assertRaises(ValueError):
            validate_directory(changed)
        changed = copy.deepcopy(records)
        changed[3]["query_calls"] = 1
        with self.assertRaises(ValueError):
            validate_directory(changed)


if __name__ == "__main__":
    unittest.main()
