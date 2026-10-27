"""Reject incomplete or altered native observations before profile admission."""

import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "flush", Path(__file__).with_name("run-v2.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def rows():
    features = (
        2,
        6,
        10,
        13,
        14,
        17,
        18,
        19,
        24,
        25,
        27,
        28,
        29,
        30,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
    )
    identity = {
        "kind": "identity",
        "arch": "x64",
        "build": 20348,
        "process_machine": 0,
        "native_machine": 0x8664,
        "shared_native_architecture": 9,
        "system_info": [9, 6, 0, 2],
        "native_system_info": [9, 6, 0, 2],
        "maximum_processors": 2,
        "active_processors": 2,
        "cpuid1": [0, 0, 0, 0],
        "cpuid7": [0, 0, 0, 0],
        "processor_features": [[i, False, 0] for i in features],
    }
    result = [identity]
    for cls, size, mode in sorted(PROFILE.matrix()):
        poison = 0x5A if mode == "alternate_output" else 0xA5
        result.append(
            {
                "kind": "query",
                "api": PROFILE.APIS[0],
                "class": cls,
                "length": size,
                "mode": mode,
                "status": 0xC0000002,
                "raised": 0,
                "returned": 0xCCCCCCCC,
                "guard": False,
                "return_guard": False,
                "output": (
                    ""
                    if mode in ("null_output", "null_output_bad_return")
                    else (bytes([poison]) * 80).hex()
                ),
            }
        )
    result.append({"kind": "unavailable_api", "api": PROFILE.APIS[1]})
    return result


class Projection(unittest.TestCase):
    def test_complete_failure_observation_is_preserved_without_success_fabrication(
        self,
    ):
        sample = rows()
        before = copy.deepcopy(sample)
        self.assertIs(PROFILE.validate_rows("x64", sample), sample)
        self.assertEqual(sample, before)

    def test_aliased_return_word_can_be_overwritten_by_record_copy(self):
        sample = rows()
        row = next(v for v in sample if v.get("mode") == "alias_return")
        row.update(
            status=0,
            returned=3,
            output=(
                bytes.fromhex("0300000040000000") + bytes(24) + bytes([0xA5]) * 48
            ).hex(),
        )
        PROFILE.validate_rows("x64", sample)

    def test_missing_duplicate_or_unknown_rows_fail(self):
        for sample in (
            rows()[:-1],
            rows() + [rows()[1]],
            rows() + [{"kind": "unknown"}],
            rows()[:2] + rows()[3:],
        ):
            with self.subTest(size=len(sample)), self.assertRaises(ValueError):
                PROFILE.validate_rows("x64", sample)

    def test_width_and_identity_corruption_fail(self):
        for edit in (
            lambda v: v[1].update(status=-1),
            lambda v: v[1].update(output="00" * 81),
            lambda v: v[0].update(native_machine=0),
            lambda v: v[0].update(raw_pointer=1234),
        ):
            sample = rows()
            edit(sample)
            with self.assertRaises(ValueError):
                PROFILE.validate_rows("x64", sample)

    def test_unexpected_write_past_record_fails(self):
        sample = rows()
        row = next(v for v in sample if v.get("mode") == "valid")
        data = bytearray.fromhex(row["output"])
        data[40] = 0
        row["output"] = data.hex()
        with self.assertRaises(ValueError):
            PROFILE.validate_rows("x64", sample)


if __name__ == "__main__":
    unittest.main()
