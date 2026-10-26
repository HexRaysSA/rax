import copy
import importlib.util
import json
from pathlib import Path
import unittest

FOLDER = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("control", FOLDER / "run-v2.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class StartupInformation(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((FOLDER / "local-29683-v2.json").read_text())["rows"]

    def test_accepts_native_main_and_owned_thread(self):
        self.assertEqual(CONTROL.validate(self.rows), self.rows)

    def test_rejects_missing_reordered_and_raw_address_fields(self):
        extra = copy.deepcopy(self.rows)
        extra[0]["raw_address"] = 123
        for rows in (self.rows[:1], list(reversed(self.rows)), extra):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                CONTROL.validate(rows)

    def test_rejects_invalid_scalar_types_and_word_extents(self):
        for field, value in (
            ("teb32_self", 1),
            ("build", True),
            ("information_words", [4096, 2]),
            ("information_words", [4096, 2, 1 << 32]),
        ):
            rows = copy.deepcopy(self.rows)
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CONTROL.validate(rows)

    def test_rejects_broken_companion_and_machine_identity(self):
        for field, value in (
            ("wow_teb_offset", 0),
            ("reverse_wow_teb_offset", 4096),
            ("native_teb_is_32", True),
            ("native_teb_self", False),
            ("native_teb_32_link", False),
            ("information_emulated_machine", 0x8664),
            ("information_native_machine", 0x8664),
        ):
            rows = copy.deepcopy(self.rows)
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CONTROL.validate(rows)

    def test_rejects_missing_process_sharing_and_page_size_mismatch(self):
        for field, value in (
            ("shared_information_with_main", False),
            ("same_words_as_main", False),
            ("information_words", [8192, 2, 0]),
        ):
            rows = copy.deepcopy(self.rows)
            rows[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CONTROL.validate(rows)

    def test_preserves_thread_local_tls_and_companion_geometry(self):
        self.rows[1].update(
            wow_teb_offset=-16384,
            reverse_wow_teb_offset=16384,
            tls32_information_nonnull=True,
            tls_views_same=False,
        )
        self.assertEqual(CONTROL.validate(self.rows), self.rows)

    def test_preserves_unknown_cpu_bits_and_compatibility_system_info(self):
        for row in self.rows:
            row["information_words"][1] = 0x80000002
        self.assertEqual(CONTROL.validate(self.rows), self.rows)
        self.assertEqual(self.rows[0]["native_processor_architecture"], 9)
        self.assertEqual(self.rows[0]["native_machine"], 0xAA64)


if __name__ == "__main__":
    unittest.main()
