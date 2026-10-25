"""Second-chance controls distinguish expected termination from a failed probe."""

import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "second_chance", Path(__file__).with_name("run-second-chance-v1.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def ready(mode):
    return {"kind": "ready", "mode": mode, "code": 0xE0425345}


class ControlTests(unittest.TestCase):
    def test_last_chance_requires_exact_exception_exit_without_handlers(self):
        PROFILE.validate("last", 0xE0425345, [ready("last")])
        for code, rows in (
            (0, [ready("last")]),
            (0xE0425345, [ready("last"), {"kind": "handler", "ordinal": 1}]),
        ):
            with self.assertRaises(RuntimeError):
                PROFILE.validate("last", code, rows)

    def test_invalid_inputs_require_status_return_and_cleanup(self):
        for mode in ("invalid-record", "invalid-context"):
            rows = [
                ready(mode),
                {
                    "kind": "complete",
                    "seen": 0,
                    "caught": 0,
                    "call_returned": True,
                    "status": 0xC0000005,
                    "removed": True,
                },
            ]
            PROFILE.validate(mode, 0, rows)
            for key, value in (("seen", 1), ("status", 0), ("removed", False)):
                bad = [rows[0], {**rows[1], key: value}]
                with self.assertRaises(RuntimeError):
                    PROFILE.validate(mode, 0, bad)

    def test_undeclared_fields_and_modes_cannot_enter_public_results(self):
        with self.assertRaises(RuntimeError):
            PROFILE.validate("last", 0xE0425345, [{**ready("last"), "address": 123}])
        with self.assertRaises(RuntimeError):
            PROFILE.validate("first", 0, [ready("first")])


if __name__ == "__main__":
    unittest.main()
