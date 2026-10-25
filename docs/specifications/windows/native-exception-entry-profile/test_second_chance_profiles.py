import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "profiles", Path(__file__).with_name("run-second-chance-v6.py")
)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class NativeProfiles(unittest.TestCase):
    def test_exact_kernel_and_view_statuses(self):
        for build, machine in ((20348, 0x8664), (26100, 0x8664), (29683, 0xAA64)):
            for arch in ("arm64", "x64", "x86"):
                if arch == "arm64" and machine != 0xAA64:
                    continue
                for mode in ("invalid-record", "invalid-context"):
                    host = {
                        "kind": "ready",
                        "mode": mode,
                        "code": CONTROL.BASE.EXCEPTION,
                        "build": build,
                        "native_machine": machine,
                        "process_machine": 0x14C if arch == "x86" else 0,
                        "pointer_bytes": 4 if arch == "x86" else 8,
                    }
                    expected = (
                        0x80000002
                        if (build, machine, arch, mode)
                        == (26100, 0x8664, "x86", "invalid-context")
                        else 0xC0000005
                    )
                    result = {
                        "kind": "complete",
                        "seen": 0,
                        "caught": 0,
                        "call_returned": True,
                        "status": expected,
                        "removed": True,
                    }
                    CONTROL.validate(mode, 0, [host, result], arch)
                    result["status"] = (
                        0xC0000005 if expected == 0x80000002 else 0x80000002
                    )
                    with self.subTest(
                        build=build, arch=arch, mode=mode
                    ), self.assertRaises(RuntimeError):
                        CONTROL.validate(mode, 0, [host, result], arch)

    def test_rejects_unqualified_kernel_and_unexpected_return(self):
        with self.assertRaises(RuntimeError):
            CONTROL.expected_status(
                "invalid-context", "x86", {"build": 99999, "native_machine": 0x8664}
            )
        with self.assertRaises(RuntimeError):
            CONTROL.expected_status(
                "invalid-context", "arm64", {"build": 26100, "native_machine": 0x8664}
            )
        host = {
            "kind": "ready",
            "mode": "last",
            "code": CONTROL.BASE.EXCEPTION,
            "build": 26100,
            "native_machine": 0x8664,
            "process_machine": 0,
            "pointer_bytes": 8,
        }
        result = {
            "kind": "complete",
            "seen": 0,
            "caught": 0,
            "call_returned": True,
            "status": 0xC0000005,
            "removed": True,
        }
        with self.assertRaises(RuntimeError):
            CONTROL.validate("last", 0, [host, result], "x64")


if __name__ == "__main__":
    unittest.main()
