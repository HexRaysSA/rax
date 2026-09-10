"""Exercise execution routing and relocation cleanup without a host cross SDK."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import package
from targets import build_configuration


class SDKExecution(unittest.TestCase):
    def test_cross_consumers_execute_from_relocated_sdk_and_restore_build(self):
        for fail_ctest in (False, True):
            with self.subTest(fail_ctest=fail_ctest), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                target = "s390x-unknown-linux-gnu"
                name = "rax-capi-0.1.0-" + target
                native = work / "build/cargo" / target / "release"
                native.mkdir(parents=True)
                original = work / "original-prefix"
                (original / "lib").mkdir(parents=True)
                (original / "lib/librax.so").write_bytes(b"fixture")
                env, cmake, runner, cc = build_configuration(target, "x86_64-unknown-linux-gnu", True, {})
                commands = []

                def run(*args, env=None):
                    commands.append(tuple(map(str, args)))
                    if args[0] == "ctest":
                        self.assertFalse(native.exists(), "test must not resolve Cargo's original libraries")
                        self.assertFalse(original.exists(), "SDK must already have moved")
                        self.assertTrue((work / "relocated SDK" / name / "lib/librax.so").exists())
                        self.assertIn("--no-tests=error", args)
                        if fail_ctest:
                            raise subprocess.CalledProcessError(1, args)

                with patch.object(package, "run", side_effect=run), \
                     patch.object(package, "run_cargo_tests", return_value={"passed": 56}), \
                     patch.object(package.subprocess, "check_output", return_value="-lrax"):
                    if fail_ctest:
                        with self.assertRaises(subprocess.CalledProcessError):
                            package.validate_sdk(target, work, name, env, cmake, runner, cc)
                    else:
                        sdk, counts = package.validate_sdk(target, work, name, env, cmake, runner, cc)
                        self.assertEqual(counts["passed"], 56)
                        executions = [c for c in commands if c[0] == runner[0]]
                        self.assertEqual(len(executions), 2)
                        self.assertTrue(all(list(c[:3]) == runner for c in executions))
                        compiles = [c for c in commands if c[0] == cc]
                        self.assertEqual(len(compiles), 2)
                        self.assertIn(str(sdk / "lib/librax.a"), compiles[1])
                        configure = next(c for c in commands if "-S" in c)
                        self.assertIn(f"-DCMAKE_CROSSCOMPILING_EMULATOR={';'.join(runner)}", configure)
                self.assertTrue(native.exists(), "restore the original build even if CTest fails")
                if fail_ctest:
                    self.assertFalse(any(c[0] == runner[0] for c in commands))

    def test_cargo_failure_remains_visible_and_stops_validation(self):
        failure = subprocess.CompletedProcess(["cargo", "test"], 101, stdout="test failure details\n")
        captured = io.StringIO()
        with patch.object(package.subprocess, "run", return_value=failure), contextlib.redirect_stdout(captured):
            with self.assertRaises(subprocess.CalledProcessError):
                package.run_cargo_tests("cargo", "test", env={})
        self.assertIn("test failure details", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
