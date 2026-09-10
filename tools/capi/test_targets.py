from pathlib import Path
import re
import unittest

from targets import TARGETS, build_configuration


class TargetContracts(unittest.TestCase):
    def test_native_mismatch_cannot_silently_skip_execution(self):
        for target in TARGETS:
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "native execution required"):
                    build_configuration(target, "unknown-host", False, {})

    def test_cross_requires_supported_target_and_linux_host(self):
        for target, spec in TARGETS.items():
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    build_configuration(target, "aarch64-apple-darwin", True, {})
                if not spec.cross_prefix:
                    with self.assertRaises(ValueError):
                        build_configuration(target, "x86_64-unknown-linux-gnu", True, {})

    def test_every_cross_consumer_uses_same_target_and_executor(self):
        for target, spec in TARGETS.items():
            if not spec.cross_prefix:
                continue
            with self.subTest(target=target):
                env, cmake, runner, cc = build_configuration(
                    target, "x86_64-unknown-linux-gnu", True, {"CARGO_ENCODED_RUSTFLAGS": "-Ctarget-cpu=native"})
                key = target.upper().replace("-", "_")
                self.assertEqual(env[f"CARGO_TARGET_{key}_LINKER"], cc)
                self.assertEqual(env[f"CARGO_TARGET_{key}_RUNNER"].split(), runner)
                self.assertIn(f"-DCMAKE_C_COMPILER={cc}", cmake)
                self.assertIn(f"-DCMAKE_CROSSCOMPILING_EMULATOR={';'.join(runner)}", cmake)
                self.assertEqual(env[f"CC_{target.replace('-', '_')}"], cc)
                self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", env)
                self.assertNotIn("armv8", env["CFLAGS"])
                self.assertNotIn("x86", env["RUSTFLAGS"])

    def test_musl_can_build_cdylib_and_preserves_cpu_baseline(self):
        for arch, cpu in (("x86_64", "x86-64"), ("aarch64", "generic")):
            target = f"{arch}-unknown-linux-musl"
            env, cmake, runner, _ = build_configuration(target, target, False, {})
            self.assertIn("-C target-feature=-crt-static", env["RUSTFLAGS"])
            self.assertIn(f"-C target-cpu={cpu}", env["RUSTFLAGS"])
            self.assertEqual((cmake, runner), ([], []))

    def test_windows_arm_selects_arm64_cmake_platform(self):
        target = "aarch64-pc-windows-msvc"
        env, _, runner, _ = build_configuration(target, target, False, {})
        self.assertEqual(env["CMAKE_GENERATOR_PLATFORM"], "ARM64")
        self.assertEqual(runner, [])

    def test_workflow_and_publication_registry_agree(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/capi-release.yml").read_text()
        lanes = re.findall(r"- \{ ([^\n]+) \}", workflow)
        targets = [re.search(r"target: ([\w-]+)", lane).group(1) for lane in lanes]
        self.assertCountEqual(targets, TARGETS)
        for lane in lanes:
            if "os:" in lane and "musl" not in lane:
                target = re.search(r"target: ([\w-]+)", lane).group(1)
                self.assertEqual("experimental: true" in lane, TARGETS[target].experimental)
        for name in ("cross-linux", "musl"):
            job = workflow.split(f"  {name}:\n", 1)[1].split("\n  publish:", 1)[0]
            self.assertIn("continue-on-error: true", job)
        self.assertIn("needs: [build, cross-linux, musl]", workflow)
        publish = workflow.split("  publish:\n", 1)[1]
        self.assertIn("!cancelled()", publish)


if __name__ == "__main__":
    unittest.main()
