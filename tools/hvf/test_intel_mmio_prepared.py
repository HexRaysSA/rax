import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import intel_mmio_prepared as prepared


class PreparedConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rax-prepared-test-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "artifact"
        self.artifact.mkdir()
        self.inputs = {"src/lib.rs": "a" * 64}
        # Admission-only fixture; this byte string is never executed or treated
        # as a Mach-O signature/SDK/guest-execution witness.
        (self.artifact / prepared.EXECUTABLE).write_bytes(b"metadata fixture only")
        self.report = {"success": True, "compile_only": True, "export_guest": True,
                       "owned_build_removed": True,
                       "executable_sha256": prepared.sha(self.artifact / prepared.EXECUTABLE),
                       "engine_source_digest": prepared.digest(self.inputs),
                       "consumer_sha256": "b" * 64, "script_sha256": "c" * 64,
                       "libraries": {"rax": {"sha256": "d" * 64}}, "build_environment": {}}
        prepared.save(self.artifact / "engine-source.json", self.inputs)
        prepared.save(self.artifact / "result.json", self.report)
        prepared.export_description(self.artifact, self.report, 2)

    def admit(self, inputs=None, consumer=None, script=None):
        return prepared.admit(self.artifact, self.inputs if inputs is None else inputs,
                              consumer or "b" * 64, script or "c" * 64, 2)

    def modify_manifest(self, **changes):
        path = self.artifact / "prepared.json"
        value = json.loads(path.read_text())
        value.update(changes)
        prepared.save(path, value)

    def test_exact_metadata_roundtrip(self):
        executable, metadata = self.admit()
        self.assertEqual(executable, (self.artifact / prepared.EXECUTABLE).resolve())
        self.assertEqual(metadata["expected_cases"], 2)

    def test_executable_modification_rejects(self):
        (self.artifact / prepared.EXECUTABLE).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.admit()

    def test_added_source_rejects(self):
        with self.assertRaisesRegex(ValueError, "source"):
            self.admit(inputs={**self.inputs, "src/new.rs": "e" * 64})

    def test_consumer_and_driver_and_support_versions_must_match(self):
        for options in ({"consumer": "e" * 64}, {"script": "f" * 64}):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, "tooling"):
                self.admit(**options)
        self.modify_manifest(support_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "tooling"):
            self.admit()

    def test_incomplete_compilation_reports_cannot_admit(self):
        for key in ("success", "compile_only", "export_guest", "owned_build_removed"):
            report = dict(self.report, **{key: False})
            prepared.save(self.artifact / "result.json", report)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "compilation"):
                self.admit()

    def test_unknown_version_and_boolean_version_reject(self):
        for version in (1, 3, True, "2"):
            self.modify_manifest(version=version)
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "version"):
                self.admit()

    def test_consumer_digest_binds_every_compiled_rust_input(self):
        directory = self.root / 'source/tools/hvf'
        directory.mkdir(parents=True)
        for name in prepared.CONSUMER_SOURCES:
            (directory / name).write_text('original ' + name)
        inputs = prepared.consumer_inputs(self.root / 'source')
        original = prepared.digest(inputs)
        for name in prepared.CONSUMER_SOURCES:
            path = directory / name
            before = path.read_bytes()
            path.write_bytes(before + b'changed')
            self.assertNotEqual(prepared.digest(prepared.consumer_inputs(self.root / 'source')),
                                original, name)
            path.write_bytes(before)
        self.assertEqual(prepared.digest(prepared.consumer_inputs(self.root / 'source')), original)

    def test_non_object_metadata_rejects(self):
        for filename in ("prepared.json", "result.json"):
            path = self.artifact / filename
            original = path.read_bytes()
            try:
                for value in ([], None, True):
                    prepared.save(path, value)
                    with self.subTest(filename=filename, value=value), self.assertRaises(ValueError):
                        self.admit()
            finally:
                path.write_bytes(original)

    def test_profile_and_executable_path_must_be_exact(self):
        self.modify_manifest(expected_cases=True)
        with self.assertRaisesRegex(ValueError, "profile"):
            self.admit()
        self.modify_manifest(expected_cases=2, executable="../outside")
        with self.assertRaisesRegex(ValueError, "executable"):
            self.admit()

    def test_native_profiles_cannot_admit_each_others_prepared_artifacts(self):
        for exported, requested in ((16, 952), (952, 16)):
            prepared.export_description(self.artifact, self.report, exported)
            with self.subTest(exported=exported, requested=requested):
                with self.assertRaisesRegex(ValueError, "profile"):
                    prepared.admit(self.artifact, self.inputs, "b" * 64, "c" * 64, requested)

    def test_artifact_symlink_rejects_without_changing_its_target(self):
        outside = self.root / "outside"
        outside.write_bytes(b"preserve")
        executable = self.artifact / prepared.EXECUTABLE
        executable.unlink()
        executable.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.admit()
        self.assertEqual(outside.read_bytes(), b"preserve")

    def test_only_complete_ordered_boolean_pass_records_qualify(self):
        path = self.root / "observations.jsonl"
        valid = [{"case": 0, "passed": True}, {"case": 1, "passed": True}]
        path.write_text("\n".join(json.dumps(row) for row in valid) + "\n")
        self.assertEqual(prepared.observations(path, 2), valid)
        invalid = [valid[:1], valid[::-1], [{"case": False, "passed": True}, valid[1]],
                   [{"case": 0, "passed": 1}, valid[1]], ["invalid", valid[1]], []]
        for rows in invalid:
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                prepared.observations(path, 2)

    def test_zero_and_boolean_expected_counts_cannot_qualify(self):
        path = self.root / "observations.jsonl"
        path.write_text("")
        for expected in (0, True):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                prepared.observations(path, expected)

    def test_command_failure_retains_raw_error_and_phase(self):
        output = self.root / "command"
        output.mkdir()
        result = {"commands": []}
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(RuntimeError, "status 7"):
            prepared.execute("fixture", [sys.executable, "-c",
                                         "import sys;sys.stderr.write('expected error\\n');sys.exit(7)"],
                             root=self.root, environment=os.environ.copy(), output=output, result=result)
        self.assertEqual((output / "fixture.stderr").read_text(), "expected error\n")
        saved = json.loads((output / "result.json").read_text())
        self.assertEqual(saved["commands"][0]["exit_code"], 7)

    def test_timeout_stops_the_owned_descendant_group(self):
        output = self.root / "timeout"
        output.mkdir()
        ready, marker = self.root / "ready", self.root / "escaped"
        descendant = "import pathlib,sys,time;time.sleep(4);pathlib.Path(sys.argv[1]).write_text('escaped')"
        parent = ("import subprocess,pathlib,sys,time;"
                  "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]);"
                  "pathlib.Path(sys.argv[3]).write_text('started');time.sleep(60)")
        result = {"commands": []}
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(subprocess.TimeoutExpired):
            prepared.execute("fixture", [sys.executable, "-c", parent, descendant,
                                         str(marker), str(ready)], root=self.root,
                             environment=os.environ.copy(), output=output, result=result, timeout=2)
        self.assertTrue(ready.exists(), "the descendant must have actually been spawned")
        time.sleep(2.3)
        self.assertFalse(marker.exists(), "the child must not escape its timed-out parent")
        self.assertTrue(json.loads((output / "result.json").read_text())["commands"][0]["timed_out"])

    def test_exited_parent_cannot_leave_stderr_descendant_unbounded(self):
        output = self.root / "orphan"
        output.mkdir()
        descendant = "import time;time.sleep(60)"
        parent = "import subprocess,sys;subprocess.Popen([sys.executable,'-c',sys.argv[1]])"
        started = time.monotonic()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(subprocess.TimeoutExpired):
            prepared.execute("fixture", [sys.executable, "-c", parent, descendant],
                             root=self.root, environment=os.environ.copy(), output=output,
                             result={"commands": []}, timeout=1)
        self.assertLess(time.monotonic() - started, 5)


if __name__ == "__main__":
    unittest.main()
