import tarfile
import zipfile
import shutil
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

import publish

from package import ROOT, TARGETS, digest, validate_tag, test_counts, seal
from publish import verify_assets


class ReleaseValidation(unittest.TestCase):
    def test_sealing_requires_notices_and_archives_them_verbatim(self):
        for target in ('x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                bundle = work / 'bundle'
                bundle.mkdir()
                (bundle / 'librax.a').write_bytes(b'fixture library')
                with self.assertRaisesRegex(RuntimeError, 'legal file'):
                    seal(bundle, work, target)
                for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
                    shutil.copy2(ROOT / name, bundle / name)
                (bundle / 'LICENSE').write_text('stale license')
                with self.assertRaisesRegex(RuntimeError, 'legal file'):
                    seal(bundle, work, target)
                shutil.copy2(ROOT / 'LICENSE', bundle / 'LICENSE')
                archive = seal(bundle, work, target)
                if target.endswith('msvc'):
                    with zipfile.ZipFile(archive) as stream:
                        contents = {name: stream.read('bundle/' + name)
                                    for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md')}
                else:
                    with tarfile.open(archive) as stream:
                        contents = {name: stream.extractfile('bundle/' + name).read()
                                    for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md')}
                for name, content in contents.items():
                    self.assertEqual(content, (ROOT / name).read_bytes())
                    self.assertIn(name, (bundle / 'SHA256SUMS').read_text())

    def test_execution_evidence_rejects_empty_ignored_or_filtered_runs(self):
        summary = "test result: ok. {} passed; 0 failed; {} ignored; 0 measured; {} filtered out"
        for text in ("", summary.format(0, 0, 0), summary.format(12, 1, 0), summary.format(12, 0, 1)):
            with self.assertRaisesRegex(RuntimeError, "execution incomplete"):
                test_counts(text)
        counts = test_counts(summary.format(12, 0, 0) + "\n" + summary.format(0, 0, 0))
        self.assertEqual(counts["passed"], 12)

    def test_tags_must_match_package_version(self):
        for version in ("0.1.0", "1.2.3-rc.1"):
            validate_tag("v" + version, version)
        for tag in ("main", "v1.2.4", "v1.2", "v1.2.3/asset", "v1.2.3;echo x"):
            with self.assertRaises(ValueError):
                validate_tag(tag, "1.2.3")

    def test_assets_require_complete_matching_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            with self.assertRaises(ValueError):
                verify_assets(dist, "0.1.0")
            for target in TARGETS:
                archives = self.add_asset(dist, target)
            self.assertEqual(len(verify_assets(dist, "0.1.0")), 4 * len(TARGETS))
            extra = dist / "unexpected"
            extra.touch()
            with self.assertRaises(ValueError):
                verify_assets(dist, "0.1.0")
            extra.unlink()
            for archive, _ in archives:
                original = archive.read_bytes()
                archive.write_bytes(b"corrupt")
                with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                    verify_assets(dist, "0.1.0")
                archive.write_bytes(original)

    def test_optional_assets_are_absent_or_complete_never_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            for target, spec in TARGETS.items():
                if not spec.experimental:
                    self.add_asset(dist, target)
            required_count = 4 * sum(not spec.experimental for spec in TARGETS.values())
            self.assertEqual(len(verify_assets(dist, "0.1.0")), required_count)
            for target, spec in TARGETS.items():
                if not spec.experimental:
                    continue
                archives = self.add_asset(dist, target)
                self.assertEqual(len(verify_assets(dist, "0.1.0")), required_count + 4)
                # A lane that delivered only half of its pair is never publishable,
                # so a missing debug bundle fails exactly like a missing SDK.
                for missing in [path for pair in archives for path in pair]:
                    missing.unlink()
                    with self.assertRaisesRegex(ValueError, "missing release asset"):
                        verify_assets(dist, "0.1.0")
                    self.add_asset(dist, target)
                for path in [path for pair in archives for path in pair]:
                    path.unlink()

    @staticmethod
    def add_asset(dist, target):
        """Write the complete SDK + debug asset set one lane uploads."""
        suffix = "zip" if "windows" in target else "tar.gz"
        assets = []
        for kind in ("", "-debug"):
            archive = dist / f"rax-capi-0.1.0-{target}{kind}.{suffix}"
            checksum = archive.with_name(archive.name + ".sha256")
            archive.write_bytes((target + kind).encode())
            checksum.write_text(f"{digest(archive)}  {archive.name}\n")
            assets.append((archive, checksum))
        return assets


class PublishOrdering(unittest.TestCase):
    def test_upload_failure_never_publishes(self):
        self.exercise([], upload_fails=True)

    def test_existing_draft_can_resume(self):
        commands = self.exercise([{"tagName": "v0.1.0", "isDraft": True}])
        self.assertEqual([c[2] for c in commands], ["upload", "edit"])

    def test_published_release_is_never_modified(self):
        self.exercise([{"tagName": "v0.1.0", "isDraft": False}], published=True)

    def exercise(self, releases, upload_fails=False, published=False):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "capi").mkdir()
            (root / "capi/Cargo.toml").write_text('[package]\nversion = "0.1.0"\n')
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                if upload_fails and command[2] == "upload":
                    raise subprocess.CalledProcessError(1, command)

            with patch.object(publish, "ROOT", root), \
                 patch.object(publish, "verify_assets", return_value=[root / "sdk.zip"]), \
                 patch("sys.argv", ["publish.py", "--tag", "v0.1.0", "--dist", str(root)]), \
                 patch.object(publish.subprocess, "check_output", return_value=json.dumps(releases)), \
                 patch.object(publish.subprocess, "run", side_effect=run):
                if upload_fails:
                    with self.assertRaises(subprocess.CalledProcessError):
                        publish.main()
                    self.assertEqual([c[2] for c in commands], ["create", "upload"])
                    self.assertIn("--draft", commands[0])
                elif published:
                    with self.assertRaises(RuntimeError):
                        publish.main()
                    self.assertEqual(commands, [])
                else:
                    publish.main()
                    self.assertIn("--draft=false", commands[-1])
            return commands


if __name__ == "__main__":
    unittest.main()
