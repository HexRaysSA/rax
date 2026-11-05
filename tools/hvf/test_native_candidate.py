import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import apply_native_candidate as candidate


class NativeCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rax-candidate-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "tools/hvf").mkdir(parents=True)
        (self.repo / "src/a.rs").write_text("pub const OLD: u32 = 1;\n")
        (self.repo / "Cargo.toml").write_text('[package]\nname = "fixture"\n')
        for name in candidate.CONSUMERS:
            (self.repo / name).write_text("fixture consumer\n")
        self.patch = self.base / "candidate.patch"
        self.patch.write_text(
            "diff --git a/src/a.rs b/src/a.rs\n"
            "--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1 +1 @@\n"
            "-pub const OLD: u32 = 1;\n+pub const NEW: u32 = 2;\n"
            "diff --git a/src/b.rs b/src/b.rs\nnew file mode 100644\n"
            "--- /dev/null\n+++ b/src/b.rs\n@@ -0,0 +1 @@\n"
            "+pub const ADDED: bool = true;\n"
        )
        before = candidate.source_inputs(self.repo)
        (self.repo / "src/a.rs").write_text("pub const NEW: u32 = 2;\n")
        (self.repo / "src/b.rs").write_text("pub const ADDED: bool = true;\n")
        after = candidate.source_inputs(self.repo)
        (self.repo / "src/a.rs").write_text("pub const OLD: u32 = 1;\n")
        (self.repo / "src/b.rs").unlink()
        self.description = {"version": 1, "patch": self.patch.name,
                            "patch_sha256": hashlib.sha256(self.patch.read_bytes()).hexdigest(),
                            "paths": ["src/a.rs", "src/b.rs"], "base_commit": "fixture",
                            "base_source_digest": candidate.digest(before),
                            "target_source_digest": candidate.digest(after)}

    def execute(self):
        manifest = self.base / "candidate.json"
        manifest.write_text(json.dumps(self.description))
        return candidate.apply_candidate(self.repo, manifest, self.base / "evidence")

    def update_patch_checksum(self):
        self.description["patch_sha256"] = hashlib.sha256(self.patch.read_bytes()).hexdigest()

    def test_exact_source_patch_applies_and_removes_its_temporary_directory(self):
        result = self.execute()
        self.assertTrue(result["success"], result)
        self.assertTrue(result["source_qualified"])
        self.assertTrue(result["owned_build_removed"])
        self.assertEqual((self.repo / "src/a.rs").read_text(), "pub const NEW: u32 = 2;\n")
        self.assertTrue((self.repo / "src/b.rs").exists())

    def test_changed_base_rejects_before_mutation(self):
        (self.repo / "src/a.rs").write_text("unrelated local edit\n")
        result = self.execute()
        self.assertFalse(result["success"])
        self.assertFalse(result["patch_applied"])
        self.assertEqual((self.repo / "src/a.rs").read_text(), "unrelated local edit\n")

    def test_patch_checksum_mismatch_rejects_before_mutation(self):
        self.description["patch_sha256"] = "0" * 64
        result = self.execute()
        self.assertFalse(result["success"])
        self.assertEqual(result["commands"], [])
        self.assertFalse((self.repo / "src/b.rs").exists())

    def test_git_metadata_path_is_not_an_allowed_source_change(self):
        self.patch.write_text(self.patch.read_text().replace("src/a.rs", ".git/config"))
        self.update_patch_checksum()
        result = self.execute()
        self.assertFalse(result["success"])
        self.assertEqual(result["commands"], [])
        self.assertFalse((self.repo / ".git").exists())

    def test_file_header_cannot_redirect_an_allowed_diff(self):
        self.patch.write_text(self.patch.read_text().replace("--- a/src/a.rs", "--- a/.git/config"))
        self.update_patch_checksum()
        result = self.execute()
        self.assertFalse(result["success"])
        self.assertEqual(result["commands"], [])

    def test_symlink_mode_rejects_before_mutation(self):
        self.patch.write_text(self.patch.read_text().replace("new file mode 100644", "new file mode 120000"))
        self.update_patch_checksum()
        result = self.execute()
        self.assertFalse(result["success"])
        self.assertFalse((self.repo / "src/b.rs").exists())

    def test_existing_symlink_is_never_followed(self):
        outside = self.base / "outside"
        outside.write_text("preserve outside input\n")
        (self.repo / "src/a.rs").unlink()
        (self.repo / "src/a.rs").symlink_to(outside)
        result = self.execute()
        self.assertFalse(result["success"])
        self.assertEqual(outside.read_text(), "preserve outside input\n")

    def test_post_apply_mismatch_cannot_qualify_the_candidate(self):
        self.description["target_source_digest"] = "0" * 64
        result = self.execute()
        self.assertTrue(result["patch_applied"])
        self.assertFalse(result["success"])
        self.assertFalse(result["source_qualified"])
        self.assertTrue(result["owned_build_removed"])


if __name__ == "__main__":
    unittest.main()
