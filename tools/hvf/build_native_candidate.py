#!/usr/bin/env python3
"""Build a sparse CI source candidate without changing the real index or working files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import apply_native_candidate as candidate


def build(root, base, expected_target, output):
    root = root.resolve()
    output.mkdir(parents=True, exist_ok=False)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}

    def git(argv, selected_environment=None):
        return subprocess.check_output(["git", *argv], cwd=root,
                                       env=selected_environment or environment)

    if Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve() != root:
        raise ValueError("candidate repository must be the checkout root")
    base = git(["rev-parse", base + "^{commit}"]).decode().strip()

    def fingerprint_tree(tree):
        names = git(["ls-tree", "-r", "-z", "--name-only", tree, "--", "src", "vendor/vm-memory",
                     *candidate.ROOT_INPUTS, *candidate.CONSUMERS]).decode().split("\0")
        names = [name for name in names if name and candidate.allowed(name)]
        process = subprocess.Popen(["git", "cat-file", "--batch"], cwd=root, env=environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        values = {}
        try:
            for name in names:
                process.stdin.write((tree + ":" + name + "\n").encode())
                process.stdin.flush()
                header = process.stdout.readline().decode().split()
                if len(header) != 3 or header[1] != "blob":
                    raise ValueError(f"candidate input is not a blob: {name}")
                data = process.stdout.read(int(header[2]))
                if len(data) != int(header[2]) or process.stdout.read(1) != b"\n":
                    raise ValueError("truncated Git object stream")
                values[name] = hashlib.sha256(data).hexdigest()
        finally:
            process.stdin.close()
            process.stdout.close()
            if process.wait() != 0:
                raise RuntimeError("Git object reader failed")
        return values

    before = fingerprint_tree(base)
    after = candidate.source_inputs(root)
    if candidate.digest(after) != expected_target:
        raise ValueError("working source differs from the explicitly qualified target digest")
    paths = sorted(name for name in before.keys() | after.keys()
                   if before.get(name) != after.get(name))
    if not paths or not all(candidate.allowed(name) for name in paths):
        raise ValueError("empty candidate or unexpected source path")
    index = Path(git(["rev-parse", "--path-format=absolute", "--git-path", "index"]).decode().strip())
    original_index = hashlib.sha256(index.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="rax-candidate-index-") as tmp:
        scratch = Path(tmp)
        selected_environment = dict(environment, GIT_INDEX_FILE=str(scratch / "index"))
        git(["read-tree", base], selected_environment)
        git(["add", "--", *paths], selected_environment)
        patch = git(["-c", "color.ui=false", "diff", "--no-ext-diff", "--no-textconv", "--no-color",
                     "--no-renames", "--cached", "--binary", "--full-index", base, "--", *paths],
                    selected_environment)
        tree = git(["write-tree"], selected_environment).decode().strip()
        if fingerprint_tree(tree) != after or candidate.patch_paths(root, patch) != paths:
            raise ValueError("staged candidate differs from the exact working source")
        snapshot = scratch / "candidate.patch"
        snapshot.write_bytes(patch)
        git(["apply", "--cached", "--reverse", "--check", str(snapshot)], selected_environment)
        git(["read-tree", base], selected_environment)
        git(["apply", "--cached", "--check", str(snapshot)], selected_environment)
        git(["apply", "--cached", str(snapshot)], selected_environment)
        if git(["write-tree"], selected_environment).decode().strip() != tree:
            raise ValueError("candidate index roundtrip differs")
    if (hashlib.sha256(index.read_bytes()).hexdigest() != original_index
            or candidate.source_inputs(root) != after):
        raise ValueError("real index or working source changed during candidate generation")
    manifest = {"version": 1, "patch": "candidate.patch", "base_commit": base,
                "patch_sha256": hashlib.sha256(patch).hexdigest(), "paths": paths,
                "base_source_digest": candidate.digest(before),
                "target_source_digest": candidate.digest(after), "target_source_tree": tree}
    (output / "candidate.patch").write_bytes(patch)
    (output / "candidate.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return {"paths": len(paths), "patch_bytes": len(patch), "base_inputs": len(before),
            "target_inputs": len(after), "target_source_digest": manifest["target_source_digest"],
            "temporary_index_removed": not scratch.exists(), "real_index_preserved": True,
            "working_source_preserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--expected-target-digest", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new artifact directory")
    args = parser.parse_args()
    print(json.dumps(build(args.repo, args.base_ref, args.expected_target_digest, args.output)))


if __name__ == "__main__":
    main()
