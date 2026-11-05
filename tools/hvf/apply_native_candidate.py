#!/usr/bin/env python3
"""Apply a pinned audit candidate in a matching disposable CI checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import tempfile

CONSUMERS = ("tools/hvf/intel_mmio_native_guest.rs", "tools/hvf/intel_mmio_native_probe.py")
ROOT_INPUTS = ("Cargo.toml", "Cargo.lock", ".cargo/config.toml")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def contained(root, name):
    root = root.resolve()
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or path.as_posix() != name
            or any(part in {".", ".."} for part in path.parts)
            or any(character in name for character in ("\\", "\0", "\n"))):
        raise ValueError(f"noncanonical candidate path: {name!r}")
    target = root
    for part in path.parts:
        target = target / part
        if target.is_symlink():
            raise ValueError(f"symlink in candidate input: {name}")
    if not target.resolve().is_relative_to(root):
        raise ValueError(f"candidate input escapes checkout: {name}")
    return target


def source_inputs(root):
    root = root.resolve()
    files = list((root / "src").rglob("*.rs"))
    files.extend(path for path in (root / "vendor/vm-memory").rglob("*")
                 if path.is_file() and path.suffix in {".rs", ".toml"})
    files.extend(root / name for name in ROOT_INPUTS if (root / name).exists())
    files.extend(root / name for name in CONSUMERS)
    return {str(path.relative_to(root)): hashlib.sha256(
        contained(root, str(path.relative_to(root))).read_bytes()).hexdigest()
            for path in sorted(files)}


def allowed(name):
    return (name in ROOT_INPUTS or name in CONSUMERS
            or (name.startswith("src/") and name.endswith(".rs"))
            or (name.startswith("vendor/vm-memory/") and Path(name).suffix in {".rs", ".toml"}))


def patch_paths(root, patch):
    names = []
    current = None
    metadata = False
    for line in patch.decode("utf-8").splitlines():
        if line.startswith("diff --git "):
            pair = shlex.split(line[len("diff --git "):])
            if (len(pair) != 2 or not pair[0].startswith("a/")
                    or not pair[1].startswith("b/") or pair[0][2:] != pair[1][2:]):
                raise ValueError("candidate renames or malformed diff paths")
            current = pair[0][2:]
            contained(root, current)
            if not allowed(current) or current in names:
                raise ValueError(f"unexpected or repeated candidate path: {current}")
            names.append(current)
            metadata = True
        elif line.startswith("@@ "):
            metadata = False
        elif metadata and line.startswith(("--- ", "+++ ")):
            path = line[4:]
            prefix = "a/" if line.startswith("--- ") else "b/"
            if path != "/dev/null" and path != prefix + current:
                raise ValueError("candidate file headers disagree with diff path")
        elif metadata and re.match(r"(?:old|new|new file|deleted file) mode ", line):
            if line.rsplit(" ", 1)[1] not in {"100644", "100755"}:
                raise ValueError("candidate may only change regular source files")
        elif metadata and line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            raise ValueError("candidate must not rename or copy paths")
        elif line == "GIT binary patch":
            raise ValueError("candidate must be a textual source patch")
    if not names:
        raise ValueError("empty candidate patch")
    return sorted(names)


def apply_candidate(root, manifest, output):
    root = root.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {"success": False, "source_qualified": False, "patch_applied": False,
              "scope": __doc__, "commands": []}
    scratch = None
    try:
        description = json.loads(manifest.read_text())
        if type(description["version"]) is not int or description["version"] != 1:
            raise ValueError("unknown candidate manifest version")
        for key in ("patch_sha256", "base_source_digest", "target_source_digest"):
            if not isinstance(description[key], str) or not re.fullmatch("[0-9a-f]{64}", description[key]):
                raise ValueError(f"invalid candidate digest: {key}")
        patch_file = contained(manifest.parent.resolve(), description["patch"])
        patch = patch_file.read_bytes()
        if hashlib.sha256(patch).hexdigest() != description["patch_sha256"]:
            raise ValueError("candidate patch checksum differs")
        names = patch_paths(root, patch)
        if names != description["paths"]:
            raise ValueError("candidate manifest path inventory differs")
        before = source_inputs(root)
        (output / "before-source.json").write_text(json.dumps(before, indent=2) + "\n")
        result.update(base_source_digest=digest(before), patch_sha256=description["patch_sha256"],
                      manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(), paths=names,
                      base_commit=description["base_commit"])
        if digest(before) != description["base_source_digest"]:
            raise ValueError("checkout source does not match the candidate base")
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        with tempfile.TemporaryDirectory(prefix="rax-native-candidate-") as tmp:
            scratch = Path(tmp)
            snapshot = scratch / "candidate.patch"
            snapshot.write_bytes(patch)
            for label, extra in [("check", ["--check"]), ("apply", [])]:
                argv = ["git", "apply", "--whitespace=nowarn", *extra, str(snapshot)]
                completed = subprocess.run(argv, cwd=root, env=environment,
                                           capture_output=True, text=True, timeout=30)
                (output / (label + ".stdout")).write_text(completed.stdout)
                (output / (label + ".stderr")).write_text(completed.stderr)
                result["commands"].append({"label": label, "argv": argv,
                                           "exit_code": completed.returncode})
                if completed.returncode:
                    raise RuntimeError(f"candidate {label} failed: {completed.returncode}")
            result["patch_applied"] = True
        after = source_inputs(root)
        (output / "after-source.json").write_text(json.dumps(after, indent=2) + "\n")
        result["target_source_digest"] = digest(after)
        if digest(after) != description["target_source_digest"]:
            raise ValueError("applied candidate source differs from the pinned target")
        result.update(success=True, source_qualified=True)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = repr(error)
    finally:
        result["owned_build_removed"] = scratch is None or not scratch.exists()
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = apply_candidate(args.repo, args.manifest.resolve(), args.output.resolve())
    print(json.dumps({key: result.get(key) for key in (
        "success", "source_qualified", "patch_applied", "error", "owned_build_removed")}))
    return 0 if result["success"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
