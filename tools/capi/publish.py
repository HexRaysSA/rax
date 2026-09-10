#!/usr/bin/env python3
"""Publish only a complete, checksum-verified set of SDKs for an existing tag."""
import argparse
import json
from pathlib import Path
import subprocess
import tomllib

from package import ROOT, TARGETS, digest, validate_tag


def verify_assets(dist, version):
    expected = set()
    for target, spec in TARGETS.items():
        suffix = "zip" if "windows" in target else "tar.gz"
        name = f"rax-capi-{version}-{target}.{suffix}"
        archive = dist / name
        checksum = dist / (name + ".sha256")
        # Candidate lanes upload only after the same execution gates pass.
        # Absence is allowed; a partial or corrupt pair is always an error.
        if spec.experimental and not archive.exists() and not checksum.exists():
            continue
        if not archive.is_file() or not checksum.is_file():
            raise ValueError(f"missing release asset: {name} or checksum")
        if checksum.read_text().strip() != f"{digest(archive)}  {name}":
            raise ValueError(f"checksum mismatch: {name}")
        expected.update((archive.name, checksum.name))
    if {p.name for p in dist.iterdir()} != expected:
        raise ValueError("unexpected files in release asset directory")
    return [dist / name for name in sorted(expected)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dist", type=Path, required=True)
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "capi/Cargo.toml").read_text())["package"]["version"]
    validate_tag(args.tag, version)
    assets = verify_assets(args.dist, version)
    # Distinguish an absent release from authentication/network errors.
    releases = json.loads(subprocess.check_output(
        ["gh", "release", "list", "--limit", "1000", "--json", "tagName,isDraft"], text=True))
    existing = next((r for r in releases if r["tagName"] == args.tag), None)
    if existing and not existing["isDraft"]:
        raise RuntimeError("release already published; refusing to replace published binaries")
    prerelease = "-" in version
    if existing is None:
        subprocess.run(["gh", "release", "create", args.tag, "--verify-tag", "--draft",
                        "--title", f"RAX {args.tag}", "--notes-file", str(ROOT / "tools/capi/release-notes.md")]
                       + (["--prerelease"] if prerelease else []), check=True)
    # Draft uploads can be retried; a partial upload is never a public release.
    subprocess.run(["gh", "release", "upload", args.tag, "--clobber", *map(str, assets)], check=True)
    subprocess.run(["gh", "release", "edit", args.tag, "--draft=false",
                    f"--prerelease={'true' if prerelease else 'false'}"], check=True)


if __name__ == "__main__":
    main()
