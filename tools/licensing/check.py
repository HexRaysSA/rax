#!/usr/bin/env python3
"""Check licensing metadata, notice propagation and Cargo file boundaries."""
import argparse
import os
from pathlib import Path, PurePosixPath
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
LEGAL_FILES = ('LICENSE', 'THIRD_PARTY_NOTICES.md')
COMMON = {*LEGAL_FILES, 'Cargo.toml', 'Cargo.toml.orig', 'Cargo.lock', 'README.md', '.cargo_vcs_info.json'}


def package_paths(listing, separator=os.sep):
    """Return `cargo package --list` entries as archive-relative POSIX paths.

    Cargo prints each entry with the host path separator, so Windows lists
    `src\\lib.rs` for the archive member `src/lib.rs`.
    """
    return [line.replace(separator, '/') for line in listing.splitlines()]


def validate_payload(package, paths):
    paths = set(paths)
    missing = set(LEGAL_FILES) - paths
    if missing:
        raise ValueError(f'{package}: missing legal files: {sorted(missing)}')
    unexpected = []
    for path in paths:
        p = PurePosixPath(path)
        allowed = path in COMMON or (path.startswith('src/') and p.suffix == '.rs')
        if package == 'rax-capi':
            allowed |= path in {'build.rs', 'CMakeLists.txt', 'Makefile', 'rax.pc.in'}
            allowed |= (bool(p.parts) and p.parts[0] in {'include', 'tests', 'examples', 'cmake'}
                        and p.suffix in {'.h', '.hpp', '.c', '.cpp', '.rs', '.in'})
            allowed |= path == 'tests/consumer/CMakeLists.txt'
        if p.is_absolute() or '..' in p.parts or not allowed:
            unexpected.append(path)
    if unexpected:
        raise ValueError(f'{package}: unexpected package files: {sorted(unexpected)}')


def check_notices(root):
    for name in LEGAL_FILES:
        if (root / name).read_bytes() != (root / 'capi' / name).read_bytes():
            raise ValueError(f'capi/{name} differs from root {name}')
    source = (root / 'src/smir/interpret/mod.rs').read_text()
    start = source.index('// Copyright (c) 2015, Intel Corporation')
    end = source.index('\nconst X86_EXP2_23_COEFFICIENTS', start)
    notice = '\n'.join(line.removeprefix('//').removeprefix(' ')
                       for line in source[start:end].splitlines())
    if notice not in (root / 'THIRD_PARTY_NOTICES.md').read_text():
        raise ValueError('Intel notice differs from the source notice')
    for package, relative, license_id in (
        ('rax', '.', 'MIT AND BSD-3-Clause'), ('rax-capi', 'capi', 'MIT')
    ):
        manifest = tomllib.loads((root / relative / 'Cargo.toml').read_text())['package']
        if manifest.get('license') != license_id or not manifest.get('include'):
            raise ValueError(f'{package}: missing license expression or explicit include list')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    check_notices(root)
    for package in ('rax', 'rax-capi'):
        result = subprocess.run(
            ['cargo', 'package', '-p', package, '--list', '--locked', '--allow-dirty'],
            cwd=root, check=True, stdout=subprocess.PIPE, text=True)
        paths = package_paths(result.stdout)
        validate_payload(package, paths)
        print(f'{package}: {len(paths)} package files; notices and boundaries verified')


if __name__ == '__main__':
    main()
