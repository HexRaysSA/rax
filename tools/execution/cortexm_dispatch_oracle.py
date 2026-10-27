"""Independent factory-created Cortex-M instruction/state observations."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def expected():
    rows = []
    for count in [1, 2, 4]:
        for identity in range(count):
            rows.extend([count, identity, 3, 0x1006, 43, 42])
    return struct.pack('<42Q', *rows)


def verify(directory):
    assert (directory / 'rows.bin').read_bytes() == expected()
    return dict(cpus=7, retired_units=21, observed_bytes=336, failed=0)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    a = p.parse_args()
    root = a.repo.resolve()
    out = a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = [
        'src/backend/emulator/mod.rs',
        'tests/suites/backend/cortexm_dispatch.rs',
        'tools/execution/cortexm_dispatch_guest.rs',
        'tools/execution/cortexm_dispatch_oracle.py',
    ]
    before = {n: sha(root / n) for n in names}
    e = os.environ.copy()
    e.update(
        CARGO_TARGET_DIR=str(a.target_dir),
        CARGO_BUILD_JOBS='1',
        CARGO_MANIFEST_DIR=str(root),
    )
    commands = []

    def run(name, args, timeout):
        start = time.monotonic()
        r = subprocess.run(args, cwd=root, env=e, capture_output=True, timeout=timeout)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        commands.append(
            dict(
                name=name,
                args=args,
                code=r.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert r.returncode == 0, (name, r.stderr[-4000:])
        return r

    r = run(
        'library',
        [
            'cargo',
            '+stable',
            'build',
            '--locked',
            '--offline',
            '--no-default-features',
            '--features',
            'x86_64-suite,smir-jit,hvf',
            '--lib',
            '--bin',
            'rax',
            '--message-format=json',
        ],
        600,
    )
    artifacts = {}
    for line in r.stdout.splitlines():
        m = json.loads(line)
        if m.get('reason') == 'compiler-artifact' and m['target']['name'] in [
            'rax',
            'vm_memory',
        ]:
            for f in m['filenames']:
                if f.endswith('.rlib'):
                    artifacts[m['target']['name']] = Path(f)
    assert set(artifacts) == {'rax', 'vm_memory'}
    for n, f in artifacts.items():
        shutil.copyfile(f, out / ('lib' + n + '.rlib'))
    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/execution/cortexm_dispatch_guest.rs'),
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '--extern',
            'vm_memory=' + str(out / 'libvm_memory.rlib'),
            '-L',
            'dependency=' + str(a.target_dir / 'debug/deps'),
            '-o',
            str(out / 'publish'),
        ],
        60,
    )
    run('publish', [str(out / 'publish'), str(out / 'rows.bin')], 60)
    report = verify(out)
    original = (out / 'rows.bin').read_bytes()
    probes = []
    for i in range(42):
        mutant = bytearray(original)
        mutant[8 * i] ^= 1
        (out / 'rows.bin').write_bytes(mutant)
        try:
            try:
                verify(out)
            except AssertionError:
                pass
            else:
                raise RuntimeError('Verifier accepted mutated word' + str(i))
        finally:
            (out / 'rows.bin').write_bytes(original)
        probes.append(
            dict(
                word=i, rejected=True, mutant_sha256=hashlib.sha256(mutant).hexdigest()
            )
        )
    assert verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=42, rejected=42, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_factory_cortexm_execution_rows_match',
                report=report,
                commands=commands,
                source_sha256=before,
                libraries_sha256={
                    n: sha(out / ('lib' + n + '.rlib')) for n in artifacts
                },
                output_sha256=sha(out / 'rows.bin'),
                fault_injection_sha256=sha(out / 'fault-injection.json'),
                scope='Factory-created M4 adapters execute21Thumb instructions across7separate CPU objects;336state bytes checked independently.No board peripheral/IRQ/SMP/native/full-private-state proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
