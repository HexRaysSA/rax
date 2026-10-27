"""Independent raw CPU/RAM/padding expectations for actual runtime bundle restore."""

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


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(directory):
    cases = []
    for index in range(6):
        positive = index < 2
        ram = directory / f'case-{index}.ram'
        cpu = directory / f'case-{index}.cpu'
        padding = directory / f'case-{index}.padding'
        assert ram.read_bytes() == bytes([0x33 if positive else 0xA5]) * 4096
        assert cpu.read_bytes() == struct.pack('<Q', 0x12345678 if positive else 0)
        assert padding.read_bytes() == b'\x6d'
        cases.append(
            dict(
                index=index,
                accepted=positive,
                artifacts={p.name: sha(p) for p in [ram, cpu, padding]},
            )
        )
    assert (directory / 'publish.stdout').read_text().splitlines() == [
        f'{i}\t{int(i < 2)}' for i in range(6)
    ]
    return dict(
        cases=6,
        accepted=2,
        rejected=4,
        ram_bytes=24576,
        cpu_marker_bytes=48,
        padding_bytes=6,
        failed=0,
    ), cases


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    a = p.parse_args()
    root, out = a.repo.resolve(), a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [
        'src/vm/runtime.rs',
        'src/vm/runtime/pci_state.rs',
        'src/devices/pci/checkpoint.rs',
        'src/vm/snapshot/pci.rs',
        'src/vm/snapshot/physical_memory.rs',
        'tests/suites/vm/runtime_checkpoint_bundle.rs',
        'tools/checkpoint/runtime_bundle_guest.rs',
        'tools/checkpoint/runtime_bundle_oracle.py',
    ]
    before = {n: sha(root / n) for n in sources}
    library = out / 'librax.rlib'
    shutil.copyfile(a.target_dir / 'debug/librax.rlib', library)
    env = os.environ.copy()
    env['CARGO_MANIFEST_DIR'] = str(root)
    commands = []
    for name, command in [
        (
            'build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(root / 'tools/checkpoint/runtime_bundle_guest.rs'),
                '--extern',
                'rax=' + str(library),
                '-L',
                'dependency=' + str(a.target_dir / 'debug/deps'),
                '-o',
                str(out / 'publish'),
            ],
        ),
        ('publish', [str(out / 'publish'), str(out)]),
    ]:
        start = time.monotonic()
        result = subprocess.run(
            command, cwd=root, env=env, capture_output=True, timeout=60
        )
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        commands.append(
            dict(
                name=name,
                args=command,
                code=result.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert result.returncode == 0, (name, result.stderr[-2000:])
    report, cases = verify(out)
    assert before == {n: sha(root / n) for n in sources}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_represented_restore_bytes_match_independent_expectations',
                report=report,
                cases=cases,
                commands=commands,
                source_sha256=before,
                library_sha256=sha(library),
                scope='Six actual public runtime cases: CPU marker,reported RAM,padding;live internal tests separately check complete represented CPU/private/legacy/PCI/media state. No guest/native execution claim.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
