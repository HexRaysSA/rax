"""Independent admission expectations and raw RAM/CPU checks for the same client."""

from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(folder, predecessor=False):
    lines = (folder / 'probe.stdout').read_text().splitlines()
    keys = [('ram', n) for n in [0, 1, 4095, 4097, 8192]] + [
        ('vm', n) for n in range(11)
    ]
    assert len(lines) == len(keys) == 16
    cases = []
    accepted_total = mutated_total = ram_bytes = cpu_bytes = 0
    for line, (kind, index) in zip(lines, keys):
        columns = line.split('\t')
        assert len(columns) == 4 and columns[:2] == [kind, str(index)]
        accepted, changed = map(int, columns[2:])
        assert accepted in [0, 1] and changed in [0, 1]
        path = folder / f'{kind}-{index}.raw'
        actual = path.read_bytes()
        assert len(actual) == 4096
        wanted = bytes([0xA5]) * 4096
        expected_accept = False
        marker_changed = False
        if predecessor:
            if kind == 'ram':
                expected_accept = True
                count = min(index, 4096)
                wanted = bytes([0x33]) * count + bytes([0xA5]) * (4096 - count)
            else:
                expected_accept = index in [1, 3, 4, 5, 8, 9, 10]
                if expected_accept:
                    wanted = bytes([0x33]) * 4096
                marker_changed = True
        assert actual == wanted, (kind, index, 'RAM bytes')
        artifacts = {path.name: sha(path)}
        if kind == 'vm':
            path = folder / f'vm-{index}.cpu'
            markers = path.read_bytes()
            assert len(markers) == 16
            assert struct.unpack('<QQ', markers) == (
                0,
                0x12345678 if predecessor else 0,
            )
            cpu_bytes += len(markers)
            artifacts[path.name] = sha(path)
        expected_change = marker_changed or wanted != bytes([0xA5]) * 4096
        assert (accepted, changed) == (int(expected_accept), int(expected_change)), (
            kind,
            index,
        )
        accepted_total += accepted
        mutated_total += changed
        ram_bytes += len(actual)
        cases.append(
            dict(
                kind=kind,
                index=index,
                accepted=bool(accepted),
                mutated=bool(changed),
                artifacts=artifacts,
            )
        )
    report = dict(
        cases=16,
        ram_cases=5,
        vm_cases=11,
        accepted=accepted_total,
        mutated=mutated_total,
        verified_ram_bytes=ram_bytes,
        verified_cpu_marker_bytes=cpu_bytes,
        failed=16 if predecessor else 0,
    )
    assert accepted_total == (12 if predecessor else 0)
    assert mutated_total == (15 if predecessor else 0)
    return report, cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.repo.resolve(), args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [
        'src/vm/memory.rs',
        'src/vm/runtime.rs',
        'src/vm/vcpu/mod.rs',
        'src/vm/snapshot.rs',
        'src/vm/snapshot/bundle.rs',
        'src/isa/x86_64/cpu_vcpu.rs',
        'src/isa/x86_64/cpu_emulator_state.rs',
        'src/isa/riscv/cpu/state_transfer.rs',
        'src/backend/emulator/riscv/cpu.rs',
        'src/backend/emulator/aarch64.rs',
        'tests/suites/vm/restore_admission.rs',
        'tools/checkpoint/admission_guest.rs',
        'tools/checkpoint/admission_oracle.py',
    ]
    before = {n: sha(root / n) for n in sources}
    library = out / 'librax.rlib'
    shutil.copyfile(args.target_dir / 'debug/librax.rlib', library)
    commands = []
    for name, command in [
        (
            'build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(root / 'tools/checkpoint/admission_guest.rs'),
                '--extern',
                'rax=' + str(library),
                '-L',
                'dependency=' + str(args.target_dir / 'debug/deps'),
                '-o',
                str(out / 'probe'),
            ],
        ),
        ('probe', [str(out / 'probe'), str(out)]),
    ]:
        start = time.monotonic()
        result = subprocess.run(command, cwd=root, capture_output=True, timeout=60)
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
                source_sha256=before,
                library_sha256=sha(library),
                commands=commands,
                cases=cases,
                report=report,
                result='all_admission_cases_rejected_without_mutation',
                scope='Actual VM/API state admission without executing guest CPU instructions. Native setter transactions, complete private/platform/SMP state and boot remain separate.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
