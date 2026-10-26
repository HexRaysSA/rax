"""Common retained QEMU guest build, execution and source binding."""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_corpus(
    *,
    names,
    make_input,
    initial_disk,
    validate_reference,
    allowed_codes,
    comparison_source,
    source_paths,
    tool_path,
    reference_differences,
    drive_options="",
):
    """Build and retain a synchronous AArch64 modern-MMIO reference corpus."""
    parser = argparse.ArgumentParser(
        description='Execute a retained modern virtio-MMIO guest corpus.'
    )
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--library', type=Path)
    parser.add_argument('--dependency-dir', type=Path)
    args = parser.parse_args()
    root, work = args.repo.resolve(), args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    library = args.library or args.target_dir / 'debug/librax.rlib'
    dependencies = args.dependency_dir or args.target_dir / 'debug/deps'
    assert library.is_file(), (
        'Build the current product library before running the oracle.'
    )
    library_hash = sha(library)
    source_hashes = {p: sha(root / p) for p in source_paths}
    commands = []

    def run(name, command, cwd=work, timeout=60, allowed_codes=(0,)):
        start = time.monotonic()
        result = subprocess.run(
            [str(v) for v in command],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        (work / (name + '.stdout')).write_bytes(result.stdout)
        (work / (name + '.stderr')).write_bytes(result.stderr)
        commands.append(
            {
                'name': name,
                'command': [str(v) for v in command],
                'code': result.returncode,
                'seconds': time.monotonic() - start,
            }
        )
        assert result.returncode in allowed_codes, (
            name,
            result.stderr.decode(errors='replace')[-2000:],
        )
        return result.stdout

    compare = work / 'compare'
    compare.unlink(missing_ok=True)
    run(
        'owning-build',
        [
            'rustc',
            '+stable',
            '--edition',
            '2024',
            root / comparison_source,
            '--extern',
            f'rax={library}',
            '-L',
            f'dependency={dependencies}',
            '-o',
            compare,
        ],
    )
    qemu = shutil.which('qemu-system-aarch64')
    assert qemu
    cases = []
    for index, name in enumerate(names):
        case = work / f'case-{index:02d}'
        case.mkdir(exist_ok=True)
        raw, expected, disk, count = make_input(index)
        (case / 'input.bin').write_bytes(raw)
        (case / 'expected.bin').write_bytes(expected)
        (case / 'expected-media.bin').write_bytes(disk)
        (case / 'disk.raw').write_bytes(initial_disk())
        shutil.copyfile(root / 'tools/virtio-diff/indirect_guest.s', case / 'guest.s')
        run(
            f'assemble-{index}',
            [
                args.llvm_bin / 'llvm-mc',
                '-triple=aarch64-none-elf',
                '-filetype=obj',
                'guest.s',
                '-o',
                'guest.o',
            ],
            cwd=case,
        )
        run(
            f'link-{index}',
            [
                args.llvm_bin / 'ld.lld',
                '-Ttext=0x40080000',
                '-e',
                '_start',
                'guest.o',
                '-o',
                'guest.elf',
            ],
            cwd=case,
        )
        run(
            f'qemu-{index}',
            [
                qemu,
                '-machine',
                'virt',
                '-cpu',
                'max',
                '-m',
                '64M',
                '-accel',
                'tcg',
                '-display',
                'none',
                '-monitor',
                'none',
                '-serial',
                f'file:{case / "records.bin"}',
                '-no-reboot',
                '-global',
                'virtio-mmio.force-legacy=false',
                '-drive',
                f'file={case / "disk.raw"},format=raw,if=none,id=disk{drive_options}',
                '-device',
                'virtio-blk-device,drive=disk,serial=rax-virtio-blk',
                '-semihosting-config',
                'enable=on,target=native',
                '-kernel',
                case / 'guest.elf',
            ],
            timeout=30,
            allowed_codes=allowed_codes(index),
        )
        frame = (case / 'records.bin').read_bytes()
        validate_reference(index, case, frame, expected, disk, work, count)
        low, high, maximum = struct.unpack_from('<III', frame, 12)
        cases.append(
            {
                'index': index,
                'name': name,
                'commands': count,
                'frame_bytes': len(frame),
                'feature_words': [low, high],
                'queue_max': maximum,
                'artifacts': {p.name: sha(p) for p in case.iterdir() if p.is_file()},
            }
        )
    report = json.loads(run('product-compare', [compare, work]))
    assert report['cases'] == len(names) and report['failed'] == 0, report
    assert sha(library) == library_hash
    assert source_hashes == {p: sha(root / p) for p in source_paths}
    manifest = {
        'result': 'shared_contract_verified_with_explicit_reference_differences',
        'cases': cases,
        'report': report,
        'reference_differences': reference_differences,
        'commands': commands,
        'tool_sha256': sha(tool_path),
        'helper_sha256': sha(Path(__file__)),
        'source_sha256': source_hashes,
        'library_sha256': library_hash,
        'qemu_version': subprocess.check_output(
            [qemu, '--version'], text=True
        ).splitlines()[0],
        'reference_scope': 'QEMU TCG guest execution and owning product source replay; no native hypervisor execution.',
    }
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(report))
