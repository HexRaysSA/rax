#!/usr/bin/env python3
"""Execute actual NVMe CQ backpressure, wrap, PCI pin interrupts and reset in QEMU.

Each case starts a fresh PCI controller and private raw disk. The guest submits
131 Flush commands, retains full CQ snapshots while a command is blocked by
backpressure, acknowledges entries, captures every CQE and PCI interrupt-status
observation, and resets the controller. No RAX-generated reference.
"""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time

CASES = [(2, 0), (2, 1), (3, 1), (4, 1), (7, 1), (16, 1), (64, 1)]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_input(index):
    size, ien = CASES[index]
    return struct.pack('<III', size, ien, 130)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--repo', type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--reference-only', action='store_true')
    parser.add_argument('--target-dir', type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    if not (repo / 'src/devices/nvme.rs').is_file():
        raise ValueError('--repo must name a RAX checkout')
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    marker = out / '.rax-nvme-queues'
    if any(out.iterdir()) and (
        not marker.is_file() or marker.read_text() != 'version=1\n'
    ):
        raise ValueError('Use an empty or owned version1 directory')
    marker.write_text('version=1\n')
    here = Path(__file__).resolve().parent
    if not args.reference_only and here.parents[1].resolve() != repo:
        raise ValueError('Run the comparison tool from the selected --repo checkout')
    if not args.reference_only and (
        args.target_dir is None
        or not (args.target_dir.resolve() / 'debug/librax.rlib').is_file()
    ):
        raise ValueError(
            '--target-dir must contain a built debug/librax.rlib;run cargo build --lib first'
        )
    bound = {
        name: sha(repo / name)
        for name in [
            'src/devices/nvme.rs',
            'src/devices/nvme/nvm.rs',
            'src/devices/nvme/prp.rs',
            'src/devices/nvme/sgl.rs',
            'tests/suites/devices/nvme_prp.rs',
            'tests/suites/devices/nvme_queues.rs',
        ]
    }
    manifest = {
        'product_source_sha256': bound,
        'version': 1,
        'cases': len(CASES),
        'tool_sha256': sha(Path(__file__)),
        'guest_source_sha256': sha(here / 'queue_guest.s'),
        'commands': [],
        'cases_completed': [],
        'scope': __doc__,
        'guest_ram_bytes': 128 << 20,
        'reference_limit': 'Single-vector pin profile;no native hardware or MSI/MSI-X delivery claim. Failed DMA policies are local primary-contract tests.',
    }

    def run(name, command, cwd=out, expected=0):
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            manifest['commands'].append(
                {
                    'name': name,
                    'args': command,
                    'code': 'timeout',
                    'seconds': time.monotonic() - start,
                }
            )
            (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            raise RuntimeError(name + ' timed out;no passing result') from None
        (cwd / (name + '.stdout')).write_bytes(result.stdout)
        (cwd / (name + '.stderr')).write_bytes(result.stderr)
        manifest['commands'].append(
            {
                'name': name,
                'args': command,
                'code': result.returncode,
                'seconds': time.monotonic() - start,
            }
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        if result.returncode != expected:
            raise RuntimeError(
                name + f' returned{result.returncode};retained raw diagnostics'
            )

    run('qemu-version', [args.qemu, '--version'])
    run('nvme-options', [args.qemu, '-device', 'nvme,help'])
    llvm = args.llvm_bin.resolve()
    run('llvm-version', [str(llvm / 'llvm-mc'), '--version'])
    for index in range(len(CASES)):
        case = out / f'case-{index}'
        case.mkdir(exist_ok=True)
        (case / 'input.bin').write_bytes(make_input(index))
        shutil.copyfile(here / 'queue_guest.s', case / 'guest.s')
        (case / 'link.ld').write_text(
            'ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n'
        )
        size, ien, count = struct.unpack('<III', (case / 'input.bin').read_bytes())
        initial = bytes(4096)
        (case / 'disk.raw').write_bytes(initial)
        run(
            'assemble',
            [
                str(llvm / 'llvm-mc'),
                '-triple=i386-none-elf',
                '-filetype=obj',
                'guest.s',
                '-o',
                'guest.o',
            ],
            case,
        )
        run(
            'link',
            [
                str(llvm / 'ld.lld'),
                '-m',
                'elf_i386',
                '-T',
                'link.ld',
                'guest.o',
                '-o',
                'guest.elf',
            ],
            case,
        )
        run(
            'qemu',
            [
                args.qemu,
                '-machine',
                'pc',
                '-cpu',
                'max',
                '-accel',
                'tcg,thread=single',
                '-m',
                '128M',
                '-nodefaults',
                '-display',
                'none',
                '-monitor',
                'none',
                '-serial',
                'none',
                '-debugcon',
                'file:' + str(case / 'records.bin'),
                '-drive',
                'if=none,id=prpdisk,format=raw,file=' + str(case / 'disk.raw'),
                '-device',
                'nvme,drive=prpdisk,serial=RAXSGLTEST,mdts=9',
                '-device',
                'isa-debug-exit,iobase=0xf4,iosize=0x04',
                '-no-reboot',
                '-kernel',
                str(case / 'guest.elf'),
            ],
            case,
            33,
        )
        records = (case / 'records.bin').read_bytes()
        stalls = count - size + 1
        assert len(records) == 20 + stalls * size * 16 + count * 20 + 44 + 8, (
            index,
            len(records),
        )
        assert (
            records[:8] == b'RAXNVQ01'
            and records[8:20] == (case / 'input.bin').read_bytes()
        )
        assert records[-8:] == b'NVQ0DONE'
        at = 20
        cqes, levels = [], []
        for sequence in range(count):
            if sequence + 1 >= size:
                at += size * 16
            cqe = records[at : at + 16]
            at += 16
            head, sqid, cid, status = struct.unpack('<HHHH', cqe[8:])
            assert (head, sqid, cid, status) == (
                (sequence + 1) % 64,
                1,
                0x5000 + sequence,
                1 ^ ((sequence // size) & 1),
            ), (index, sequence, cqe.hex())
            pin = struct.unpack_from('<I', records, at)[0]
            at += 4
            assert pin == ien, (index, sequence, pin, ien)
            cqes.append(cqe.hex())
            levels.append(pin)
        tail = records[at:-8]
        assert len(tail) == 44
        assert struct.unpack_from('<I', tail)[0] == 0
        cqe = tail[4:20]
        head, sqid, cid, status = struct.unpack('<HHHH', cqe[8:])
        assert (head, sqid, cid, status) == (
            (count + 1) % 64,
            1,
            0x5000 + count,
            1 ^ ((count // size) & 1),
        )
        pins = struct.unpack('<6I', tail[20:])
        assert pins == (ien, 0, ien, 0, 0, 0), pins
        assert (case / 'disk.raw').read_bytes() == initial
        manifest['cases_completed'].append(
            {
                'index': index,
                'queue_size': size,
                'interrupts_enabled': bool(ien),
                'commands': count + 1,
                'blocked_snapshots': stalls,
                'completions': cqes + [cqe.hex()],
                'interrupt_levels': levels + list(pins),
                'artifact_sha256': {
                    name: sha(case / name)
                    for name in [
                        'input.bin',
                        'guest.s',
                        'guest.elf',
                        'records.bin',
                        'disk.raw',
                    ]
                },
            }
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    manifest['result'] = 'reference_complete'
    if not args.reference_only:
        if args.target_dir is None:
            raise ValueError('--target-dir required for product comparison')
        # The comparator executes the exact production device through the same
        # public queue interface;its expected payloads are these actual bytes.
        library = args.target_dir.resolve() / 'debug/librax.rlib'
        before_library = sha(library)
        shutil.copyfile(library, out / 'librax.rlib')
        assert before_library == sha(library) == sha(out / 'librax.rlib'), (
            'Helper library changed while captured'
        )
        manifest['rax_library_sha256'] = before_library
        manifest['comparison_source_sha256'] = sha(here / 'queue_compare.rs')
        run(
            'owning-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                '--test',
                str(repo / 'tests/suites/devices/nvme_queues.rs'),
                '--extern',
                'rax=' + str(out / 'librax.rlib'),
                '-L',
                'dependency=' + str(library.parent / 'deps'),
                '-o',
                str(out / 'owning'),
            ],
        )
        run('owning', [str(out / 'owning'), '--test-threads=4'])
        assert (
            '48 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
            in (out / 'owning.stdout').read_text()
        )
        run(
            'comparison-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(here / 'queue_compare.rs'),
                '--extern',
                'rax=' + str(out / 'librax.rlib'),
                '-L',
                'dependency=' + str(library.parent / 'deps'),
                '-o',
                str(out / 'compare'),
            ],
        )
        run('comparison', [str(out / 'compare'), str(out)])
        report = json.loads((out / 'comparison.stdout').read_text())
        assert report['cases'] == 7 and report['failed'] == 0
        manifest['report'] = report
        manifest['result'] = 'reference_and_product_match'
    assert bound == {name: sha(repo / name) for name in bound}, (
        'Product changed during reference/product comparison'
    )
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(
        json.dumps(
            {'cases': len(manifest['cases_completed']), 'result': manifest['result']}
        )
    )


if __name__ == '__main__':
    main()
