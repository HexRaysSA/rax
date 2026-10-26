#!/usr/bin/env python3
"""Execute actual NVMe queue creation/deletion and feature admission in QEMU.

Fourteen independent PCI guests retain all input SQEs and raw CQEs. Mandatory
completion fields are compared with the production device;DNR policy differences
are reported explicitly with raw records retained, never treated as full CQE
identity. The reference uses mqes255/max_ioqpairs4 to match the selected profile.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path
import shutil
import struct
import subprocess
import time

CASES = [
    'normal-lifetime',
    'duplicate-cq',
    'duplicate-sq',
    'cq-sizes',
    'sq-sizes',
    'queue-identifiers',
    'missing-cq',
    'cq-offsets',
    'sq-offsets',
    'contiguous',
    'physical-zero',
    'feature-invalid',
    'feature-selectors',
    'cq-entry-size',
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def queue(op, qid=1, size=4, base=0x01004000, flags=1):
    c = bytearray(64)
    c[0] = op
    struct.pack_into('<Q', c, 24, base)
    struct.pack_into('<II', c, 40, qid | ((size - 1) << 16), flags)
    return c


def feature(op, value, request=0):
    c = bytearray(64)
    c[0] = op
    struct.pack_into('<II', c, 40, value, request)
    return c


def make_input(index):
    cq = lambda **kw: queue(5, **kw)
    sq = lambda **kw: queue(
        1, base=kw.pop('base', 0x01006000), flags=kw.pop('flags', 0x10001), **kw
    )
    dc = lambda: queue(4)
    ds = lambda: queue(0)
    setq = lambda value=7, request=0: feature(9, value, request)
    getq = lambda selector: feature(10, 7 | (selector << 8))
    cc = 0x00460001
    if index == 0:
        commands = [setq(), cq(), sq(), dc(), ds(), dc(), setq(), getq(3)]
    elif index == 1:
        commands = [cq(), cq(base=0x01008000)]
    elif index == 2:
        commands = [cq(), sq(), sq(base=0x01008000)]
    elif index == 3:
        commands = [cq(size=1), cq(size=256), cq(qid=2, size=257)]
    elif index == 4:
        commands = [cq(), sq(size=1), sq(size=256), sq(qid=2, size=257)]
    elif index == 5:
        commands = [
            cq(qid=0),
            cq(qid=5),
            cq(),
            sq(qid=0),
            queue(4, qid=0),
            queue(0, qid=0),
        ]
    elif index == 6:
        commands = [sq(qid=2, flags=0x20001)]
    elif index == 7:
        commands = [cq(qid=2, base=0x01004008), cq(qid=2, base=0x01004FFF)]
    elif index == 8:
        commands = [cq(), sq(qid=2, base=0x01006008), sq(qid=2, base=0x01006FFF)]
    elif index == 9:
        commands = [cq(flags=0), cq(), sq(flags=0x10000)]
    elif index == 10:
        commands = [cq(base=0), sq(), ds(), dc(), cq(), sq(base=0)]
    elif index == 11:
        commands = [
            setq(request=0xFFFF),
            setq(request=0xFFFF0000),
            setq(request=0xFFFFFFFF),
            setq(value=0x80000007),
        ]
    elif index == 12:
        commands = [getq(i) for i in range(8)]
    elif index == 13:
        cc = 0x00060001
        commands = [cq()]
    else:
        raise ValueError(index)
    for i, c in enumerate(commands):
        struct.pack_into('<H', c, 2, 0x7000 + i)
    return struct.pack('<II', cc, len(commands)) + b''.join(commands)


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
    marker = out / '.rax-nvme-admission'
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
            'tests/suites/devices/nvme_admission.rs',
        ]
    }
    manifest = {
        'product_source_sha256': bound,
        'version': 1,
        'cases': len(CASES),
        'tool_sha256': sha(Path(__file__)),
        'guest_source_sha256': sha(here / 'admission_guest.s'),
        'commands': [],
        'cases_completed': [],
        'scope': __doc__,
        'guest_ram_bytes': 128 << 20,
        'reference_limit': 'DeleteCQ0 returns 0x100 in QEMU versus primary Figure161/RAX 0x101. Reserved SEL4-7 return current values in QEMU versus explicit RAX Invalid Field. DNR policy differs on24 commands. Every difference is retained;no full CQE/profile equivalence claim.',
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
        shutil.copyfile(here / 'admission_guest.s', case / 'guest.s')
        (case / 'link.ld').write_text(
            'ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n'
        )
        cc, count = struct.unpack_from('<II', (case / 'input.bin').read_bytes())
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
                'nvme,drive=prpdisk,serial=RAXADMISSION,mdts=9,mqes=255,max_ioqpairs=4',
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
        assert len(records) == 24 + count * 16, (index, len(records), count)
        assert (
            records[:8] == b'RAXNVAD1'
            and records[8:16] == (case / 'input.bin').read_bytes()[:8]
        )
        assert records[-8:] == b'NVADDONE'
        completions = []
        for slot in range(count):
            cqe = records[16 + slot * 16 : 32 + slot * 16]
            head, sqid, cid, status = struct.unpack('<HHHH', cqe[8:])
            assert (head, sqid, cid, status & 1) == (slot + 1, 0, 0x7000 + slot, 1), (
                index,
                slot,
                cqe.hex(),
            )
            completions.append(cqe.hex())
        assert (case / 'disk.raw').read_bytes() == initial
        manifest['cases_completed'].append(
            {
                'index': index,
                'name': CASES[index],
                'commands': count,
                'completions': completions,
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
        manifest['comparison_source_sha256'] = sha(here / 'admission_compare.rs')
        run(
            'owning-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                '--test',
                str(repo / 'tests/suites/devices/nvme_admission.rs'),
                '--extern',
                'rax=' + str(out / 'librax.rlib'),
                '-L',
                'dependency=' + str(library.parent / 'deps'),
                '-o',
                str(out / 'owning'),
            ],
        )
        run('owning-inventory', [str(out / 'owning'), '--list', '--format', 'terse'])
        inventory = [
            line.removesuffix(': test')
            for line in (out / 'owning-inventory.stdout').read_text().splitlines()
            if line.endswith(': test')
        ]
        assert len(inventory) >= 47 and len(set(inventory)) == len(inventory)
        for required in [
            'every_admin_queue_wire_size_is_independent_of_io_mqes',
            'minimum_one_entry_admin_queue_never_enables_or_performs_dma',
        ]:
            assert required in inventory
        run('owning', [str(out / 'owning'), '--test-threads=4'])
        summaries = re.findall(
            r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; '
            r'\d+ measured; (\d+) filtered out;',
            (out / 'owning.stdout').read_text(),
        )
        assert summaries == [(str(len(inventory)), '0', '0', '0')]
        manifest['owning_inventory'] = {
            'count': len(inventory),
            'tests': inventory,
            'log_sha256': sha(out / 'owning-inventory.stdout'),
            'result': 'complete_unfiltered_owner_passed',
        }
        run(
            'comparison-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(here / 'admission_compare.rs'),
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
        assert report['cases'] == 14 and report['failed'] == 0
        manifest['report'] = report
        assert (
            report['dnr_differences'] == 24
            and report['primary_policy_differences'] == 5
        )
        manifest['result'] = (
            'reference_common_fields_match_with_primary_policy_differences'
        )
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
