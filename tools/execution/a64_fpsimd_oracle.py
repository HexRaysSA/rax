#!/usr/bin/env python3
"""Replay the frozen FP/SIMD admission corpus against independent QEMU CPUs.

The checked-in words are immutable test inputs. This tool never derives an
expected event from RAX and never updates the checked-in expected events.
"""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / 'docs/development/a64-fpsimd-allocation/oracle-corpus.json'
GUEST = ROOT / 'docs/development/a64-half-admission'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    args = parser.parse_args()
    output = args.work_dir.resolve()
    marker = output / '.rax-admission-oracle'
    if output.exists() and any(output.iterdir()) and not marker.exists():
        raise ValueError('work directory contains unowned files')
    output.mkdir(parents=True, exist_ok=True)
    marker.write_text('Task-generated FP/SIMD oracle artifacts.\n')
    rows = json.loads(CORPUS.read_text())['records']
    expected = ''.join(row['expected'] for row in rows)
    data = output / 'words.s'
    data.write_text('.section .rodata\n.global test_words,test_words_end\ntest_words:\n'
                    + ''.join(f' .word 0x{row["word"]:08x}\n' for row in rows)
                    + 'test_words_end:\n')
    mc, ld, objcopy = (args.llvm_bin / name for name in ('llvm-mc', 'ld.lld', 'llvm-objcopy'))

    def run(command):
        return subprocess.run(list(map(str, command)), capture_output=True, check=True)

    run([mc, '-triple=aarch64', '-filetype=obj', data, '-o', output / 'words.o'])
    records, guests = [], []
    for el in (0, 1):
        key = f'el{el}-fpen0'
        obj, elf, raw = (output / (key + suffix) for suffix in ('.o', '.elf', '.bin'))
        run([mc, '-triple=aarch64', '-filetype=obj', f'--defsym=TEST_EL={el}', '--defsym=FPEN=0',
             GUEST / 'batch.s', '-o', obj])
        run([ld, '-T', GUEST / 'batch.ld', obj, output / 'words.o', '-o', elf])
        run([objcopy, '-O', 'binary', elf, raw])
        if raw.stat().st_size >= 0xf0000:
            raise ValueError('corpus overlaps the guest instruction patch page')
        guests.append(dict(key=key, elf_sha256=digest(elf), raw_sha256=digest(raw)))
        for model in ('cortex-a53', 'cortex-a76', 'cortex-a710'):
            command = [str(args.qemu), '-machine', 'virt,secure=on,virtualization=on',
                       '-cpu', model, '-m', '128M', '-display', 'none', '-monitor', 'none',
                       '-serial', 'none', '-semihosting-config', 'enable=on,target=native',
                       '-device', 'loader,file=' + str(elf) + ',cpu-num=0', '-no-reboot']
            start = time.monotonic()
            result = subprocess.run(command, capture_output=True, timeout=50)
            stem = key + '-' + model
            (output / (stem + '.stdout')).write_bytes(result.stdout)
            (output / (stem + '.stderr')).write_bytes(result.stderr)
            events = (result.stdout + result.stderr).decode()
            record = dict(key=key, model=model, command=command, code=result.returncode,
                          events=len(events), seconds=time.monotonic() - start,
                          allocated=events.count('D'), undefined=events.count('U'),
                          output_sha256=hashlib.sha256(events.encode()).hexdigest())
            records.append(record)
            (output / 'partial.json').write_text(json.dumps(records, indent=2) + '\n')
            if result.returncode or len(events) != len(rows) or set(events) - {'D', 'U'}:
                raise ValueError(('oracle/harness failure', record))
            if model == 'cortex-a710' and events != expected:
                raise ValueError(('independent oracle disagrees with frozen expected events', record))
            print(json.dumps(record), flush=True)
    result = dict(corpus_sha256=digest(CORPUS), words=len(rows), records=records, guests=guests,
                  qemu_sha256=digest(args.qemu), qemu_version=run([args.qemu, '--version']).stdout.decode(),
                  source_sha256=digest(GUEST / 'batch.s'), linker_sha256=digest(GUEST / 'batch.ld'))
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
