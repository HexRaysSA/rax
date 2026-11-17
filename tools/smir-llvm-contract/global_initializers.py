#!/usr/bin/env python3
"""Pinned, header-free source-initializer witnesses; no target code execution."""
import argparse
import json
from pathlib import Path
import subprocess


CASES = {
    'ptr64': ('unsigned long', '(unsigned long)&target[1]'),
    'ptr32_direct': ('unsigned int', '(unsigned int)&target[1]'),
    'ptr8_direct': ('unsigned char', '(unsigned char)&target[1]'),
    'bitint33_via64': ('unsigned _BitInt(33)', '(unsigned long)&target[1]'),
    'bitint65_via64': ('unsigned _BitInt(65)', '(unsigned long)&target[1]'),
    'wide128_via64': ('unsigned __int128', '(unsigned long)&target[1]'),
    'mask': ('unsigned long', '((unsigned long)&target[1]) & 65535UL'),
    'bias': ('unsigned long', '(unsigned long)&target[1] + 7UL'),
    'same_object_delta': ('unsigned long', '(unsigned long)&target[1] - (unsigned long)&target[0]'),
    'two_object_delta': ('unsigned long', '(unsigned long)&target[1] - (unsigned long)&other'),
}
MODES = {'O0': ['-O0'], 'O2': ['-O2'],
         'thin': ['-O2', '-flto=thin'], 'full': ['-O2', '-flto=full']}


def observe(clang, output):
    """160 finite compilations, O(C) subprocesses and retained output bytes.

    full/thin are PRELINK IR only. Compiler identity and source hashes belong to
    validate.py's encompassing receipt; this report records actual argv/results.
    """
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for mode, options in MODES.items():
        for target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'):
            for language, extension in (('c23', 'c'), ('c++23', 'cpp')):
                for name, (typ, expression) in CASES.items():
                    stem = '-'.join((mode, target, extension, name))
                    source, ir = output / (stem + '.' + extension), output / (stem + '.ll')
                    source.write_text('int target[2]; int other;\n' + typ + ' result = ' + expression + ';\n')
                    argv = [str(clang), '-target', target, '-std=' + language,
                            *options, '-S', '-emit-llvm', str(source), '-o', str(ir)]
                    process = subprocess.run(argv, capture_output=True, text=True)
                    row = dict(mode=mode, target=target, language=language, case=name,
                               argv=argv, returncode=process.returncode, diagnostics=process.stderr)
                    if process.returncode == 0:
                        text = ir.read_text()
                        row.update(initializer=next(line for line in text.splitlines()
                                                   if line.startswith('@result =')),
                                   dynamic_ctors='@llvm.global_ctors' in text)
                    rows.append(row)
    (output / 'observations.json').write_text(json.dumps(rows, indent=2) + '\n')
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = observe(args.clang, args.output)
    print(json.dumps(dict(compilations=len(result), accepted=sum(r['returncode'] == 0 for r in result))))
