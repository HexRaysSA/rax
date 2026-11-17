#!/usr/bin/env python3
"""Compile-only 6-host x C23/C++23 declaration/layout witnesses, no native launch."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[3]
HEADER=ROOT/'tools/smir-runtime-contract/include/rax_portable_contract_v1.h'
TARGETS=['x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu',
         'x86_64-apple-macos13','arm64-apple-macos13',
         'x86_64-pc-windows-msvc','aarch64-pc-windows-msvc']


def run(compiler=None):
    compiler=compiler or shutil.which('clang')
    if compiler is None:raise RuntimeError('clang unavailable; no skip is a pass')
    compiler=str(Path(compiler).resolve())
    resource=subprocess.check_output([compiler,'-print-resource-dir'],text=True).strip()
    results=[]
    source='#include "rax_portable_contract_v1.h"\nint check(void) { return (int)sizeof(RaxPortableConfigV1); }\n'
    with tempfile.TemporaryDirectory(prefix='rax-runtime-capi-') as directory:
        path=Path(directory)/'probe.c';path.write_text(source)
        for target in TARGETS:
            for language,standard in [('c','c2x'),('c++','c++23')]:
                command=[compiler,'-target',target,'-x',language,'-std='+standard,'-ffreestanding',
                         '-nostdinc','-isystem',resource+'/include','-I',str(HEADER.parent),
                         '-Wall','-Wextra','-Werror','-fsyntax-only',str(path)]
                result=subprocess.run(command,text=True,capture_output=True)
                results.append({'target':target,'language':language,'command':command,'exit':result.returncode,
                                'stderr':result.stderr})
    return {'compiler':compiler,'version':subprocess.check_output([compiler,'--version'],text=True),
            'header_sha256':hashlib.sha256(HEADER.read_bytes()).hexdigest(),
            'probe_sha256':hashlib.sha256(source.encode()).hexdigest(),'results':results,
            'pass':sum(r['exit']==0 for r in results),'fail':sum(r['exit']!=0 for r in results),
            'limits':'compile-only declarations and static layouts; no linked ABI, runtime or OS qualification'}


if __name__=='__main__':
    result=run();print(json.dumps(result,indent=2));raise SystemExit(bool(result['fail']))
