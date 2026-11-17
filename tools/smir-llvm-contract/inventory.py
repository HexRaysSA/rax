#!/usr/bin/env python3
"""Generate/check exhaustive draft LLVM contract matrices from pinned sources."""
import argparse
from collections import Counter
import csv
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from contracts import RECIPES, INTRINSIC_DETAILS
from frontend_contract import configuration
from bindings import core_bindings
from constant_contract import inventory as constant_inventory

from policy import (
    ADDRESS_SPACES, DEFAULT_DATA_ADDRESS_SPACE, DATALAYOUT, INSTRUCTION_RULES,
    PARAMETERLESS_CARRIERS, PIN, PROGRAM_ADDRESS_SPACE, PROGRAM_POINTER_LAYOUT,
    RULES, TRIPLE,
    attribute_rule, intrinsic_rule,
)

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'docs/specifications/smir/portable/llvm'
SOURCES = [
    'cmake/Modules/LLVMVersion.cmake', 'llvm/LICENSE.TXT',
    'llvm/docs/LangRef.md', 'llvm/docs/UndefinedBehavior.rst', 'llvm/docs/ExceptionHandling.md',
    'llvm/include/llvm/IR/Instruction.def', 'llvm/include/llvm/IR/Type.h',
    'llvm/include/llvm/IR/Attributes.td', 'llvm/include/llvm/IR/Intrinsics.td',
    'llvm/include/llvm/TargetParser/Triple.h',
    'llvm/lib/TargetParser/Triple.cpp', 'llvm/include/llvm/Target/TargetMachine.h',
    'llvm/lib/Target/SPIRV/SPIRVTargetMachine.cpp',
    'llvm/lib/Target/SPIRV/SPIRVCodeGenPassBuilder.cpp',
    'llvm/lib/Target/SPIRV/TargetInfo/SPIRVTargetInfo.cpp',
    'llvm/lib/CodeGen/CodeGenTargetMachineImpl.cpp',
    'llvm/lib/Passes/PassBuilderPipelines.cpp',
    'llvm/include/llvm/Passes/PassBuilder.h', 'clang/lib/CodeGen/BackendUtil.cpp',
    'llvm/include/llvm/Analysis/TargetLibraryInfo.h',
    'llvm/lib/BinaryFormat/Magic.cpp', 'llvm/lib/Object/Binary.cpp',
    'llvm/lib/Object/ObjectFile.cpp', 'llvm/lib/Object/ArchiveWriter.cpp',
    'llvm/include/llvm/IR/DataLayout.h', 'llvm/lib/IR/DataLayout.cpp',
    'llvm/include/llvm/IR/DerivedTypes.h', 'llvm/lib/IR/Type.cpp',
    'llvm/include/llvm/IR/Verifier.h', 'llvm/include/llvm/IRReader/IRReader.h',
    'llvm/lib/IRReader/IRReader.cpp',
    'clang/include/clang/Basic/TargetInfo.h', 'clang/lib/Basic/Targets.cpp',
    'clang/lib/Basic/Targets/SPIR.h', 'clang/lib/Basic/Targets/WebAssembly.h',
    'clang/lib/AST/ASTContext.cpp', 'clang/lib/AST/RecordLayoutBuilder.cpp',
    'clang/lib/AST/Type.cpp', 'clang/lib/Sema/SemaType.cpp',
    'clang/lib/CodeGen/CodeGenTypes.cpp', 'clang/lib/CodeGen/CGRecordLayoutBuilder.cpp',
    'clang/lib/CodeGen/CodeGenModule.cpp', 'clang/lib/CodeGen/Targets/SPIR.cpp',
    'clang/lib/CodeGen/CGCXXABI.h', 'clang/lib/CodeGen/ItaniumCXXABI.cpp',
    'clang/lib/Driver/ToolChains/Clang.cpp', 'clang/lib/Driver/Driver.cpp',
    'clang/www/c_status.html', 'clang/www/cxx_status.html',
    'libcxx/docs/Status/Cxx23.rst', 'libcxx/docs/Status/Cxx23Papers.csv',
    'libcxx/docs/Status/Cxx23Issues.csv', 'libcxx/docs/DesignDocs/ABIVersioning.rst',
    'libc/docs/platform_support.md', 'libc/docs/arch_support.md',
    'libc/docs/porting.md', 'compiler-rt/lib/builtins/CMakeLists.txt',
    'libcxxabi/src/CMakeLists.txt', 'libunwind/src/CMakeLists.txt',
    'libcxxabi/src/cxa_personality.cpp', 'libcxxabi/src/cxa_exception.cpp', 'libcxxabi/src/cxa_handlers.cpp',
    'libcxx/include/__config_site.in', 'libcxx/CMakeLists.txt', 'libcxxabi/CMakeLists.txt',
    'llvm/include/llvm/IR/Comdat.h', 'llvm/include/llvm/IR/CallingConv.h',
    'llvm/include/llvm/IR/LLVMContext.h', 'llvm/include/llvm/IR/Instructions.h',
    'llvm/lib/IR/Verifier.cpp', 'llvm/lib/IR/Instructions.cpp',
    'llvm/lib/Linker/IRMover.cpp', 'llvm/lib/Linker/LinkModules.cpp',
    'llvm/lib/Transforms/IPO/FunctionImport.cpp',
    'llvm/lib/Transforms/Coroutines/CoroSplit.cpp',
    'llvm/lib/Transforms/Coroutines/CoroEarly.cpp',
    'llvm/lib/Transforms/Coroutines/CoroCleanup.cpp',
    'llvm/lib/Transforms/Coroutines/CoroFrame.cpp',
    'llvm/lib/Transforms/Coroutines/CoroConditionalWrapper.cpp',
    'llvm/include/llvm/Transforms/Coroutines/CoroShape.h',
    'llvm/include/llvm/Transforms/Coroutines/CoroInstr.h',
    'llvm/include/llvm/IR/Constants.h', 'llvm/lib/IR/Constants.cpp',
    'llvm/include/llvm/IR/Value.def', 'clang/lib/Sema/SemaCoroutine.cpp',
    'llvm/include/llvm/IR/ValueHandle.h','llvm/lib/IR/Value.cpp',
    'llvm/include/llvm/IR/PassInstrumentation.h',
    'clang/include/clang/Options/Options.td', 'clang/include/clang/Basic/LangOptions.def',
    'clang/lib/CodeGen/CGCoroutine.cpp', 'clang/lib/CodeGen/CGException.cpp',
    'clang/lib/CodeGen/CGAtomic.cpp', 'clang/lib/CodeGen/CGBuiltin.cpp',
    'libcxx/docs/DesignDocs/AtomicDesign.rst', 'libcxx/include/__atomic/atomic_flag.h',
    'clang/lib/Headers/stdatomic.h', 'libcxx/include/__configuration/abi.h',
    'libcxx/include/typeinfo', 'libcxx/include/__thread/support.h',
    'clang/lib/Headers/stddef.h', 'clang/lib/Headers/stdint.h',
    'llvm/lib/Analysis/ConstantFolding.cpp', 'llvm/lib/Transforms/Utils/SimplifyLibCalls.cpp',
    'llvm/lib/Transforms/InstCombine/InstCombineMulDivRem.cpp',
    'llvm/lib/Transforms/InstCombine/InstCombineCalls.cpp',
    'libc/src/fenv/fesetexceptflag.cpp', 'libc/include/llvm-libc-macros/fenv-macros.h',
    'compiler-rt/lib/builtins/powidf2.c', 'compiler-rt/lib/builtins/powitf2.c',
    *['clang/lib/Headers/__stddef_' + name + '.h' for name in
      ('header_macro','ptrdiff_t','size_t','wchar_t','null','nullptr_t','unreachable','max_align_t','offsetof')],
]


def canonical(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def command(argv):
    result = subprocess.run(argv, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f'{argv!r}: exit {result.returncode}\n{result.stderr}')
    return result.stdout


def tablegen(llvm, executable, name):
    with tempfile.TemporaryDirectory(prefix='smir-tablegen-') as scratch:
        output = Path(scratch) / 'records.json'
        dependencies = Path(scratch) / 'records.d'
        command([str(executable), '-I', str(llvm / 'llvm/include'), '--dump-json',
                 str(llvm / f'llvm/include/llvm/IR/{name}.td'), '-o', str(output),
                 '-d', str(dependencies)])
        records = json.loads(output.read_text())
        dep_text = dependencies.read_text().split(': ', 1)[1]
        records['!smir-dependencies'] = [str(Path(p).relative_to(llvm))
                                         for p in shlex.split(dep_text)]
        return records


def instructions(llvm):
    text = (llvm / 'llvm/include/llvm/IR/Instruction.def').read_text()
    parsed = re.findall(r'^HANDLE_(\w+)_INST\s*\(\s*(\d+),\s*(\w+)\s*,\s*(\w+)\s*\)', text, re.M)
    assignment = {}
    for rule, names in INSTRUCTION_RULES.items():
        for name in names.split():
            if name in assignment:
                raise ValueError(f'duplicate instruction policy: {name}')
            assignment[name] = rule
    names = {row[2] for row in parsed}
    if names != assignment.keys():
        raise ValueError(f'instruction policy drift: {names ^ assignment.keys()}')
    return [dict(opcode=int(opcode), name=name, category=category, llvm_class=cls,
                 rule=assignment[name], disposition=RULES[assignment[name]][0],
                 contract=RULES[assignment[name]][1], implemented=False)
            for category, opcode, name, cls in parsed]


def type_expression(reference, records):
    """Render overloaded signatures without leaking anonymous TableGen IDs."""
    name = reference['def']
    record = records[name]
    if not record.get('!anonymous'):
        return name
    parts = []
    for key in sorted(record):
        if key.startswith('!') or key in ('IITs', 'IIT_Vecs', 'Sig'):
            continue
        value = record[key]
        if isinstance(value, dict) and 'def' in value:
            value = value['def']
        parts.append(f'{key}={value}')
    classes = [c for c in record['!superclasses'] if c.startswith('LLVM')]
    return (classes[-1] if classes else 'type') + '(' + ','.join(parts) + ')'


def types(llvm):
    source = (llvm / 'llvm/include/llvm/IR/Type.h').read_text()
    body = source.split('enum TypeID {', 1)[1].split('};', 1)[0]
    names = re.findall(r'^\s*(\w+TyID)\b', body, re.M)
    rules = {
        'HalfTyID': 'fp', 'BFloatTyID': 'fp',
        'FloatTyID': 'fp', 'DoubleTyID': 'fp',
        'FP128TyID': 'fp', 'X86_FP80TyID': 'E-FOREIGN-FP-TYPE',
        'PPC_FP128TyID': 'E-FOREIGN-FP-TYPE', 'X86_AMXTyID': 'E-TARGET-TYPE',
        'VoidTyID': 'zero-logical-results', 'LabelTyID': 'block-reference-only',
        'MetadataTyID': 'non-runtime-metadata-only',
        'TokenTyID': 'legalized_opaque_handle', 'IntegerTyID': 'bitvector-width-1..8388608',
        'ByteTyID': 'raw_shadow', 'FunctionTyID': 'logical_signature',
        'PointerTyID': 'guest_pointer', 'StructTyID': 'explicit-fields-and-layout',
        'ArrayTyID': 'explicit-element-and-count', 'FixedVectorTyID': 'fixed-lane-wise-values',
        'ScalableVectorTyID': 'E-SCALABLE-TYPE', 'TypedPointerTyID': 'E-TARGET-TYPE',
        'TargetExtTyID': 'compiler-private-opaque-carrier-or-diagnostic',
    }
    if set(names) != rules.keys():
        raise ValueError(f'type policy drift: {set(names) ^ rules.keys()}')
    rows = [dict(name=name, rule=rules[name], implemented=False,
                 disposition='diagnostic' if rules[name].startswith('E-') else 'portable')
            for name in names]
    row=next(item for item in rows if item['name']=='TargetExtTyID')
    row.update(parameterless_names=list(PARAMETERLESS_CARRIERS),
               constraints='Exact original compiler/source context required; no ordinary memory/sizing/arithmetic/casts. Existing exception/journal/stack_mark/fenv mappings unchanged: fenv freeze default, branded handles only proven concrete-valid copy else E-OPAQUE-FREEZE. New code_binding/source_scope are SSA-only compiler carriers, not new execution kinds; freeze and public source ABI/foreign escape always reject. code_binding names actual checked CodePtr<Fn>; source_scope erases to original source ScopeSlot, not DataPtr/Int authority. Call/phi/select/copy retain actual Fn or scope lineage; binding aggregate groups require the exact single transaction contract.',
               fallback_diagnostic='E-TARGET-TYPE')
    return rows


def intrinsic_rows(records):
    rows = []
    for name in sorted(records['!instanceof']['Intrinsic']):
        record = records[name]
        disposition, diagnostic, detail = intrinsic_rule(name, record['TargetPrefix'])
        llvm_name = record['LLVMName'] or 'llvm.' + name.removeprefix('int_').replace('_', '.')
        rows.append({
            'record': name, 'llvm_name': llvm_name, 'target': record['TargetPrefix'],
            'returns': ';'.join(type_expression(t, records) for t in record['RetTypes']) or 'void',
            'parameters': ';'.join(type_expression(t, records) for t in record['ParamTypes']),
            'disposition': disposition, 'diagnostic': diagnostic, 'contract': detail,
            'location': ';'.join(record['!locs']), 'implemented': 'false',
        })
    return rows


def attribute_rows(records):
    rows = []
    for name in sorted(records['!instanceof']['Attr']):
        record = records[name]
        disposition, diagnostic, detail = attribute_rule(record['AttrString'])
        rows.append(dict(record=name, name=record['AttrString'],
                         classes=record['!superclasses'],
                         properties=[p['def'] for p in record['Properties']],
                         disposition=disposition, diagnostic=diagnostic,
                         contract=detail, implemented=False))
    return rows


class StatusTables(HTMLParser):
    """Read status cells from the upstream HTML, retaining text and paper links."""
    def __init__(self):
        super().__init__()
        self.rows = []
        self.row = None
        self.cell = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'tr':
            self.row = []
        if tag == 'td' and self.row is not None:
            self.cell = {'text': '', 'class': attrs.get('class', ''), 'links': []}
        if tag == 'a' and self.cell is not None and 'href' in attrs:
            self.cell['links'].append(attrs['href'])

    def handle_data(self, data):
        if self.cell is not None:
            self.cell['text'] += data + ' '

    def handle_endtag(self, tag):
        if tag == 'td' and self.cell is not None:
            self.cell['text'] = ' '.join(self.cell['text'].split())
            self.row.append(self.cell)
            self.cell = None
        if tag == 'tr' and self.row is not None:
            if self.row:
                self.rows.append(self.row)
            self.row = None


def language_gaps(llvm, path, section):
    source = (llvm / path).read_text()
    start = source.index(f'<h2 id="{section}">')
    end = source.find('<h2', start + 4)
    parser = StatusTables()
    parser.feed(source[start:end if end >= 0 else len(source)])
    gaps = []
    for row in parser.rows:
        statuses = [cell for cell in row if cell['class'] in ('none', 'partial', 'unknown')]
        if statuses:
            gaps.append({'cells': row, 'source': path,
                         'classification': 'upstream-documented-gap-not-smir-port'})
    if not parser.rows:
        raise ValueError(f'no status rows parsed: {path}')
    return {'status_rows': len(parser.rows), 'gaps': gaps}


def library_gaps(llvm):
    result = []
    for name in ('Cxx23Papers.csv', 'Cxx23Issues.csv'):
        path = 'libcxx/docs/Status/' + name
        for row in csv.DictReader(io.StringIO((llvm / path).read_text())):
            if not any(value for value in row.values()):
                continue
            status = row.get('Status', '').strip()
            if status not in ('|Complete|', '|Nothing To Do|'):
                result.append({'source': path, 'upstream_row': row,
                               'classification': 'upstream-status-not-complete; not an executable test'})
    return result


def generate(llvm, tblgen):
    actual = command(['git', '-C', str(llvm), 'rev-parse', 'HEAD']).strip()
    if actual != PIN:
        raise ValueError(f'pin mismatch: expected {PIN}, got {actual}')
    intrinsics = tablegen(llvm, tblgen, 'Intrinsics')
    attrs = tablegen(llvm, tblgen, 'Attributes')
    inst = instructions(llvm)
    intrinsic = intrinsic_rows(intrinsics)
    constrained = {row['record'].removeprefix('int_experimental_constrained_')
                   for row in intrinsic if row['record'].startswith('int_experimental_constrained_')}
    from bindings import CONSTRAINED
    if constrained != CONSTRAINED:
        raise ValueError('constrained intrinsic binding inventory changed')
    attributes = attribute_rows(attrs)
    # TableGen dependency output covers multiclasses, defm and transitive includes;
    # source regexes alone cannot enumerate the expanded intrinsic universe.
    paths = sorted(set(SOURCES) | set(intrinsics['!smir-dependencies'])
                   | set(attrs['!smir-dependencies']))
    # HEAD alone does not prove worktree source bytes match the pin.
    queries = ''.join(f'{PIN}:{p}\n' for p in paths)
    objects = subprocess.run(['git', '-C', str(llvm), 'cat-file', '--batch-check'],
                             input=queries, text=True, capture_output=True, check=True)
    lines = objects.stdout.splitlines()
    if len(lines) != len(paths):
        raise ValueError('source object count mismatch')
    for path, identity in zip(paths, lines):
        data = (llvm / path).read_bytes()
        expected = identity.split()[0]
        actual_blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if actual_blob != expected:
            raise ValueError(f'source differs from pinned blob: {path}')
    manifest = [dict(path=p, sha256=hashlib.sha256((llvm / p).read_bytes()).hexdigest(),
                     bytes=(llvm / p).stat().st_size,
                     url=f'https://github.com/llvm/llvm-project/blob/{PIN}/{p}') for p in paths]
    target = dict(revision='llvm-contract-draft-v1', implemented=False,
                  llvm_revision=PIN, triple=TRIPLE, datalayout=DATALAYOUT,
                  personality=['linux', 'darwin', 'windows'],
                  carrier=['elf', 'macho', 'pe'],
                  pointer_bits=64, pointer_index_bits=64, byte_bits=8,
                  endian='little', stack_alignment_bytes=16,
                  address_spaces=list(ADDRESS_SPACES),
                  default_data_address_space=DEFAULT_DATA_ADDRESS_SPACE,
                  program_address_space=PROGRAM_ADDRESS_SPACE,
                  program_pointer=dict(PROGRAM_POINTER_LAYOUT),
                  hosted_languages=['C23', 'C++23'],
                  libcxx_abi_version=1, wint_t_bits=32, wint_t_signed=False, weof=0xffffffff,
                  implementation_missing=['SMIR frontend and emitter', 'hosted sysroot/runtime ports',
                                          'native JIT/foreign EH/host qualification'])
    gaps = {'llvm_revision': PIN, 'claim': 'upstream documentation snapshot, not complete standards certification',
            'c23': language_gaps(llvm, 'clang/www/c_status.html', 'c2x'),
            'cxx23': language_gaps(llvm, 'clang/www/cxx_status.html', 'cxx23'),
            'libcxx_cxx23': library_gaps(llvm),
            'llvm_libc_host_support': {
                'source': 'libc/docs/platform_support.md',
                'summary': 'Development focuses on Linux; macOS/Windows have partial support and are not continuously tested in this source snapshot.'}}
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(intrinsic[0]), delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(intrinsic)
    summary = dict(llvm_revision=PIN, type_count=len(types(llvm)), instruction_count=len(inst),
                   intrinsic_count=len(intrinsic), target_independent_intrinsics=sum(not r['target'] for r in intrinsic),
                   attribute_count=len(attributes),
                   intrinsic_dispositions=dict(Counter(r['disposition'] for r in intrinsic)),
                   instruction_dispositions=dict(Counter(r['disposition'] for r in inst)),
                   attribute_dispositions=dict(Counter(r['disposition'] for r in attributes)),
                   implemented_lowerings=0)
    return {
        'candidate-bindings.json': canonical(core_bindings()),
        'constant-matrix.json': canonical(constant_inventory(llvm)),
        'frontend-contract.json': canonical(configuration()),
        'lowering-contracts.json': canonical(dict(revision='llvm-lowering-v2', recipes=RECIPES, intrinsics=INTRINSIC_DETAILS)),
        'target.json': canonical(target), 'type-matrix.json': canonical(types(llvm)),
        'instruction-matrix.json': canonical(inst),
        'intrinsic-matrix.tsv': stream.getvalue(), 'attribute-matrix.json': canonical(attributes),
        'upstream-gaps.json': canonical(gaps), 'summary.json': canonical(summary),
        'sources.json': canonical(dict(issuer='LLVM Project', revision=PIN,
                                      retrieved='2026-11-05', license='Apache-2.0 WITH LLVM-exception',
                                      archive_owner='INTEGRATOR', files=manifest)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm', type=Path, required=True)
    parser.add_argument('--tblgen', type=Path)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    tblgen = args.tblgen or args.llvm / 'build/bin/llvm-tblgen'
    outputs = generate(args.llvm, tblgen)
    for name, content in outputs.items():
        path = PACKAGE / name
        if args.write:
            path.write_text(content)
        elif not path.is_file() or path.read_text() != content:
            raise SystemExit(f'stale or absent generated contract: {path}')
    print(canonical(json.loads(outputs['summary.json'])), end='')


if __name__ == '__main__':
    main()
