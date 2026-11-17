"""Build an independent, unverified source-carrier payload oracle in Rust."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[2]
GRAMMAR = ROOT / 'docs/specifications/smir/portable/schema/runtime/source_carrier_records.json'
SCHEMA_SHA256 = 'c64512a81e9716f1870e77c266d9de8aebf2b6ee7779f5dd44fb33a9aa8f9cb0'


def quote(text):
    return '"' + ''.join('\\' + c if c in ('"', '\\') else
                         '\\u{' + format(ord(c), 'x') + '}' if ord(c) < 32 else c
                         for c in text) + '"'


def generate(document):
    """Emit the exact ordered grammar and leaf constraints, without semantics."""
    def fields(rows):
        return 'vec![' + ','.join('(' + quote(n) + '.into(),' + quote(k) + '.into())'
                                 for n, k in rows) + ']'
    records = []
    for name, rule in document['records'].items():
        discriminator = ('Some(' + quote(rule['discriminator']) + '.into())'
                         if 'discriminator' in rule else 'None')
        variants = ','.join('(' + quote(t) + '.into(),' + fields(v) + ')'
                            for t, v in rule.get('variants', {}).items())
        records.append('(' + quote(name) + '.into(),Definition{discriminator:' +
                       discriminator + ',fields:' + fields(rule.get('fields', [])) +
                       ',variants:BTreeMap::from([' + variants + '])})')
    counts = [('(' + quote(path) + '.into(),CountBounds{minimum:' + str(rule['minimum']) +
               ',maximum:' + str(rule['maximum']) + '})')
              for path, rule in document['field_caps'].items()]
    scalars = []
    for path, rule in document['source_scalar_rules'].items():
        values = []
        if rule.get('type') == 'integer':
            values.append('ScalarRule::UnsignedRange{minimum:' + str(rule['minimum']) +
                          ',maximum:' + str(rule['maximum']) + '}')
        if 'const' in rule:
            value = rule['const']
            if type(value) is int:
                values.append('ScalarRule::UnsignedEquals(' + str(value) + ')')
            elif type(value) is bool:
                values.append('ScalarRule::BooleanEquals(' + str(value).lower() + ')')
            elif type(value) is str:
                values.append('ScalarRule::TextOneOf(vec![' + quote(value) + '.into()])')
            else:
                raise ValueError('unsupported scalar constant')
        if 'enum' in rule:
            if not all(type(v) is str for v in rule['enum']):
                raise ValueError('unsupported scalar enum')
            values.append('ScalarRule::TextOneOf(vec![' +
                          ','.join(quote(v) + '.into()' for v in rule['enum']) + '])')
        if values:
            scalars.append('(' + quote(path) + '.into(),vec![' + ','.join(values) + '])')
    return ('use std::collections::BTreeMap;\n'
            'fn carrier_schema()->framing::records::Schema{use framing::records::Definition;'
            'BTreeMap::from([' + ','.join(records) + '])}\n'
            'fn carrier_refinements()->framing::records::Refinements{'
            'use framing::records::{Refinements,CountBounds,ScalarRule};Refinements{'
            'counts:BTreeMap::from([' + ','.join(counts) + ']),'
            'scalars:BTreeMap::from([' + ','.join(scalars) + '])}}\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output, *, compiler):
    output = Path(output).resolve()
    compiler = Path(compiler)
    if not compiler.is_absolute() or not compiler.is_file():
        raise ValueError('absolute installed Rust compiler required')
    if output.is_relative_to(ROOT):
        raise ValueError('fresh external output directory required')
    size = GRAMMAR.stat().st_size
    if not 0 < size <= 1024 * 1024:
        raise ValueError('source-carrier schema bound')
    with GRAMMAR.open('rb') as stream:
        raw = stream.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('source-carrier schema identity')
    source = ROOT / 'tools/smir-format/source_carrier_rust_probe.rs'
    inputs = [Path(__file__).resolve(), GRAMMAR, source, compiler]
    inputs += sorted((ROOT / 'src/smir/portable').rglob('*.rs'))
    before = {str(p): digest(p) for p in inputs}
    output.mkdir(parents=True, exist_ok=False)
    schema = output / 'schema.rs'
    schema.write_text(generate(json.loads(raw)))
    binary = output / 'probe'
    command = [str(compiler), '--edition=2024', str(source), '-o', str(binary)]
    env = dict(os.environ, SMIR_SOURCE_CARRIER_SCHEMA=str(schema), TMPDIR=str(output))
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    version = subprocess.run([str(compiler), '--version', '--verbose'],
                             capture_output=True, text=True)
    drift = [str(p) for p in inputs if digest(p) != before[str(p)]]
    receipt = dict(command=command, exit=result.returncode,
                   stdout=result.stdout, stderr=result.stderr, input_hashes=before,
                   input_drift=drift, compiler_version=version.stdout,
                   schema_sha256=SCHEMA_SHA256, generated_schema_sha256=digest(schema),
                   binary_sha256=digest(binary) if binary.exists() else None,
                   scope='Ordered payload grammar/refinements/reencoding only; no module digest, '
                         'reference, semantic, source-context or execution admission.',
                   limits='Compiler sysroot, libraries and native file opens are not exhaustively attested.')
    (output / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if result.returncode or drift or version.returncode:
        raise RuntimeError('source-carrier Rust oracle build failed')
    return binary


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output, compiler=args.compiler))


if __name__ == '__main__':
    main()
