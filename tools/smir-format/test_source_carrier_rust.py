"""Independent Rust source-carrier payload boundaries; no execution admission."""
from copy import deepcopy
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import codec
import source_carrier_rust as oracle

FIXTURES = oracle.ROOT / 'docs/specifications/smir/portable/conformance/runtime/source-carrier'


class RustSourceCarrier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        installed = shutil.which('rustc')
        if installed is None:
            raise RuntimeError('installed Rust compiler required; no skipped oracle')
        result = subprocess.run([installed, '--print', 'sysroot'], capture_output=True,
                                text=True, check=True)
        compiler = Path(result.stdout.strip()) / 'bin' / ('rustc.exe' if os.name == 'nt' else 'rustc')
        cls.temporary = tempfile.TemporaryDirectory(prefix='smir-rust-carrier-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.probe = oracle.build(cls.directory / 'build', compiler=compiler)
        cls.rows = json.loads((FIXTURES / 'grammar-cases.json').read_text())
        cls.schema = json.loads(oracle.GRAMMAR.read_text())
        cls.generic = codec.RecordCodec(cls.schema['records'])

    def run_probe(self, kind, raw, accepted=True):
        path = self.directory / 'payload.bin'
        path.write_bytes(raw)
        result = subprocess.run([str(self.probe), '--record', kind, str(path)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0 if accepted else 2,
                         (kind, result.stdout, result.stderr))
        return json.loads(result.stdout) if accepted else result.stdout.strip()

    def test_every_record_variant_and_nullable_profile(self):
        seen = set()
        for row in self.rows:
            self.assertEqual(self.run_probe(row['kind'], bytes.fromhex(row['hex'])), row['value'])
            seen.add((row['kind'], row['variant'], row['nullable_profile']))
        expected = {(name, tag, mode) for name, rule in self.schema['records'].items()
                    for tag in (rule['variants'] if 'discriminator' in rule else [''])
                    for mode in ['all_null', 'all_some']}
        self.assertEqual(seen, expected)

    def test_actual_v2_v3_payloads_and_legacy_reader_refusal(self):
        schemas = {name: json.loads((oracle.ROOT / 'docs/specifications/smir/portable/schema' /
                                    name / 'candidate.json').read_text())
                   for name in ('execution', 'runtime', 'abi')}
        old = codec.CandidateCodec(schemas)
        for name in ('published-sret', 'retained-pointer', 'scoped-phi', 'explicit-empty'):
            root = json.loads((FIXTURES / (name + '.wire.json')).read_text())
            self.assertEqual(self.run_probe('root3', (FIXTURES / (name + '.root3.bin')).read_bytes()), root)
            prior = old.decode((FIXTURES / (name + '.v2.smo')).read_bytes())
            payload = old.records.encode('execution_functions', prior.roots[3])
            self.assertEqual(self.run_probe('root3', payload), prior.roots[3])
            with self.assertRaises(codec.RecordError):
                old.decode((FIXTURES / (name + '.v3.smo')).read_bytes())

    def test_reserved_vector_optional_view_and_observer_fields(self):
        edits = [('sc_scope', '', lambda v: v.update(view={'some': 'bogus'})),
                 ('sc_phase_event', 'call', lambda v: v.update(return_adoptions=[0xffffffff])),
                 ('operation_v3', 'source_journal_observe', lambda v: v.update(scope_value=0xffffffff)),
                 ('operation_v3', 'source_journal_observe', lambda v: v.update(adoption=0xffffffff))]
        for kind, variant, edit in edits:
            row = next(r for r in self.rows if r['kind'] == kind and r['variant'] == variant
                       and r['nullable_profile'] == 'all_some')
            value = deepcopy(row['value'])
            edit(value)
            raw = self.generic.encode(kind, value)
            self.assertEqual(self.run_probe(kind, raw, False), 'WIRE-REFINEMENT-SCALAR')

    def test_revision_truncation_tail_and_count_before_elements(self):
        raw = (FIXTURES / 'empty.root3.bin').read_bytes()
        for count in range(len(raw)):
            self.run_probe('root3', raw[:count], False)
        for revision in (0, 1, 4, 0xffffffff):
            self.assertEqual(self.run_probe('root3', revision.to_bytes(4, 'little') + raw[4:], False),
                             'V3-REVISION')
        self.assertEqual(self.run_probe('root3', raw + b'\0', False), 'WIRE-TRAILING')
        bad = raw[:12] + (4097).to_bytes(4, 'little') + raw[16:]
        self.assertEqual(self.run_probe('root3', bad, False), 'WIRE-REFINEMENT-COUNT')
        self.assertEqual(self.run_probe('opt:u32', b'\2', False), 'WIRE-TAG')

    def test_builder_input_guards_and_real_compiler_receipt(self):
        receipt = json.loads((self.directory / 'build/build.json').read_text())
        self.assertEqual(receipt['exit'], 0)
        self.assertEqual(receipt['input_drift'], [])
        self.assertEqual(receipt['schema_sha256'], oracle.SCHEMA_SHA256)
        with self.assertRaises(ValueError):
            oracle.build(oracle.ROOT / 'forbidden-oracle-output', compiler=Path('rustc'))
        self.assertFalse((oracle.ROOT / 'forbidden-oracle-output').exists())
        compiler = next(Path(name) for name in receipt['input_hashes'] if Path(name).name in ('rustc', 'rustc.exe'))
        with self.assertRaises(ValueError):
            oracle.build(oracle.ROOT / 'forbidden-oracle-output', compiler=compiler)
        self.assertFalse((oracle.ROOT / 'forbidden-oracle-output').exists())
        with self.assertRaises(FileExistsError):
            oracle.build(self.directory / 'build', compiler=compiler)


if __name__ == '__main__':
    unittest.main(verbosity=2)
