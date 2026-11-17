"""Actual pinned Clang source-cell observations and independent path fixtures."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import source_cell_witness as W


class SourceCells(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oracle = Path(os.environ.get('SMIR_SOURCE_CELL_ORACLE',
            '/tmp/rax-portable-smir-01/LLVM/SOURCE-CELL-build-r3/source-cell-oracle'))
        cls.source = W.FIXTURES / 'cells.cpp'
        cls.queries = json.loads((W.FIXTURES / 'queries.json').read_text())
        cls.expected = json.loads((W.FIXTURES / 'expected.json').read_text())
        cls.paths = [Path(__file__), Path(W.__file__), Path(W.__file__).with_suffix('.cpp'), W.SCHEMA,
                     cls.oracle, cls.oracle.parent / 'build-receipt.json']
        cls.paths += [p for p in W.FIXTURES.rglob('*') if p.is_file()]
        cls.hashes = {p: W.digest(p) for p in cls.paths}
        cls.witnesses = [W.compile_witness(cls.oracle, cls.source, t, cls.queries) for t in
                         ['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu']]

    @classmethod
    def tearDownClass(cls):
        drift = [str(p) for p, h in cls.hashes.items() if W.digest(p) != h]
        if drift:
            raise AssertionError('Oracle/source/schema drift: ' + repr(drift))

    def test_actual_ast_layout_and_authored_relations(self):
        self.assertEqual(len(self.queries), 31)
        for witness in self.witnesses:
            self.assertEqual(len(witness['raw']['records']), 18)
            self.assertIn(W.PIN, witness['raw']['clang_version'])
            results = {q['selector']['label']: q['result'] for q in witness['queries']}
            for row in self.expected['comparisons']:
                with self.subTest(target=witness['context']['target'], row=row):
                    self.assertEqual(W.compare(results[row['left']], results[row['right']]),
                        dict(relation=row['relation'], same_coverage_view=row['same_coverage_view']))
            for left, right in self.expected['equal_physical_offsets']:
                self.assertEqual(results[left]['offset_min_bits'], results[right]['offset_min_bits'])
                self.assertNotEqual(results[left]['canonical_pattern'], results[right]['canonical_pattern'])
            for label in self.expected['unavailable']:
                self.assertEqual(results[label]['status'], 'unavailable')
                self.assertNotIn('canonical_pattern', results[label])
                self.assertNotIn('offset_constant_bits', results[label])
            self.assertFalse(witness['runtime_authority']); self.assertFalse(witness['source_fact_authority'])

    def test_symbolic_arrays_and_nearest_class_owner(self):
        for witness in self.witnesses:
            result = {q['selector']['label']: q['result'] for q in witness['queries']}
            huge = result['huge_all']
            self.assertEqual(len(huge['axes']), 1)
            self.assertEqual(huge['axes'][0]['count'], 1000000000)
            self.assertEqual(huge['offset_coefficients_bits'], [32])
            self.assertEqual(huge['offset_max_bits'], 31999999968)
            self.assertEqual(huge['width_bits'], 32)
            self.assertEqual(len(result['grid_all']['axes']), 2)
            self.assertEqual(result['diamond_nv_unknown'], dict(status='unavailable',
                code='CELL_NV_MOST_DERIVED_UNAVAILABLE', step_index=1))
            self.assertEqual(result['member_nv_reset']['status'], 'resolved')
            self.assertEqual(result['member_nv_reset']['leaf_view'], 'nonvirtual')
            self.assertEqual(result['unknown_prefix_not_repaired'], dict(status='unavailable',
                code='CELL_NV_MOST_DERIVED_UNAVAILABLE', step_index=0))

    def test_sticky_unknown_continues_known_path_rejections(self):
        model = W.Evaluator(self.witnesses[0]['raw'], self.witnesses[0]['context']['id'])
        query = copy.deepcopy(next(q for q in self.queries if q['label'] == 'diamond_nv_unknown'))
        query['steps'].append(dict(kind='member', declaration_index=99))
        with self.assertRaisesRegex(W.CellError, '^CELL_DECLARATION_INDEX$'):
            model.select(query)
        with self.assertRaisesRegex(W.CellError, '^CELL_RELATION_UNAVAILABLE$'):
            W.compare(dict(status='unavailable'), dict(status='resolved'))

    def test_exact_negative_path_matrix(self):
        model = W.Evaluator(self.witnesses[0]['raw'], self.witnesses[0]['context']['id'])
        rows = [
            ('D', [dict(kind='base', declaration_index=0, virtual=True)], 'CELL_VIRTUAL_FLAG'),
            ('D', [dict(kind='base', declaration_index=9, virtual=False)], 'CELL_DECLARATION_INDEX'),
            ('D', [dict(kind='member', declaration_index=0), dict(kind='member', declaration_index=0)], 'CELL_STEP_TYPE'),
            ('Huge', [dict(kind='member', declaration_index=0), dict(kind='element', selection=dict(first=1000000000, count=1))], 'CELL_ARRAY_BOUNDS'),
            ('Huge', [dict(kind='member', declaration_index=0), dict(kind='element', selection=dict(first=0, count=True))], 'CELL_INTEGER'),
            ('Huge', [dict(kind='member', declaration_index=0), dict(kind='element', selection=dict(first=0, count=0))], 'CELL_ARRAY_BOUNDS'),
            ('Bits', [dict(kind='member', declaration_index=0)], 'CELL_BITFIELD_SCOPE'),
            ('Bits', [dict(kind='member', declaration_index=1)], 'CELL_BITFIELD_SCOPE'),
        ]
        for root, steps, code in rows:
            with self.subTest(code=code, steps=steps), self.assertRaisesRegex(W.CellError, '^' + code + '$'):
                model.select(dict(label='negative', root=root, view='complete', steps=steps))

    def test_schema_and_raw_source_graph_rejections(self):
        schema = json.loads(W.SCHEMA.read_text())
        bad = copy.deepcopy(self.witnesses[0]); bad['runtime_authority'] = True
        with self.assertRaisesRegex(W.CellError, '^CELL_SCHEMA$'): W.validate_schema(schema, bad)
        bad = copy.deepcopy(self.witnesses[0]['raw']); bad['records'].append(copy.deepcopy(bad['records'][0]))
        with self.assertRaisesRegex(W.CellError, '^CELL_DUPLICATE$'): W.Evaluator(bad, self.witnesses[0]['context']['id'])
        bad = copy.deepcopy(self.witnesses[0]['raw']); bad['records'][0]['id'] = 'invented'
        with self.assertRaisesRegex(W.CellError, '^CELL_DECLARATION_ID$'): W.Evaluator(bad, self.witnesses[0]['context']['id'])
        bad = copy.deepcopy(self.witnesses[0]['raw'])
        next(r for r in bad['records'] if r['name'] == 'Nested')['fields'][0]['type']['record'] = 'missing'
        with self.assertRaisesRegex(W.CellError, '^CELL_REFERENCE$'): W.Evaluator(bad, self.witnesses[0]['context']['id'])

    def test_actual_cli_normal_optimized_determinism(self):
        with tempfile.TemporaryDirectory(prefix='llvm-source-cells-') as directory:
            outputs = []
            for target in ['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu']:
                pair = []
                for opt in [False, True]:
                    output = Path(directory) / (target + str(opt) + '.json')
                    command = [sys.executable, '-B'] + (['-O'] if opt else []) + [str(Path(W.__file__)),
                        'run', '--oracle', str(self.oracle), '--source', str(self.source), '--target', target,
                        '--queries', str(W.FIXTURES / 'queries.json'), '--output', str(output)]
                    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONOPTIMIZE='1' if opt else '0')
                    run = subprocess.run(command, capture_output=True, text=True, env=env)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(json.loads(run.stdout)['interpreter_optimization'], int(opt))
                    pair.append(output.read_bytes())
                self.assertEqual(pair[0], pair[1]); outputs.append(json.loads(pair[0]))
            self.assertNotEqual(outputs[0]['context']['id'], outputs[1]['context']['id'])
            self.assertEqual(W.compare(outputs[0]['queries'][0]['result'], outputs[1]['queries'][0]['result'])['relation'], 'disjoint')

    def test_real_compiler_rejection_and_exact_build_identity(self):
        with tempfile.TemporaryDirectory(prefix='llvm-source-cells-negative-') as directory:
            directory = Path(directory)
            source = directory / 'invalid.cpp'; source.write_text('template<class T> struct Dependent { T value; };\n')
            with self.assertRaisesRegex(W.CellError, '^CELL_ORACLE_SCOPE$'):
                W.compile_witness(self.oracle, source, 'x86_64-unknown-linux-gnu', [])
            source.write_text('struct Broken { int value }\n')
            with self.assertRaisesRegex(W.CellError, '^CELL_COMPILER_REJECTED$'):
                W.compile_witness(self.oracle, source, 'x86_64-unknown-linux-gnu', [])
            binary = directory / 'source-cell-oracle'; shutil.copy2(self.oracle, binary)
            receipt = json.loads((self.oracle.parent / 'build-receipt.json').read_text()); receipt['binary_sha256'] = '0' * 64
            (directory / 'build-receipt.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(W.CellError, '^CELL_BUILD_IDENTITY$'):
                W.compile_witness(binary, self.source, 'x86_64-unknown-linux-gnu', self.queries)


if __name__ == '__main__':
    unittest.main()
