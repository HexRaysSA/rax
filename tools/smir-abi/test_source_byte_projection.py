"""Actual original owner/model checks, isolated from ABI candidate.py discovery."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CASES = (
    'test_archived_original_fixture_corpus',
    'test_actual_numeric_and_raw_storage_bindings_same_source',
    'test_original_static_projection_is_unbound',
    'test_actual_new2_abi_typed_unavailable_before_nominal_factory',
    'test_wrong_missing_duplicate_table_reject',
    'test_wrong_roots_and_changed_owner_reject',
)


def run_actual_witness(case, expected_optimize, expected_cache):
    """Only the child loads execution's candidate package; no parent cache edits."""
    if (sys.flags.optimize != expected_optimize or not sys.flags.dont_write_bytecode
            or sys.pycache_prefix != expected_cache):
        raise RuntimeError('SOURCE_BYTE_TEST_CHILD_MODE')
    sys.path[:0] = [str(ROOT / 'tools' / path) for path in (
        'smir-format/execution', 'smir-runtime-contract', 'smir-abi', 'smir-format')]
    import candidate
    from candidate.context import RootContext
    from record_layout.test_source_programs import q
    from source_bytes import verify_projection_descriptor
    from source_bytes.fixtures import projection_fixture as fixture
    from record_layout.materialization import _api

    class ActualProjection(unittest.TestCase):
        def test_archived_original_fixture_corpus(self):
            from source_bytes.fixtures import OUT
            roots = {int(k): v for k, v in json.loads(
                (OUT / 'unsigned-char-original-roots.json').read_text())['sections'].items()}
            owner = RootContext(roots)
            budget = _api().SourceQueryBudget(max_work=10**20, max_edges=10**20,
                                             max_copied_bytes=10**20, max_depth=128)
            descriptor = json.loads((OUT / 'unsigned-char-projection.json').read_text())
            result = verify_projection_descriptor(descriptor, owner, budget=budget)
            self.assertFalse(result.source_fact_authority)
            expected = {
                'duplicate': 'ABI_BYTE_DUPLICATE',
                'nonlocal-context': 'ABI_BYTE_LOCAL_CONTEXT',
                'omitted-table': 'ABI_BYTE_CATEGORY_TABLE',
                'wrong-category': 'ABI_BYTE_CATEGORY_TABLE',
                'wrong-root': 'ABI_BYTE_SOURCE_ROOTS',
            }
            for name, code in expected.items():
                with self.assertRaises(_api().SourceDataError) as error:
                    verify_projection_descriptor(json.loads(
                        (OUT / ('reject-' + name + '.json')).read_text()), owner,
                        budget=budget)
                self.assertEqual(error.exception.code, code)

        def test_actual_numeric_and_raw_storage_bindings_same_source(self):
            from nominal import NominalGraph
            from storage_binding import verify_binding
            owner, descriptor, budget = fixture()
            graph = NominalGraph(owner.sections[10], 'original', budget=budget)

            def binding(identifier, layout):
                return dict(id=identifier, nominal=q(5000), execution_layout=q(layout),
                            kind='object_bytes', view_offset_bits=0, view_width_bits=8,
                            required_alignment=1, access_bytes=1,
                            fragments=[dict(source_path=[], source_offset_bits=0,
                                            execution_offset_bits=0, width_bits=8,
                                            role='value')])

            self.assertTrue(verify_binding(binding(0, 5100), graph, owner.memory_layout))
            self.assertTrue(verify_binding(binding(1, 5101), graph, owner.memory_layout))
            from candidate.values import Value, from_raw, raw_bits
            from candidate.raw import Raw
            from candidate.machine import Machine
            from candidate.verify import verify
            from test_candidate import fixture as core_fixture
            # Actual Raw8 input from an issued memory allocation, not fabricated origin.
            machine = Machine(verify(*core_fixture()))
            pointer = machine.memory.allocate(8, 8)
            fragment = Raw.pointer(pointer).slice(0, 8)
            original = Value(q(5000), 'concrete', fragment)
            observed = from_raw(owner.types, q(5001), raw_bits(owner.types, original))
            returned = from_raw(owner.types, q(5000), raw_bits(owner.types, observed))
            self.assertEqual(returned.data.bits, fragment.bits)
            self.assertFalse(returned.data.origins)
            self.assertTrue(original.data.origins)

        def test_original_static_projection_is_unbound(self):
            owner, descriptor, budget = fixture()
            result = verify_projection_descriptor(descriptor, owner, budget=budget)
            self.assertIs(result.owner, owner)
            self.assertEqual(result.categories, ((5000, 'unsigned_char'),))
            self.assertFalse(result.source_fact_authority)
            self.assertFalse(result.semantic_admission)
            self.assertFalse(result.runtime_authority)
            self.assertTrue(result.original_category_evidence_required)

        def test_actual_new2_abi_typed_unavailable_before_nominal_factory(self):
            owner, descriptor, budget = fixture()
            hits = []

            def trace(frame, event, arg):
                if (event == 'call' and frame.f_code.co_filename.endswith('/nominal.py')
                        and frame.f_code.co_name == '__init__'):
                    hits.append(1)

            sys.setprofile(trace)
            try:
                with self.assertRaises(_api().SourceDataError) as error:
                    owner.verify_abi()
            finally:
                sys.setprofile(None)
            self.assertEqual(error.exception.kind, 'unavailable')
            self.assertEqual(error.exception.code, 'ABI_CC_SOURCE_BYTE_EVIDENCE_UNAVAILABLE')
            self.assertEqual(hits, [])
            self.assertFalse(owner.abi_checked)

        def test_wrong_missing_duplicate_table_reject(self):
            for case in ('wrong', 'missing', 'duplicate'):
                owner, descriptor, budget = fixture()
                if case == 'wrong':
                    descriptor['types'][0]['category'] = 'char'
                elif case == 'missing':
                    descriptor['types'] = []
                else:
                    descriptor['types'] *= 2
                with self.assertRaises(_api().SourceDataError):
                    verify_projection_descriptor(descriptor, owner, budget=budget)

        def test_wrong_roots_and_changed_owner_reject(self):
            owner, descriptor, budget = fixture()
            descriptor['context'] = 1
            with self.assertRaises(_api().SourceDataError) as error:
                verify_projection_descriptor(descriptor, owner, budget=budget)
            self.assertEqual(error.exception.code, 'ABI_BYTE_LOCAL_CONTEXT')
            owner, descriptor, budget = fixture()
            descriptor['abi_root'] = '0' * 64
            with self.assertRaises(_api().SourceDataError):
                verify_projection_descriptor(descriptor, owner, budget=budget)
            owner, descriptor, budget = fixture()
            owner.sections[10]['types'][-1]['bits'] = 7
            with self.assertRaises(Exception):
                verify_projection_descriptor(descriptor, owner, budget=budget)

    result = unittest.TextTestRunner(verbosity=2).run(ActualProjection(case))
    report = dict(format='smir-source-byte-child-witness-v1', case=case,
                  optimize=sys.flags.optimize, dont_write_bytecode=sys.flags.dont_write_bytecode,
                  pycache_prefix=sys.pycache_prefix, source=str(Path(__file__).resolve()),
                  candidate=str(Path(candidate.__file__).resolve()), tests=result.testsRun,
                  failures=len(result.failures), errors=len(result.errors), skips=len(result.skipped))
    print(json.dumps(report, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


class Projection(unittest.TestCase):
    def run_witness(self, case):
        with tempfile.TemporaryDirectory(prefix='source-byte-case-',
                                         dir=os.environ.get('SMIR_ABI_TMP')) as directory:
            # Root's process auditor supplies an absent shared prefix. Reusing
            # it retains that contract; -B prevents parent/child cache creation.
            inherited_cache = sys.pycache_prefix
            cache = (inherited_cache if inherited_cache and not Path(inherited_cache).exists()
                     else str(Path(directory) / 'pycache'))
            optimize = sys.flags.optimize
            command = [sys.executable, '-B']
            if optimize:
                command.append('-' + 'O' * optimize)
            command += [str(Path(__file__).resolve()), '--source-byte-case', case,
                        '--expected-optimize', str(optimize), '--expected-cache', cache]
            environment = dict(os.environ, PYTHONOPTIMIZE=str(optimize),
                               PYTHONPYCACHEPREFIX=cache, PYTHONDONTWRITEBYTECODE='1')
            child = subprocess.run(command, capture_output=True, text=True,
                                   env=environment, timeout=60)
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
            report = json.loads(child.stdout)
            self.assertEqual(report['format'], 'smir-source-byte-child-witness-v1')
            self.assertEqual(report['case'], case)
            self.assertEqual(report['optimize'], optimize)
            self.assertEqual(report['dont_write_bytecode'], 1)
            self.assertEqual(report['pycache_prefix'], cache)
            self.assertEqual(report['source'], str(Path(__file__).resolve()))
            self.assertEqual(report['candidate'], str(
                ROOT / 'tools/smir-format/execution/candidate/__init__.py'))
            self.assertEqual((report['tests'], report['failures'], report['errors'],
                              report['skips']), (1, 0, 0, 0))

    def test_archived_original_fixture_corpus(self):
        self.run_witness('test_archived_original_fixture_corpus')

    def test_actual_numeric_and_raw_storage_bindings_same_source(self):
        self.run_witness('test_actual_numeric_and_raw_storage_bindings_same_source')

    def test_original_static_projection_is_unbound(self):
        self.run_witness('test_original_static_projection_is_unbound')

    def test_actual_new2_abi_typed_unavailable_before_nominal_factory(self):
        self.run_witness('test_actual_new2_abi_typed_unavailable_before_nominal_factory')

    def test_wrong_missing_duplicate_table_reject(self):
        self.run_witness('test_wrong_missing_duplicate_table_reject')

    def test_wrong_roots_and_changed_owner_reject(self):
        self.run_witness('test_wrong_roots_and_changed_owner_reject')


if __name__ == '__main__':
    if sys.argv[1:2] == ['--source-byte-case']:
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument('--source-byte-case', choices=CASES, required=True)
        parser.add_argument('--expected-optimize', type=int, required=True)
        parser.add_argument('--expected-cache', required=True)
        arguments = parser.parse_args()
        sys.exit(run_actual_witness(arguments.source_byte_case,
                                  arguments.expected_optimize, arguments.expected_cache))
    unittest.main(verbosity=2)
