"""Actual type/ABI-checked ABI3 source witnesses for local INT032 predicates.

These component tests do not certify the final object verifier.
"""
from pathlib import Path
import sys
import json
import unittest
import hashlib
import subprocess
import importlib.util
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
# Distinct from the ABI owner's source_roles package in combined processes.
_MODEL_NAME = 'rax_runtime_source_role_model'
if _MODEL_NAME not in sys.modules:
    _spec = importlib.util.spec_from_file_location(_MODEL_NAME,HERE/'__init__.py')
    _module = importlib.util.module_from_spec(_spec)
    sys.modules[_MODEL_NAME] = _module
    _spec.loader.exec_module(_module)
_MODEL = sys.modules[_MODEL_NAME]
Budget, SourceRoleError, SourceRoles = _MODEL.Budget, _MODEL.SourceRoleError, _MODEL.SourceRoles
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec
# unittest discovery imports the runtime candidate package first. Its stable
# runtime_candidate alias is separate; reserve the absolute candidate namespace
# for the execution owner's actual RootContext, as other runtime join tests do.
for _name, _loaded in list(sys.modules.items()):
    _location = getattr(_loaded,'__file__',None)
    if (_name == 'candidate' or _name.startswith('candidate.')) and _location and \
            HERE.parent/'candidate' in Path(_location).parents:
        del sys.modules[_name]
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
from candidate.context import RootContext
from candidate.type_system import key, ref

SPEC = ROOT / 'docs/specifications/smir/portable'
CODEC = CandidateCodec({name: json.loads((SPEC/'schema'/name/'candidate.json').read_text())
                        for name in ('execution','runtime','abi')})


def checked_case(data):
    actual = RootContext(CODEC.decode(data).roots)
    actual.verify_abi()
    # Bounded source/type/ABI model checks; malformed source imports cannot
    # produce an execution proof after the now-wired source-role refinement.
    # Complete CLI outcomes are checked separately.

    def nominal(reference):
        actual.assert_snapshot()
        return actual.abi_entity('nominal',reference)

    def layout(reference):
        actual.assert_snapshot()
        source = actual.nominals[key(reference)]
        return actual.abi_graph.layout(ref(source['id']))

    def compatible(left,right):
        actual.assert_snapshot()
        return actual.abi_graph.compatible(ref(actual.nominals[key(left)]['id']),
            ref(actual.nominals[key(right)]['id']),ignore_top_cv=True)

    return actual, SourceRoles(nominal,layout,actual.execution,compatible=compatible)


class SourceRoleModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Immutable complete objects are produced by this role's durable source
        # generator; no other role directory is needed by consuming tests.
        cls.path = SPEC/'conformance/runtime/candidate/source-roles/atomic-flag.json'
        cls.document = json.loads(cls.path.read_text())

    def test_declared_source_generator_provenance_and_nonwriting_reproduction(self):
        provenance = self.document['provenance']
        generator = ROOT / provenance['generator']
        self.assertEqual(hashlib.sha256(generator.read_bytes()).hexdigest(),
                         provenance['generator_sha256'])
        for relative, expected in provenance['input_sha256'].items():
            self.assertFalse(Path(relative).is_absolute())
            self.assertNotIn('..', Path(relative).parts)
            self.assertEqual(hashlib.sha256((ROOT/relative).read_bytes()).hexdigest(),expected)
        size = 0
        for case in self.document['cases']:
            data = bytes.fromhex(case['encoded_hex'])
            size += len(data)
            self.assertEqual(hashlib.sha256(data).hexdigest(),case['sha256'])
        self.assertEqual(size,provenance['encoded_object_bytes'])
        command = [sys.executable,'-B'] + (['-O'] if sys.flags.optimize else [])
        result = subprocess.run(command+[str(generator),'--check'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_actual_nine_source_graphs_known_kind_before_missing_geometry(self):
        for case in self.document['cases']:
            with self.subTest(case=case['name']):
                actual, model = checked_case(bytes.fromhex(case['encoded_hex']))
                reference = actual.sections[6]['imports'][0]['abi']['some']
                if case['source_role_accept']:
                    model.atomic_flag(reference)
                else:
                    with self.assertRaises(SourceRoleError) as caught:
                        model.atomic_flag(reference)
                    self.assertEqual(caught.exception.code,'RT_HELPER_SOURCE_ROLE')
                    model.layout = None
                    with self.assertRaises(SourceRoleError) as caught:
                        model.atomic_flag(reference)
                    self.assertEqual(caught.exception.code,'RT_HELPER_SOURCE_ROLE')
                actual.assert_snapshot()

    def test_whole_reference_wrong_kinds_reject_and_actual_flag_controls_pass(self):
        with tempfile.TemporaryDirectory(prefix='smir-source-role-') as folder:
            for case in self.document['cases']:
                with self.subTest(case=case['name']):
                    path = Path(folder)/(case['name']+'.smo')
                    path.write_bytes(bytes.fromhex(case['encoded_hex']))
                    command = [sys.executable,'-B'] + (['-O'] if sys.flags.optimize else [])
                    result = subprocess.run(command+[str(ROOT/'tools/smir-format/codec.py'),
                        'verify-candidate-reference',str(path)],capture_output=True,text=True)
                    self.assertEqual(result.returncode,0 if case['source_role_accept'] else 2,
                                     result.stdout+result.stderr)
                    if case['source_role_accept']:
                        report = json.loads(result.stdout)
                        self.assertTrue(report['reference_verified'])
                        self.assertFalse(report['production_admitted'])
                    else:
                        self.assertIn('RT_HELPER_SOURCE_ROLE',result.stderr)
                        self.assertNotIn('WIRE-',result.stderr)
                        self.assertNotIn('EVIDENCE_UNAVAILABLE',result.stderr)

    def test_actual_flag_requires_geometry_and_resource(self):
        case = next(c for c in self.document['cases'] if c['source_role_accept'])
        actual, model = checked_case(bytes.fromhex(case['encoded_hex']))
        reference = actual.sections[6]['imports'][0]['abi']['some']
        model.layout = None
        with self.assertRaises(SourceRoleError) as caught:
            model.atomic_flag(reference)
        self.assertEqual(caught.exception.code,'RT_HELPER_SOURCE_EVIDENCE_UNAVAILABLE')
        model.budget = Budget(0)
        with self.assertRaises(SourceRoleError) as caught:
            model.atomic_flag(reference)
        self.assertEqual(caught.exception.code,'RT_SOURCE_RESOURCE')


if __name__ == '__main__':
    unittest.main()
