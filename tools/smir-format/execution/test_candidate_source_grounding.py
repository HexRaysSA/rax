"""Isolated original-owner grounding witnesses; legacy imports remain untouched."""
from pathlib import Path
import json
import os
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
DIRECTORY = ROOT / 'docs/specifications/smir/portable/conformance/execution/source-grounding'
CATALOG = json.loads((DIRECTORY / 'cases.json').read_bytes())


class SourceGroundingCases(unittest.TestCase):
    def run_original(self, name):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                           PYTHONOPTIMIZE='1' if sys.flags.optimize else '0')
        flags = ['-O'] if sys.flags.optimize else []
        run = subprocess.run([sys.executable, '-B', *flags,
                              str(DIRECTORY / 'run_case.py'), name],
                             capture_output=True, text=True, timeout=120,
                             env=environment)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        report = json.loads(run.stdout.splitlines()[-1])
        self.assertEqual((report['tests'], report['fail'], report['error'], report['skip']),
                         (1, 0, 0, 0))
        self.assertEqual(report['optimize'], 1 if sys.flags.optimize else 0)


def install_case(row):
    def test(self):
        self.run_original(row['id'])
    name = 'test_' + row['id'].replace('.', '_')
    test.__name__ = name
    setattr(SourceGroundingCases, name, test)


for row in CATALOG['cases']:
    install_case(row)


class SourceGroundingIsolation(unittest.TestCase):
    def test_public_module_import_preserves_legacy_codec_and_path(self):
        import importlib
        codec = importlib.import_module('codec')
        before = tuple(sys.path)
        checker_before = sys.modules.get('source_contracts.checker')
        importlib.import_module('candidate.source_grounding')
        self.assertEqual(tuple(sys.path), before)
        self.assertIs(sys.modules.get('codec'), codec)
        self.assertIs(sys.modules.get('source_contracts.checker'), checker_before)
        self.assertEqual(Path(codec.__file__).resolve(), ROOT / 'tools/smir-format/execution/codec.py')

    def test_unknown_private_child_case_has_no_fallback(self):
        run = subprocess.run([sys.executable, '-B', str(DIRECTORY / 'run_case.py'),
                              'retired_or_unknown_case'], capture_output=True, text=True,
                             env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), timeout=30)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(run.stdout, '')
        self.assertIn('unknown source-grounding conformance case', run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
