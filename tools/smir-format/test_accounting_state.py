"""A withdrawn candidate cannot bind live sources or pass the compiler gate."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from check_spec import inactive_candidate_blockers

ROOT = Path(__file__).resolve().parents[2]


class CandidateAccountingState(unittest.TestCase):
    def test_withdrawn_state_is_incomplete_without_reusing_history(self):
        manifest = {'candidate_state': 'WITHDRAWN_HISTORICAL_DIGEST',
                    'current_candidate_sha256': None, 'candidate_sha256': '01' * 32,
                    'components': [{'artifacts': [{'path': 'historical-missing-file', 'sha256': '02' * 32}]}]}
        original = copy.deepcopy(manifest)
        blockers = inactive_candidate_blockers(manifest)
        self.assertTrue(blockers)
        self.assertIn('no active compiler candidate', blockers[0])
        self.assertEqual(manifest, original)

    def test_withdrawn_state_cannot_claim_an_active_digest(self):
        for current in ('03' * 32, '', False):
            with self.subTest(current=current):
                with self.assertRaisesRegex(ValueError, 'withdrawn candidate claims a current digest'):
                    inactive_candidate_blockers({'candidate_state': 'WITHDRAWN_HISTORICAL_DIGEST',
                                                 'current_candidate_sha256': current})
        with self.assertRaises(ValueError):
            inactive_candidate_blockers({'candidate_state': 'WITHDRAWN_HISTORICAL_DIGEST'})

    def test_ordinary_candidates_keep_strict_accounting_path(self):
        for state in (None, 'DRAFT', 'ACTIVE', 'WITHDRAWN_HISTORICAL_DIGEST_typo'):
            self.assertIsNone(inactive_candidate_blockers({'candidate_state': state}))

    def test_current_accounting_reports_its_actual_gate(self):
        manifest = json.loads((ROOT / 'docs/specifications/smir/portable/compiler-contract.json').read_text())
        status = json.loads((ROOT / 'docs/specifications/smir/portable/status.json').read_text())
        before = (ROOT / 'docs/specifications/smir/portable/compiler-contract.json').read_bytes()
        command = [sys.executable, '-B', str(ROOT / 'tools/smir-format/check_spec.py')]
        run = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        expected = 'PASS' if status['compiler_freeze_passed'] else 'INCOMPLETE'
        self.assertIn('Compiler contract gate: ' + expected, run.stdout)
        run = subprocess.run([*command, '--require-compiler-freeze'], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0 if status['compiler_freeze_passed'] else 1, run.stdout + run.stderr)
        if manifest.get('candidate_state') == 'WITHDRAWN_HISTORICAL_DIGEST':
            self.assertIn('no active compiler candidate', run.stderr)
        self.assertEqual((ROOT / 'docs/specifications/smir/portable/compiler-contract.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
