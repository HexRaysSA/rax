"""Actual S074 evaluator compared against LLVM-owned integer/authority oracle."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class ConstantProgramCrossWitnesses(unittest.TestCase):
    def test_actual_weak_absence_provider_snapshot_is_part_of_authority(self):
        process=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('weak_reservation_witness.py'))],
                               capture_output=True,text=True)
        self.assertEqual(process.returncode,0,process.stderr)
        report=json.loads(process.stdout)
        self.assertEqual([case['kind'] for case in report['cases']],['data','function'])

    def test_six_integer_widths_three_ops_and_two_authority_roundtrips(self):
        process = subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('initializer_witness.py'))],
                                 capture_output=True,text=True)
        self.assertEqual(process.returncode,0,process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(len(report['cases']),27)
        self.assertEqual([r['origin_restored'] for r in report['cases'][18:20]], [False,True])
        self.assertEqual([r['expected_poison'] for r in report['cases'][20:]], [False,True,True,False,True,False,True])
