"""Exact LLVM051 contracts: pure actual-graph tests and separate pinned tools."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_contract import BIN


def witness(options=()):
    process=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('life_marker_witness.py')),*map(str,options)],
                           capture_output=True,text=True)
    if process.returncode:raise AssertionError(process.stderr)
    return json.loads(process.stdout)


class MarkerGrammarWitnesses(unittest.TestCase):
    def test_actual_source_graph_facts_grammar_rejections_and_stable_builder_captures(self):
        report=witness()['pure']
        self.assertEqual(report['positive_notes'],8)
        self.assertEqual(len(report['rejections']),10)
        self.assertTrue(report['two_view_same_value'])
        self.assertEqual(report['external_destroy_formals'],2)
        self.assertEqual([x['source_state'] for x in report['builder_stability']],['undef','poison'])


class MarkerPinnedSurvivalWitnesses(unittest.TestCase):
    def test_actual_pinned_o0_o2_full_thin_preserve_exact_notes_and_operand_pairs(self):
        with tempfile.TemporaryDirectory(prefix='smir-life-marker-') as output:
            report=witness(['--clang',BIN/'clang++','--output',output])
        self.assertEqual([r['mode'] for r in report['live']],['O0','O2','full','thin'])
        self.assertEqual([r['split'] for r in report['live']],[True,True,True,False])
        self.assertTrue(all(r['actual_fact_blobs'] and r['exact_source_operand_pairs'] for r in report['live']))
