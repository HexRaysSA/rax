"""Identified LLVM050/R042 draft reference template, not production admission."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

import bindings


def actual_factory():
    # Published catalog template; no source authority is inferred from a row.
    _, records=bindings.catalog()
    return copy.deepcopy(records['journal_begin'])


class JournalTemplateTests(unittest.TestCase):
    def test_actual_admitted_source_graph_order_not_formal_numeric_id(self):
        process=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('journal_template_witness.py'))],
                               capture_output=True,text=True)
        self.assertEqual(process.returncode,0,process.stderr)
        result=json.loads(process.stdout)
        self.assertEqual([r['fixed_arity'] for r in result['cases']],[1,3])

    def test_real_zero_formals_and_fixed_typed_nonempty_formals(self):
        factory=actual_factory()
        for captures in ([],[dict(kind='int',bits=64),dict(kind='data_ptr',space='guest_data')]):
            result=bindings.instantiate(factory,[],contract='construction',journal_captures=captures)
            self.assertFalse(result['variadic'])
            self.assertEqual(result['params'],[dict(builtin='data_ptr'),*captures])
            self.assertEqual(result['param_noundef'],[False]*(1+len(captures)))
        with self.assertRaisesRegex(ValueError,'LLVM_JOURNAL_CAPTURE_METADATA'):
            bindings.instantiate(factory,[],contract='construction')

    def test_no_result_duplicate_wrong_namespace_or_unsolicited_template(self):
        factory=actual_factory()
        mutations=[lambda r:r['params'].append(copy.deepcopy(r['params'][-1])),
                   lambda r:r['results'].append(dict(type='journal_captures',noundef=False)),
                   lambda r:r['abi_namespace'].update(construction='nominal')]
        for mutate in mutations:
            record=copy.deepcopy(factory);mutate(record)
            with self.assertRaisesRegex(ValueError,'LLVM_JOURNAL_TEMPLATE'):
                bindings.instantiate(record,[],contract='construction',journal_captures=[])
        _,records=bindings.catalog()
        with self.assertRaisesRegex(ValueError,'LLVM_JOURNAL_UNUSED_CAPTURES'):
            bindings.instantiate(records['journal_claim_destroy'],[],journal_captures=[])
