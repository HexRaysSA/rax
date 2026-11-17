"""LLVM slot elimination -> actual SEM SSA with registry-issued exception values.

External branch conditions are a finite path oracle, supplied at each terminator.
This validates typed identity/phi transport, not compiled C++ source execution.
"""
import json
import os
import subprocess
import sys
import unittest

from common import ROOT, SPEC
from candidate.machine import Machine
from candidate.type_system import ref
from candidate.values import Value
from candidate.verify import verify
from test_candidate import block, decl, fixture, operation


def transform_in_independent_process():
    # LLVM reference uses top-level module names also used by legacy SEM tools.
    # A process gives each owner its actual imports without alias substitution.
    script = '''import json,sys
from eh_slots import eliminate,execute
source=json.load(open(sys.argv[1]))
result=[]
for case in source['cases']:
 result.append({'name':case['name'],'ssa':eliminate(case['source']),
 'paths':[{'path':p,'expected':execute(case['source'],p,{'outer':'owner-A','inner':'owner-B'})}
          for p in case['paths']]})
print(json.dumps(result))
'''
    result = subprocess.run([sys.executable, '-c', script,
        str(SPEC / 'conformance/llvm/eh-slots.json')], cwd=ROOT / 'tools/smir-llvm-contract',
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def semantic_roots(document):
    roots = fixture()
    signature = roots[0]['types'][15]
    signature.update(params=[ref(10), ref(10), ref(0)], results=[ref(10)],
                     param_noundef=[True, True, True], result_noundef=[True])
    names = {'outer': 0, 'inner': 1}
    ids = {item['id']: index for index, item in enumerate(document['blocks'])}
    for item in document['blocks']:
        for phi in item['phis']:
            names[phi['result']] = len(names) + 1  # ID2 is branch oracle input.
    next_value = max([2, *names.values()]) + 1
    blocks, observations = [], {}
    for item in document['blocks']:
        phis = []
        for phi in item['phis']:
            incoming = {}
            for edge in phi['incoming']:
                assert edge['block'] not in incoming or incoming[edge['block']] == edge['value']
                incoming[edge['block']] = edge['value']
            phis.append({'result': decl(names[phi['result']], 10), 'incoming': [
                {'predecessor': ids[parent], 'value': names[value]} for parent, value in incoming.items()]})
        operations = []
        for node in item['ops']:
            assert node['op'] == 'observe'
            operations.append(operation('copy', [decl(next_value, 10)], [names[node['value']]]))
            observations[ids[item['id']], len(operations) - 1] = next_value
            next_value += 1
        targets = item['successors']
        if item['return'] is not None:
            term = {'op': 'return', 'values': [names[item['return']]]}
        elif len(set(targets)) == 1:
            term = {'op': 'jump', 'target': ids[targets[0]]}
        else:
            term = {'op': 'cbranch', 'condition': 2, 'true': ids[targets[0]], 'false': ids[targets[1]]}
        blocks.append(block(ids[item['id']], operations, term, phis))
    roots[1]['functions'][0].update(params=[decl(0, 10), decl(1, 10), decl(2, 0)],
        entry=ids[document['entry']], blocks=blocks)
    return roots, ids, observations


class CandidateExceptionSlotTests(unittest.TestCase):
    def test_independent_slot_paths_preserve_actual_issued_handles_and_phi_swaps(self):
        paths = 0
        for case in transform_in_independent_process():
            roots, ids, observations = semantic_roots(case['ssa'])
            blocks = {b['id']: b for b in roots[1]['functions'][0]['blocks']}
            for path_case in case['paths']:
                with self.subTest(case=case['name'], path=path_case['path']):
                    machine = Machine(verify(*roots))
                    outer = machine.handle(ref(10), {'nominal': ('self', 0)})
                    inner = machine.handle(ref(10), {'nominal': ('self', 1)})
                    identity = {'owner-A': outer.data.identity, 'owner-B': inner.data.identity}
                    machine.start(0, [outer, inner, Value(ref(0), 'concrete', 0)])
                    expected_blocks = [ids[name] for name in path_case['path']]
                    entered, seen = 0, []
                    for _ in range(1000):
                        frame = machine.stack[-1]
                        if frame.position == -1:
                            self.assertEqual(frame.block, expected_blocks[entered])
                            entered += 1
                        before = frame.block, frame.position
                        term = blocks[frame.block]['term']
                        if frame.position == len(blocks[frame.block]['ops']) and term['op'] == 'cbranch':
                            frame.values[2] = Value(ref(0), 'concrete', int(term['true'] == expected_blocks[entered]))
                        outcome = machine.run(fuel=1)
                        if before in observations:
                            seen.append(frame.values[observations[before]].data.identity)
                        if outcome['kind'] != 'resource':
                            break
                    self.assertEqual(outcome['kind'], 'return')
                    self.assertEqual(entered, len(expected_blocks))
                    expected = path_case['expected']
                    self.assertEqual(outcome['values'][0].data.identity, identity[expected['returned']])
                    self.assertEqual(seen, [identity[value] for value in expected['observed']])
                    paths += 1
        self.assertEqual(paths, 9)
        print('Cross-role LLVM slot-to-SEM SSA:9 finite paths, issued opaque handles, simultaneous loop phis')


if __name__ == '__main__':
    unittest.main()
