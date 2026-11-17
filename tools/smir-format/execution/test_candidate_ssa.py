"""Independent Rust graph-path dominance witness, including invoke edge results."""
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

from common import ROOT


class CandidateSSATests(unittest.TestCase):
    def test_independent_path_exclusion(self):
        rng = random.Random(0x53534132)
        cases, expected = [], []
        # Diamond: normal definition belongs to block1, cannot dominate block2/3.
        for origin, use, accepted in [(1, 1, True), (1, 2, False), (1, 3, False), (0, 3, True)]:
            cases.append(['entry 0', 'block 0', 'block 1', 'block 2', 'block 3',
                          'edge 0 1', 'edge 0 2', 'edge 1 3', 'edge 2 3',
                          f'def 0 32 {origin} -2', f'use 0 32 {use} 0'])
            expected.append('OK' if accepted else 'ssa_dominance')
        for _ in range(512):
            count = rng.randrange(2, 24)
            edges = [(index, index + 1) for index in range(count - 1)]
            edges += [(rng.randrange(count), rng.randrange(1, count)) for _ in range(count)]
            origin, target = rng.randrange(count), rng.randrange(count)
            # Independent finite path-removal criterion in the harness generates
            # exact expected results; implementation uses Rust traversal.
            pending, reached = [0], set()
            while pending:
                current = pending.pop()
                if current in reached or current == origin:
                    continue
                reached.add(current)
                pending += [to for source, to in edges if source == current]
            accepted = origin == target or target not in reached
            cases.append(['entry 0'] + [f'block {i}' for i in range(count)]
                         + [f'edge {a} {b}' for a, b in edges]
                         + [f'def 0 32 {origin} -2', f'use 0 32 {target} 0'])
            expected.append('OK' if accepted else 'ssa_dominance')
        with tempfile.TemporaryDirectory(prefix='rax-candidate-ssa-') as temporary:
            probe = Path(temporary) / 'ssa-probe'
            subprocess.run(['rustc', '--edition', '2024', '-D', 'warnings',
                            str(ROOT / 'tools/smir-format/execution/candidate/ssa_probe.rs'), '-o', str(probe)], check=True)
            result = subprocess.run([str(probe)], input=''.join('\n'.join(case) + '\nend\n' for case in cases),
                                    text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.splitlines(), expected)
        print('Candidate independent Rust SSA witness:516 graphs;seed0x53534132;no skips')
