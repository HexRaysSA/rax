"""Private conformance child: no executable SMIR or transferable proof output."""
from pathlib import Path
import json
import os
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[6]
# Dispatch validation precedes all owner/verifier imports; unknown names cannot fall back.
catalog = json.loads((HERE / 'cases.json').read_bytes())
allowed = {row['id'] for row in catalog['cases']}
if len(sys.argv) != 2 or sys.argv[1] not in allowed:
    raise SystemExit('unknown source-grounding conformance case')
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[1])
if suite.countTestCases() != 1:
    raise SystemExit('source-grounding case must resolve exactly one test')
result = unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps(dict(case=sys.argv[1], tests=result.testsRun,
                      fail=len(result.failures), error=len(result.errors),
                      skip=len(result.skipped), optimize=sys.flags.optimize)))
sys.exit(0 if result.wasSuccessful() and result.testsRun == 1 and not result.skipped else 1)
