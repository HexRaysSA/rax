"""Negative process-isolated import-identity witness; never issues facts."""
import sys
from types import ModuleType
from pathlib import Path

root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / 'tools/smir-runtime-contract'))
name = sys.argv[1]
if name.startswith('candidate.'):
    sys.path.insert(0, str(root / 'tools/smir-format/execution'))
    __import__('candidate')
module = ModuleType(name)
module.__file__ = '/noncanonical/source-contract-import-probe.py'
sys.modules[name] = module
from source_contracts.__main__ import main
raise SystemExit(main(sys.argv[2:]))
