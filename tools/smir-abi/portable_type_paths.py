"""Explicit foundation selection; never search/fall back to another checkout."""
from pathlib import Path
import os

def foundation():
    override=os.environ.get('SMIR_TYPE_FRONTEND_FOUNDATION')
    root=Path(__file__).resolve().parents[2] if override is None else Path(override)
    if not root.is_absolute():raise ValueError('PORTABLE_FOUNDATION_ABSOLUTE_PATH_REQUIRED')
    root=root.resolve(strict=True)
    required=('tools/smir-abi/nominal.py','tools/smir-format/execution/candidate/type_system.py',
              'docs/specifications/smir/portable/schema/abi/candidate.json',
              'docs/specifications/smir/portable/schema/execution/candidate.json',
              'docs/specifications/smir/portable/llvm/target.json',
              'docs/specifications/smir/portable/llvm/frontend-contract.json')
    if not root.is_dir() or not all((root/p).is_file() for p in required):
        raise ValueError('PORTABLE_FOUNDATION_INCOMPLETE')
    return root
