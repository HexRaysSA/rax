"""Reuse owned independent legacy native carrier extractor, not a native loader."""
import importlib.util
from pathlib import Path
import sys


def discover(payload,kind):
    directory=Path(__file__).resolve().parents[1]
    # Legacy modules use sibling absolute imports; preserve their established API.
    sys.path.insert(0,str(directory))
    try:
        from carriers import inspect
        from schema import ContractError
        from .errors import Reject
        try:return inspect(payload,kind)
        except ContractError as error:raise Reject('RT_LAUNCH_CARRIER_INVALID',str(error)) from error
    finally:
        sys.path.remove(str(directory))
