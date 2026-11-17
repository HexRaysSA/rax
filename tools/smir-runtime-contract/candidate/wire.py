"""Shared INT-008 physical codec with runtime-owned exact root schemas."""
import importlib.util
import json
from pathlib import Path
import sys

from .errors import Reject, require

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/runtime/candidate.json'
CODEC = ROOT / 'tools/smir-format/codec.py'
_MODULE = '_smir_runtime_record_primitives'
if _MODULE not in sys.modules:
    specification = importlib.util.spec_from_file_location(_MODULE, CODEC)
    module = importlib.util.module_from_spec(specification)
    sys.modules[_MODULE] = module
    specification.loader.exec_module(module)
PRIMITIVES = sys.modules[_MODULE]


def records():
    return json.loads(SCHEMA.read_text())['records']


def codec():
    return PRIMITIVES.RecordCodec(records())


def encode(kind, value):
    try:
        return codec().encode(kind, value)
    except PRIMITIVES.RecordError as error:
        raise Reject('RT_WIRE', str(error)) from error


def decode(kind, payload):
    try:
        return codec().decode(kind, payload)
    except PRIMITIVES.RecordError as error:
        raise Reject('RT_WIRE', str(error)) from error


def validate_shape(kind, value):
    payload = encode(kind, value)
    require(decode(kind, payload) == value, 'RT_NONCANONICAL')
    return payload
