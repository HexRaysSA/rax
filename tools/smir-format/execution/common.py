"""Shared draft record mechanics; not a production admission interface."""
from dataclasses import dataclass
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
SPEC = ROOT / 'docs/specifications/smir/portable'
SCHEMA_PATH = SPEC / 'schema/execution/records.json'
SCHEMA = json.loads(SCHEMA_PATH.read_text())
# Both documents are owned execution drafts. Importing a record shape does not
# make its operations admissible to the integer-only semantic verifier.
EXCEPTIONS_PATH = SPEC / 'schema/execution/exceptions.json'
SCHEMA['records'].update(json.loads(EXCEPTIONS_PATH.read_text())['records'])
TYPES_PATH = SPEC / 'schema/execution/types.json'
SCHEMA['records'].update(json.loads(TYPES_PATH.read_text())['records'])
TOKEN = re.compile(r'[a-z][a-z0-9_]{0,62}\Z', re.ASCII)
HEX = re.compile(r'(?:[0-9a-f]{2})*\Z', re.ASCII)


class Reject(ValueError):
    """Symbolic draft diagnostic, deliberately outside the public ID registry."""

    def __init__(self, code, detail=''):
        self.code = code
        self.detail = detail
        super().__init__(f'{code}: {detail}')


def require(condition, code, detail=''):
    if not condition:
        raise Reject(code, detail)


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 8 * 1024 * 1024
    max_nodes: int = 100_000
    max_list: int = 100_000
    max_depth: int = 64
    max_blocks: int = 1024
    max_functions: int = 256
    max_bits: int = 65535


class Budget:
    def __init__(self, limits):
        self.limits = limits
        self.nodes = 0

    def visit(self, depth):
        self.nodes += 1
        require(depth <= self.limits.max_depth and self.nodes <= self.limits.max_nodes,
                'limit', 'record depth or node count')


def fields(record_type, value):
    """Resolve exact record fields; union discriminators are symbolic tokens."""
    record = SCHEMA['records'][record_type]
    if 'variants' not in record:
        return record['fields'], None
    key = record['discriminator']
    require(isinstance(value, dict) and isinstance(value.get(key), str)
            and value[key] in record['variants'],
            'shape', f'{record_type} discriminator')
    return record['variants'][value[key]], key


def check_shape(record_type, value, limits=Limits(), budget=None, depth=0):
    """Validate all fields without coercion, defaults, unknown keys or bool-as-int."""
    budget = budget or Budget(limits)
    budget.visit(depth)
    if record_type.startswith('vec:'):
        require(isinstance(value, list) and len(value) <= limits.max_list,
                'shape', record_type)
        for item in value:
            check_shape(record_type[4:], item, limits, budget, depth + 1)
        return
    if record_type in {'u32', 'u64'}:
        require(type(value) is int and 0 <= value < 2**int(record_type[1:]), 'shape', record_type)
        return
    if record_type == 'hex':
        require(isinstance(value, str) and len(value) <= 2 * limits.max_bytes
                and HEX.fullmatch(value) is not None, 'shape', 'lowercase byte hex')
        return
    if record_type == 'token':
        require(isinstance(value, str) and TOKEN.fullmatch(value) is not None,
                'shape', 'ASCII token')
        return
    require(isinstance(value, dict), 'shape', record_type)
    layout, discriminator = fields(record_type, value)
    expected = {name for name, _ in layout}
    if discriminator is not None:
        expected.add(discriminator)
    require(set(value) == expected, 'shape', f'{record_type} exact fields')
    for name, kind in layout:
        check_shape(kind, value[name], limits, budget, depth + 1)


def bit_pattern(text, width):
    require(len(text) == 2 * ((width + 7) // 8), 'constant', 'byte extent')
    value = int.from_bytes(bytes.fromhex(text), 'little')
    require(value < 2**width, 'constant', 'nonzero high padding bits')
    return value
