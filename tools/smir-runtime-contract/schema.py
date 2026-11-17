"""Strict draft schema validation and canonical reference JSON transport.

This validates runtime metadata, not executable SMIR admission. No production
runtime imports this package. The schema subset is deliberate and checked.
"""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / 'docs/specifications/smir/portable/schema/runtime'
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024


class ContractError(ValueError):
    """A local symbolic diagnostic; it is not a shared SMIR error number."""

    def __init__(self, code, detail=''):
        self.code = code
        super().__init__(f'{code}: {detail}')


def require(condition, code, detail=''):
    if not condition:
        raise ContractError(code, detail)


def canonical(document):
    """Encode the exact local transport, without admitting a guest program."""
    def check(value, depth=0):
        require(depth <= 64, 'DOCUMENT_DEPTH')
        if value is None or type(value) in (str, int, bool):
            if type(value) is str:
                # Reject isolated surrogates even though JSON escapes could encode them.
                value.encode('utf-8')
            return
        if type(value) is list:
            for item in value:
                check(item, depth + 1)
            return
        if type(value) is dict and all(type(key) is str for key in value):
            for key, item in value.items():
                check(key, depth + 1)
                check(item, depth + 1)
            return
        raise ContractError('TRANSPORT_TYPE', type(value).__name__)
    try:
        check(document)
        payload = json.dumps(document, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode('ascii')
    except ContractError:
        raise
    except (UnicodeError, RecursionError, ValueError) as error:
        raise ContractError('TRANSPORT_VALUE', str(error)) from error
    require(len(payload) <= MAX_DOCUMENT_BYTES, 'DOCUMENT_LIMIT')
    return payload


def decode(payload):
    require(len(payload) <= MAX_DOCUMENT_BYTES, 'DOCUMENT_LIMIT')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_KEY', key)
            result[key] = value
        return result

    def reject_constant(value):
        raise ContractError('TRANSPORT_CONSTANT', value)

    try:
        document = json.loads(payload.decode('ascii'), object_pairs_hook=unique,
                              parse_constant=reject_constant)
    except ContractError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ContractError('TRANSPORT_SYNTAX', str(error)) from error
    require(canonical(document) == payload, 'NONCANONICAL')
    return document


SCHEMA_KEYWORDS = {
    '$schema', '$id', '$ref', '$defs', 'title', 'type', 'const', 'enum', 'oneOf',
    'properties', 'required', 'additionalProperties', 'items', 'minItems',
    'maxItems', 'minLength', 'maxLength', 'pattern', 'minimum', 'maximum',
}


def audit_schema(rule):
    require(type(rule) is dict and rule.keys() <= SCHEMA_KEYWORDS,
            'SCHEMA_KEYWORD')
    for value in rule.get('$defs', {}).values():
        audit_schema(value)
    if 'properties' in rule:
        require(rule.get('additionalProperties') is False and
                set(rule.get('required', [])) == rule['properties'].keys(),
                'SCHEMA_OBJECT_DEFINITION')
        for value in rule['properties'].values():
            audit_schema(value)
    if 'items' in rule:
        audit_schema(rule['items'])
    for value in rule.get('oneOf', []):
        audit_schema(value)


def validate(document, name):
    """Validate our complete used JSON Schema subset; O(nodes + string bytes)."""
    root = json.loads((SCHEMAS / f'{name}.schema.json').read_text())
    audit_schema(root)
    _validate(document, root, root, '$')


def _validate(value, rule, root, path):
    if '$ref' in rule:
        prefix = '#/$defs/'
        if rule['$ref'].startswith(prefix):
            return _validate(value, root['$defs'][rule['$ref'][len(prefix):]], root, path)
        prefix = 'urn:rax:smir:runtime-draft-v1:'
        require(rule['$ref'].startswith(prefix), 'SCHEMA_REF', path)
        name = rule['$ref'][len(prefix):]
        require(name in {'state'}, 'SCHEMA_REF', path)
        referenced = json.loads((SCHEMAS / f'{name}.schema.json').read_text())
        audit_schema(referenced)
        return _validate(value, referenced, referenced, path)
    if 'oneOf' in rule:
        accepted = 0
        for variant in rule['oneOf']:
            try:
                _validate(value, variant, root, path)
                accepted += 1
            except ContractError:
                pass
        require(accepted == 1, 'SCHEMA_ONE_OF', path)
        return
    if 'const' in rule:
        require(type(value) is type(rule['const']) and value == rule['const'],
                'SCHEMA_CONST', path)
    if 'enum' in rule:
        require(value in rule['enum'], 'SCHEMA_ENUM', path)
    kind = rule.get('type')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int,
             'boolean': bool, 'null': type(None)}
    if kind:
        require(type(value) is types[kind], 'SCHEMA_TYPE', path)
    if kind == 'object':
        require(set(rule['required']) <= value.keys(), 'SCHEMA_REQUIRED', path)
        require(rule['additionalProperties'] is False, 'SCHEMA_DEFINITION', path)
        require(value.keys() <= rule['properties'].keys(), 'SCHEMA_UNKNOWN_KEY', path)
        for key, item in value.items():
            _validate(item, rule['properties'][key], root, f'{path}.{key}')
    elif kind == 'array':
        require(len(value) <= rule.get('maxItems', len(value)), 'SCHEMA_COUNT', path)
        require(len(value) >= rule.get('minItems', 0), 'SCHEMA_COUNT', path)
        for index, item in enumerate(value):
            _validate(item, rule['items'], root, f'{path}[{index}]')
    elif kind == 'string':
        require(rule.get('minLength', 0) <= len(value) <= rule.get('maxLength', len(value)),
                'SCHEMA_LENGTH', path)
        if 'pattern' in rule:
            require(re.fullmatch(rule['pattern'], value) is not None, 'SCHEMA_PATTERN', path)
        try:
            value.encode('utf-8')
        except UnicodeError as error:
            raise ContractError('SCHEMA_UNICODE', path) from error
    elif kind == 'integer':
        require(rule.get('minimum', value) <= value <= rule.get('maximum', value),
                'SCHEMA_RANGE', path)


def unique_by(records, key, code):
    result = {}
    for record in records:
        identity = record[key]
        require(identity not in result, code, str(identity))
        result[identity] = record
    return result


def unique_list(values, code):
    require(len(set(values)) == len(values), code)


def alignment(value):
    return 1 <= value <= 2**31 and value & (value - 1) == 0
