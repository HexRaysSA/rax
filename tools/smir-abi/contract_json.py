"""Dependency-free canonical JSON and the exact JSON Schema subset used here.

Only local $refs, type/const/enum, bounds/pattern, oneOf/anyOf, array items and
closed object properties are supported. Unknown validation keywords fail closed.
This is not a general JSON Schema implementation or an envelope decoder.
"""

import json
from pathlib import Path
import re

SPEC = Path(__file__).resolve().parents[2] / 'docs/specifications/smir/portable/schema/abi'
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
ANNOTATIONS = {'$schema', '$id', '$defs', 'title', 'description'}
KEYWORDS = ANNOTATIONS | {
    '$ref', 'type', 'const', 'enum', 'minimum', 'maximum', 'minLength', 'maxLength',
    'pattern', 'oneOf', 'anyOf', 'minItems', 'maxItems', 'items',
    'properties', 'required', 'additionalProperties',
}


def fail(detail):
    raise ValueError('ABI_SCHEMA:' + detail)


def audit(schema, root):
    if not isinstance(schema, dict) or not schema.keys() <= KEYWORDS:
        fail('unsupported-schema')
    if '$ref' in schema:
        ref = schema['$ref']
        if not isinstance(ref, str) or not ref.startswith('#/$defs/') or ref[8:] not in root.get('$defs', {}):
            fail('reference')
    for keyword in ('oneOf', 'anyOf'):
        for child in schema.get(keyword, []):
            audit(child, root)
    for keyword in ('properties', '$defs'):
        for child in schema.get(keyword, {}).values():
            audit(child, root)
    if 'items' in schema:
        audit(schema['items'], root)


def verify(value, schema, root=None):
    if root is None:
        audit(schema, schema)
    root = schema if root is None else root
    if not isinstance(schema, dict) or not schema.keys() <= KEYWORDS:
        fail('unsupported-schema')
    if '$ref' in schema:
        ref = schema['$ref']
        if not ref.startswith('#/$defs/') or ref[8:] not in root.get('$defs', {}):
            fail('reference')
        verify(value, root['$defs'][ref[8:]], root)
    for keyword in ('oneOf', 'anyOf'):
        if keyword in schema:
            matches = 0
            for alternative in schema[keyword]:
                try:
                    verify(value, alternative, root)
                    matches += 1
                except ValueError:
                    pass
            if matches == 0 or keyword == 'oneOf' and matches != 1:
                fail(keyword)
    if 'type' in schema:
        kind = schema['type']
        matches = {'object': isinstance(value, dict), 'array': isinstance(value, list),
                   'string': isinstance(value, str), 'integer': type(value) is int,
                   'boolean': type(value) is bool, 'null': value is None}
        if not matches.get(kind, False):
            fail('type')
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        fail('const')
    if 'enum' in schema and not any(type(value) is type(item) and value == item
                                    for item in schema['enum']):
        fail('enum')
    if type(value) is int:
        if value < schema.get('minimum', value) or value > schema.get('maximum', value):
            fail('range')
    if isinstance(value, str):
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', len(value)):
            fail('length')
        if 'pattern' in schema and re.search(schema['pattern'], value) is None:
            fail('pattern')
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', len(value)):
            fail('items')
        if 'items' in schema:
            for item in value:
                verify(item, schema['items'], root)
    if isinstance(value, dict):
        if not set(schema.get('required', [])) <= value.keys():
            fail('required')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and not value.keys() <= properties.keys():
            fail('unknown-key')
        for name, item in value.items():
            if name in properties:
                verify(item, properties[name], root)


def check_named(value, filename):
    verify(value, json.loads((SPEC / filename).read_text()))


def loads(payload):
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise ValueError('ABI_JSON_LIMIT')
    def object_pairs(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('ABI_JSON_DUPLICATE')
            result[name] = value
        return result

    def noninteger(value):
        raise ValueError('ABI_JSON_NUMBER')

    return json.loads(payload, object_pairs_hook=object_pairs,
                      parse_float=noninteger, parse_constant=noninteger)


def encode(value):
    # Round-trip excludes floats/NaN in caller-created Python values too.
    result = json.dumps(value, ensure_ascii=True, sort_keys=True,
                        separators=(',', ':'), allow_nan=False).encode('ascii')
    loads(result)
    return result


def decode(payload):
    value = loads(payload)
    if encode(value) != payload:
        raise ValueError('ABI_JSON_NONCANONICAL')
    return value
