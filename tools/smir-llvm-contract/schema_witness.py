"""Independent validator for the finite JSON Schema subset in request.schema.json.

This is a schema witness, not a general JSON Schema implementation. Unknown
validation keywords reject instead of becoming implicitly permissive.
"""


class SchemaError(ValueError):
    pass


def validate(value, schema):
    supported = {'$schema', '$id', '$comment', 'title', 'type', 'const', 'enum',
                 'additionalProperties', 'required', 'properties', 'prefixItems',
                 'minItems', 'maxItems', 'maxProperties'}
    if schema.keys() - supported:
        raise SchemaError('unsupported schema keyword')
    expected_type = schema.get('type')
    types = {'object': dict, 'array': list, 'integer': int,
             'boolean': bool, 'string': str}
    if expected_type is not None:
        if expected_type not in types or type(value) is not types[expected_type]:
            raise SchemaError('type')
    if 'const' in schema and value != schema['const']:
        raise SchemaError('const')
    if 'enum' in schema and value not in schema['enum']:
        raise SchemaError('enum')
    if type(value) is dict:
        if set(schema.get('required', [])) - value.keys():
            raise SchemaError('required')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and value.keys() - properties.keys():
            raise SchemaError('additionalProperties')
        if 'maxProperties' in schema and len(value) > schema['maxProperties']:
            raise SchemaError('maxProperties')
        for name in value.keys() & properties.keys():
            validate(value[name], properties[name])
    if type(value) is list:
        if len(value) < schema.get('minItems', 0):
            raise SchemaError('minItems')
        if 'maxItems' in schema and len(value) > schema['maxItems']:
            raise SchemaError('maxItems')
        for index, item_schema in enumerate(schema.get('prefixItems', [])):
            if index < len(value):
                validate(value[index], item_schema)
