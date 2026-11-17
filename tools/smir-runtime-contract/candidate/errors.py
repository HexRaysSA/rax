"""Symbolic candidate diagnostics; not public framing error numbers."""


class Reject(ValueError):
    def __init__(self, code, detail=''):
        self.code = code
        super().__init__(code + (': ' + detail if detail else ''))


def require(condition, code, detail=''):
    if not condition:
        raise Reject(code, detail)


def exact(value, fields, code='RT_FIELDS'):
    require(type(value) is dict and set(value) == set(fields), code)


def uint(value, width=64):
    require(type(value) is int and 0 <= value < 1 << width, 'RT_INTEGER')
    return value


def unique(records, key, code='RT_DUPLICATE'):
    result = {}
    for value in records:
        identity = value[key]
        require(identity not in result, code, str(identity))
        result[identity] = value
    return result


def some(value):
    return {'some': value}


def option(value):
    if value is None:
        return None
    exact(value, ['some'], 'RT_OPTION')
    return value['some']
