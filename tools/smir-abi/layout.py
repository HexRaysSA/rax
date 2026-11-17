#!/usr/bin/env python3
"""Independent, bounded portable object-layout model; never an execution loader."""

from dataclasses import dataclass
import json
from pathlib import Path
import sys

from contract_json import check_named, loads

MAX_OBJECT = (1 << 61) - 1  # bytes; all bit extents then fit u64
MAX_ALIGN = 65536
MAX_TYPES = 4096
MAX_DEPTH = 128

# Size and ABI alignment, in bytes. No host ctypes or compiler queried here.
SCALARS = {
    'bool': (1, 1), 'char': (1, 1), 'signed char': (1, 1),
    'unsigned char': (1, 1), 'char8_t': (1, 1),
    'short': (2, 2), 'unsigned short': (2, 2), 'char16_t': (2, 2),
    'int': (4, 4), 'unsigned int': (4, 4), 'wchar_t': (4, 4), 'wint_t': (4, 4),
    'char32_t': (4, 4), 'float': (4, 4),
    'long': (8, 8), 'unsigned long': (8, 8),
    'long long': (8, 8), 'unsigned long long': (8, 8),
    'size_t': (8, 8), 'ptrdiff_t': (8, 8), 'double': (8, 8),
    'pointer': (8, 8), 'nullptr_t': (8, 8),
    '__int128': (16, 16), 'unsigned __int128': (16, 16),
    'long double': (16, 16), 'data_member_pointer': (8, 8),
    'function_member_pointer': (16, 8),
}
INTEGER_NAMES = {
    name for name in SCALARS
    if name not in {'float', 'double', 'long double', 'pointer', 'nullptr_t',
                    'data_member_pointer', 'function_member_pointer'}
}


class ABIError(ValueError):
    """Symbolic draft error identity; not a shared public diagnostic number."""


def require(condition, code):
    if not condition:
        raise ABIError(code)


def integer(value, low, high, code='ABI_RANGE'):
    require(type(value) is int and low <= value <= high, code)
    return value


def keys(value, required, optional=()):
    require(isinstance(value, dict), 'ABI_SHAPE')
    require(set(required) <= value.keys() <= set(required) | set(optional), 'ABI_SHAPE')


def alignment(value):
    integer(value, 1, MAX_ALIGN)
    require(value & (value - 1) == 0, 'ABI_ALIGNMENT')
    return value


def align_up(value, align):
    result = (value + align - 1) // align * align
    require(0 <= result <= MAX_OBJECT, 'ABI_SIZE_OVERFLOW')
    return result


def decimal(value):
    require(isinstance(value, str), 'ABI_ENUM_VALUE')
    require(len(value) <= 20000, 'ABI_LIMIT')
    # At most 128-bit unfixed enums; fixed BitInt enums use their declared width.
    import re
    require(re.fullmatch(r'0|-?[1-9][0-9]*', value) is not None, 'ABI_ENUM_VALUE')
    # Chunked conversion supports the full 65535-bit enum base without changing
    # Python's process-global decimal digit limit.
    negative = value.startswith('-')
    digits = value[1:] if negative else value
    result = 0
    for start in range(0, len(digits), 9):
        chunk = digits[start:start + 9]
        result = result * 10 ** len(chunk) + int(chunk)
    return -result if negative else result


@dataclass(frozen=True)
class Layout:
    size: int
    align: int
    fields: tuple = ()
    underlying: str | None = None
    flexible: bool = False

    def document(self):
        result = {'size': self.size, 'align': self.align}
        if self.fields:
            result['fields'] = list(self.fields)
        if self.underlying is not None:
            result['underlying'] = self.underlying
        if self.flexible:
            result['flexible'] = True
        return result


class LayoutModel:
    """O(T + F) cached graph layout, O(T + F + depth) space; cycles reject.

    T is number of type records, F total record members. Big-integer operations
    are bounded by object extent and the declared 65535-bit integer maximum.
    C++ inheritance/vtables are source-defined, witnessed separately, and must
    never be submitted here as plain C records.
    """

    def __init__(self, document):
        try:
            check_named(document, 'layout.schema.json')
        except ValueError as error:
            raise ABIError(str(error)) from error
        keys(document, ('revision', 'language', 'types', 'roots'))
        require(document['revision'] == 'abi-layout-draft-v1', 'ABI_REVISION')
        require(document['language'] in ('c23', 'c++23'), 'ABI_LANGUAGE')
        require(isinstance(document['types'], list), 'ABI_SHAPE')
        require(isinstance(document['roots'], list), 'ABI_SHAPE')
        require(0 < len(document['types']) <= MAX_TYPES, 'ABI_LIMIT')
        self.language = document['language']
        self.types = {}
        self.cache = {}
        self.active = set()
        for record in document['types']:
            require(isinstance(record, dict), 'ABI_SHAPE')
            name = record.get('id')
            require(isinstance(name, str) and 0 < len(name) <= 256, 'ABI_TYPE_ID')
            require(name not in self.types, 'ABI_DUPLICATE_TYPE')
            self.types[name] = record
        self.roots = document['roots']

    def all(self):
        # Validate unreachable records as well: malformed metadata cannot hide.
        for name in self.types:
            self.layout(name)
        return {name: self.layout(name).document() for name in self.roots}

    def layout(self, name):
        require(isinstance(name, str) and name in self.types, 'ABI_UNKNOWN_TYPE')
        if name in self.cache:
            return self.cache[name]
        require(name not in self.active, 'ABI_RECURSIVE_OBJECT')
        require(len(self.active) < MAX_DEPTH, 'ABI_LIMIT')
        self.active.add(name)
        try:
            result = self.compute(self.types[name])
            require(result.size <= MAX_OBJECT, 'ABI_SIZE_OVERFLOW')
            self.cache[name] = result
            return result
        finally:
            self.active.remove(name)

    def integer_info(self, name):
        record = self.types.get(name, {})
        if record.get('kind') == 'bitint':
            self.layout(name)
            return record['bits'], record['signed']
        require(record.get('kind') == 'scalar' and record.get('name') in INTEGER_NAMES,
                'ABI_INTEGER_TYPE')
        self.layout(name)
        scalar = record['name']
        signed = not scalar.startswith('unsigned') and scalar not in {
            'bool', 'char8_t', 'char16_t', 'char32_t', 'size_t', 'wint_t'}
        return (1 if scalar == 'bool' else SCALARS[scalar][0] * 8), signed

    def compute(self, record):
        kind = record.get('kind')
        if kind == 'scalar':
            keys(record, ('id', 'kind', 'name'))
            require(record['name'] in SCALARS, 'ABI_SCALAR')
            return Layout(*SCALARS[record['name']])
        if kind == 'bitint':
            keys(record, ('id', 'kind', 'bits', 'signed'))
            require(type(record['signed']) is bool, 'ABI_SHAPE')
            bits = integer(record['bits'], 2 if record['signed'] else 1, 65535)
            octets = (bits + 7) // 8
            align = min(8, 1 << (octets - 1).bit_length())
            return Layout(align_up(octets, align), align)
        if kind == 'enum':
            return self.enum(record)
        if kind == 'complex':
            keys(record, ('id', 'kind', 'element'))
            item = self.types.get(record['element'], {})
            require(item.get('kind') == 'scalar' and item.get('name') in {
                'float', 'double', 'long double'}, 'ABI_COMPLEX_ELEMENT')
            element = self.layout(record['element'])
            return Layout(element.size * 2, element.align)
        if kind == 'array':
            keys(record, ('id', 'kind', 'element', 'count'))
            element = self.layout(record['element'])
            require(not element.flexible, 'ABI_FLEXIBLE_NESTING')
            if record['count'] is None:
                require(self.language == 'c23', 'ABI_FLEXIBLE_LANGUAGE')
                return Layout(0, element.align, flexible=True)
            count = integer(record['count'], 1, MAX_OBJECT)
            size = element.size * count
            require(size <= MAX_OBJECT, 'ABI_SIZE_OVERFLOW')
            return Layout(size, element.align)
        if kind == 'atomic':
            keys(record, ('id', 'kind', 'element'))
            element = self.layout(record['element'])
            require(not element.flexible, 'ABI_ATOMIC_TYPE')
            require(self.types[record['element']]['kind'] not in ('atomic', 'array'),
                    'ABI_ATOMIC_TYPE')
            if element.size <= 16:
                size = 1 << (element.size - 1).bit_length()
                return Layout(size, max(size, element.align))
            return Layout(element.size, element.align)
        if kind == 'vector':
            keys(record, ('id', 'kind', 'element', 'count'))
            item = self.types.get(record['element'], {})
            require(item.get('kind') == 'scalar' and item.get('name') in {
                'char', 'signed char', 'unsigned char', 'short', 'unsigned short',
                'int', 'unsigned int', 'long', 'unsigned long', 'long long',
                'unsigned long long', 'float', 'double'}, 'ABI_VECTOR_ELEMENT')
            count = integer(record['count'], 1, 64)
            size = self.layout(record['element']).size * count
            extent = 1 << (size - 1).bit_length()
            require(extent <= 64, 'ABI_VECTOR_SIZE')
            return Layout(extent, extent)
        if kind in ('struct', 'union'):
            return self.record(record)
        raise ABIError('ABI_KIND')

    def enum(self, record):
        keys(record, ('id', 'kind', 'underlying', 'values'))
        require(isinstance(record['values'], list) and record['values'], 'ABI_ENUM_VALUE')
        values = [decimal(value) for value in record['values']]
        if record['underlying'] is not None:
            bits, signed = self.integer_info(record['underlying'])
            low = -(1 << (bits - 1)) if signed else 0
            high = (1 << (bits - (1 if signed else 0))) - 1
            require(min(values) >= low and max(values) <= high, 'ABI_ENUM_RANGE')
            layout = self.layout(record['underlying'])
            return Layout(layout.size, layout.align, underlying=record['underlying'])
        for name, bits, signed in [('int', 32, True), ('unsigned int', 32, False),
                                   ('long', 64, True), ('unsigned long', 64, False)]:
            low = -(1 << (bits - 1)) if signed else 0
            high = (1 << (bits - (1 if signed else 0))) - 1
            if min(values) >= low and max(values) <= high:
                return Layout(*SCALARS[name], underlying=name)
        raise ABIError('ABI_ENUM_RANGE')

    def record(self, record):
        keys(record, ('id', 'kind', 'fields', 'align'))
        require(isinstance(record['fields'], list), 'ABI_SHAPE')
        require(len(record['fields']) <= 65536, 'ABI_LIMIT')
        explicit_align = alignment(record['align'])
        union = record['kind'] == 'union'
        cursor = 0  # bits, may point into the final allocated byte
        extent = 0  # bits rounded to bytes
        align = explicit_align
        offsets = []
        names = set()
        for index, field in enumerate(record['fields']):
            keys(field, ('name', 'type', 'bits'), ('align',))
            member_align = alignment(field.get('align', 1))
            name = field['name']
            require(name is None or isinstance(name, str) and 0 < len(name) <= 256,
                    'ABI_FIELD_NAME')
            if name is not None:
                require(name not in names, 'ABI_DUPLICATE_FIELD')
                names.add(name)
            layout = self.layout(field['type'])
            if field['bits'] is not None:
                require(member_align == 1, 'ABI_BITFIELD_ALIGNAS')
                base = self.types[field['type']]
                require(base['kind'] in ('scalar', 'bitint', 'enum'), 'ABI_BITFIELD_TYPE')
                if base['kind'] == 'enum':
                    width = layout.size * 8
                else:
                    width, _ = self.integer_info(field['type'])
                bits = integer(field['bits'], 0, MAX_OBJECT * 8)
                require(bits != 0 or name is None, 'ABI_NAMED_ZERO_BITFIELD')
                require(base.get('name') != 'bool' or bits <= 1 or self.language == 'c++23',
                        'ABI_BITFIELD_WIDTH')
                require(bits <= width or self.language == 'c++23', 'ABI_BITFIELD_WIDTH')
                position = 0 if union else cursor
                if bits > layout.size * 8:
                    # C++ wide fields begin at the next byte, then T' alignment.
                    container = max(size for size in (1, 2, 4, 8, 16) if size * 8 <= bits)
                    position = 0 if union else align_up((cursor + 7) // 8, container) * 8
                    align = max(align, container)
                else:
                    unit_bits = layout.size * 8
                    align_bits = layout.align * 8
                    if bits == 0 or position % align_bits + bits > unit_bits:
                        position = ((position + align_bits - 1) // align_bits) * align_bits
                    if name is not None:
                        align = max(align, layout.align)
                offsets.append({'name': name, 'offset_bits': position, 'width_bits': bits})
                cursor = position + bits
                extent = max(extent, (cursor + 7) // 8 * 8)
            else:
                require(name is not None, 'ABI_ANONYMOUS_RECORD_UNSUPPORTED')
                if layout.flexible:
                    require(not union and index == len(record['fields']) - 1 and index > 0,
                            'ABI_FLEXIBLE_POSITION')
                    require(self.types[field['type']]['kind'] == 'array', 'ABI_FLEXIBLE_NESTING')
                field_align = max(layout.align, member_align)
                position = 0 if union else align_up((cursor + 7) // 8, field_align) * 8
                offsets.append({'name': name, 'offset_bits': position,
                                'width_bits': layout.size * 8})
                cursor = position + layout.size * 8
                extent = max(extent, cursor)
                align = max(align, field_align)
        # Empty records in ISO C are invalid; C++ empty class has unique size 1.
        require(record['fields'] or self.language == 'c++23', 'ABI_EMPTY_C_RECORD')
        require(names or self.language == 'c++23', 'ABI_UNNAMED_C_RECORD')
        size = align_up(max(1, (extent + 7) // 8), align)
        flexible = any(self.layout(field['type']).flexible for field in record['fields'])
        return Layout(size, align, tuple(offsets), flexible=flexible)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    args = parser.parse_args()
    try:
        result = LayoutModel(loads(args.input.read_text())).all()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
