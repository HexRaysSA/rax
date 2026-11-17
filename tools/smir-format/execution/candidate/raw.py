"""Raw bN up to2^23 bits with sparse ordered pointer-origin spans."""
from dataclasses import dataclass

from common import require


@dataclass(frozen=True)
class Span:
    offset: int
    length: int
    pointer: object
    source: int


@dataclass(frozen=True)
class Raw:
    width: int
    bits: int
    poison: int = 0
    origins: tuple = ()
    undef: int = 0

    def __post_init__(self):
        require(type(self.width) is int and 1 <= self.width <= 2**23, 'raw_width')
        require(type(self.bits) is int and type(self.poison) is int and type(self.undef) is int
                and 0 <= self.bits < 1 << self.width and 0 <= self.poison < 1 << self.width
                and 0 <= self.undef < 1 << self.width and not self.poison & self.undef, 'raw_bits')
        previous = 0
        require(type(self.origins) is tuple, 'raw_origins')
        for span in self.origins:
            require(isinstance(span, Span) and type(span.offset) is int and type(span.length) is int
                    and type(span.source) is int and previous <= span.offset and 0 < span.length <= 64
                    and span.offset + span.length <= self.width and 0 <= span.source
                    and span.source + span.length <= 64, 'raw_origin_extent')
            mask = (1 << span.length) - 1
            require(not ((self.poison | self.undef) >> span.offset) & mask
                    and (self.bits >> span.offset) & mask == (span.pointer.address >> span.source) & mask,
                    'raw_origin_bits')
            previous = span.offset + span.length

    @classmethod
    def integer(cls, width, bits, poison=0, undef=0):
        return cls(width, bits, poison, (), undef)

    @classmethod
    def pointer(cls, pointer):
        return cls(64, pointer.address, 0, (Span(0, 64, pointer, 0),))

    def slice(self, offset, width):
        require(type(offset) is int and type(width) is int and offset >= 0
                and width > 0 and offset + width <= self.width, 'raw_slice')
        mask = (1 << width) - 1
        spans = []
        for span in self.origins:
            start, end = max(offset, span.offset), min(offset + width, span.offset + span.length)
            if start < end:
                spans.append(Span(start - offset, end - start, span.pointer, span.source + start - span.offset))
        return Raw(width, (self.bits >> offset) & mask, (self.poison >> offset) & mask, tuple(spans),
                   (self.undef >> offset) & mask)

    def freeze(self):
        return Raw(self.width, self.bits & ~(self.poison | self.undef), 0, self.origins)

    def scalar(self):
        return {'kind': 'poison'} if self.poison else {'kind': 'bits', 'bits': self.bits & ~self.undef}

    def as_pointer(self):
        require(self.width == 64, 'raw_pointer_width')
        if self.poison:
            return {'kind': 'poison'}
        pointer = self.origins[0].pointer if self.origins else None
        cursor = 0
        for span in self.origins:
            if span.offset != cursor or span.source != cursor or span.pointer != pointer:
                pointer = None
                break
            cursor += span.length
        if pointer is not None and cursor == 64:
            return {'kind': 'pointer', 'address': self.bits, 'identity': pointer.identity,
                    'generation': pointer.generation, 'domain': pointer.domain,
                    'access_range': getattr(pointer, 'access_range', None), 'permit': getattr(pointer, 'permit', None),
                    'authority': getattr(pointer, 'authority', None), 'lineage': getattr(pointer, 'lineage', None)}
        from candidate.ranges import intersect
        restricted = None
        for span in self.origins:
            restricted = intersect(restricted, getattr(span.pointer, 'access_range', None))
        return {'kind': 'pointer', 'address': self.bits, 'identity': None, 'generation': None,
                'domain': 'unprovenanced', 'access_range': restricted}


def concat(parts):
    require(type(parts) is list and parts, 'raw_concat')
    bits = poison = undef = width = 0
    spans = []
    for part in parts:
        require(isinstance(part, Raw) and width + part.width <= 2**23, 'raw_concat_width')
        bits |= part.bits << width
        poison |= part.poison << width
        undef |= part.undef << width
        for span in part.origins:
            shifted = Span(width + span.offset, span.length, span.pointer, span.source)
            if spans and spans[-1].offset + spans[-1].length == shifted.offset and spans[-1].pointer == shifted.pointer \
                    and spans[-1].source + spans[-1].length == shifted.source:
                previous = spans.pop()
                shifted = Span(previous.offset, previous.length + shifted.length, previous.pointer, previous.source)
            spans.append(shifted)
        width += part.width
    return Raw(width, bits, poison, tuple(spans), undef)


def overwrite(base, offset, value):
    require(0 <= offset and offset + value.width <= base.width, 'raw_overlay')
    parts = []
    if offset:
        parts.append(base.slice(0, offset))
    parts.append(value)
    end = offset + value.width
    if end < base.width:
        parts.append(base.slice(end, base.width - end))
    return concat(parts)
