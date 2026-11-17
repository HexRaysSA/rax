"""Per-bit raw-byte poison/provenance reference for pinned LLVM bN semantics.

The linear memory below is a sequential witness, not guest memory, an allocator,
or a substitute for the runtime's guarded lifetime/concurrency implementation.
"""
from dataclasses import dataclass

from common import HEX, bit_pattern, require


@dataclass(frozen=True)
class Pointer:
    identity: str
    address: int
    generation: int
    domain: str = 'data'

    def __post_init__(self):
        require(isinstance(self.identity, str) and len(self.identity) == 64
                and HEX.fullmatch(self.identity) is not None, 'shadow_identity')
        require(type(self.address) is int and 0 <= self.address < 2**64
                and type(self.generation) is int and 0 < self.generation < 2**64,
                'shadow_pointer')
        require(self.domain in {'data', 'code'}, 'shadow_pointer')
        if self.domain == 'code':
            require(self.address != 0 and self.address % 2 == 0, 'shadow_pointer', 'code token')


@dataclass(frozen=True)
class Raw:
    width: int
    bits: int
    poison: int
    origins: tuple

    def __post_init__(self):
        require(type(self.width) is int and 1 <= self.width <= 65535, 'shadow_width')
        require(type(self.bits) is int and 0 <= self.bits < 2**self.width
                and type(self.poison) is int and 0 <= self.poison < 2**self.width,
                'shadow_bits')
        require(type(self.origins) is tuple and len(self.origins) == self.width, 'shadow_origins')
        for index, origin in enumerate(self.origins):
            if origin is None:
                continue
            require(type(origin) is tuple and len(origin) == 2
                    and isinstance(origin[0], Pointer) and type(origin[1]) is int
                    and 0 <= origin[1] < 64, 'shadow_origins')
            pointer, source_bit = origin
            require(not (self.poison >> index) & 1, 'shadow_origins', 'poison has no pointer origin')
            require((self.bits >> index) & 1 == (pointer.address >> source_bit) & 1,
                    'shadow_origins', 'pointer bit inconsistent with admitted origin')

    @classmethod
    def integer(cls, width, bits, poison=0):
        require(type(width) is int and 1 <= width <= 65535, 'shadow_width')
        return cls(width, bits, poison, (None,) * width)

    @classmethod
    def pointer(cls, pointer):
        require(isinstance(pointer, Pointer), 'shadow_pointer')
        return cls(64, pointer.address, 0, tuple((pointer, index) for index in range(64)))

    def slice(self, offset, width):
        require(type(offset) is int and type(width) is int and offset >= 0
                and width > 0 and offset + width <= self.width, 'shadow_range')
        mask = (1 << width) - 1
        return Raw(width, (self.bits >> offset) & mask, (self.poison >> offset) & mask,
                   self.origins[offset:offset + width])

    def freeze(self):
        # Zero each poison bit independently; retain every unaffected raw bit
        # and pointer-origin fragment. Freezing must not invent provenance.
        return Raw(self.width, self.bits & ~self.poison, 0, self.origins)

    def scalar(self):
        return {'kind': 'poison'} if self.poison else {'kind': 'bits', 'bits': self.bits}

    def as_pointer(self):
        require(self.width == 64, 'shadow_width', 'portable pointer is64 bits')
        if self.poison:
            return {'kind': 'poison'}
        first = self.origins[0]
        if first is not None:
            pointer = first[0]
            if all(origin == (pointer, index) for index, origin in enumerate(self.origins)):
                return {'kind': 'pointer', 'address': self.bits, 'identity': pointer.identity,
                        'generation': pointer.generation, 'domain': pointer.domain}
        return {'kind': 'pointer', 'address': self.bits, 'identity': None,
                'generation': None, 'domain': 'unprovenanced'}


def concat(parts):
    require(isinstance(parts, list) and parts and all(isinstance(part, Raw) for part in parts),
            'shadow_shape')
    width = sum(part.width for part in parts)
    require(width <= 65535, 'shadow_width')
    bits = poison = offset = 0
    origins = []
    # First part occupies the lowest-address / least-significant bits.
    for part in parts:
        bits |= part.bits << offset
        poison |= part.poison << offset
        origins.extend(part.origins)
        offset += part.width
    return Raw(width, bits, poison, tuple(origins))


class Memory:
    """Fixed-size sequential bit-shadow memory; all effects bounds-checked first."""

    def __init__(self, size):
        require(type(size) is int and 0 <= size <= 8191, 'shadow_limit')
        self.bits = [0] * (8 * size)
        self.poison = [1] * (8 * size)
        self.origins = [None] * (8 * size)

    def bounds(self, address, width):
        require(type(address) is int and address >= 0 and type(width) is int and width > 0
                and width % 8 == 0 and 8 * address + width <= len(self.bits), 'shadow_range')
        return 8 * address

    def load(self, address, width):
        offset = self.bounds(address, width)
        bits = sum(self.bits[offset + index] << index for index in range(width))
        poison = sum(self.poison[offset + index] << index for index in range(width))
        return Raw(width, bits, poison, tuple(self.origins[offset:offset + width]))

    def store(self, address, value):
        require(isinstance(value, Raw), 'shadow_shape')
        offset = self.bounds(address, value.width)
        self.bits[offset:offset + value.width] = [(value.bits >> index) & 1 for index in range(value.width)]
        self.poison[offset:offset + value.width] = [(value.poison >> index) & 1 for index in range(value.width)]
        self.origins[offset:offset + value.width] = value.origins

    def move(self, destination, source, size):
        require(type(size) is int and size >= 0, 'shadow_range')
        if size == 0:
            require(type(destination) is int and type(source) is int
                    and 0 <= destination <= len(self.bits) // 8 and 0 <= source <= len(self.bits) // 8,
                    'shadow_range')
            return
        self.bounds(destination, 8 * size)
        self.bounds(source, 8 * size)
        snapshot = self.load(source, 8 * size)
        self.store(destination, snapshot)


def from_document(document):
    """Admit exact local raw-value fixture records; pointer registry is explicit.

    The registry is an assumed prior admission result, not self-authenticating
    pointer evidence or a permission to dereference any supplied address.
    """
    require(isinstance(document, dict) and set(document) == {
        'revision', 'width', 'bits', 'poison', 'pointers', 'origins'}, 'shadow_shape')
    require(document['revision'] == 'raw_bits_draft_v1', 'shadow_revision')
    width = document['width']
    require(type(width) is int and 1 <= width <= 65535, 'shadow_width')
    for field in ['bits', 'poison']:
        require(isinstance(document[field], str) and len(document[field]) == 2 * ((width + 7) // 8)
                and HEX.fullmatch(document[field]) is not None, 'shadow_shape')
    bits = bit_pattern(document['bits'], width)
    poison = bit_pattern(document['poison'], width)
    require(isinstance(document['pointers'], list) and len(document['pointers']) <= 1024
            and isinstance(document['origins'], list) and len(document['origins']) <= width, 'shadow_limit')
    registry = {}
    for record in document['pointers']:
        require(isinstance(record, dict) and set(record) == {'identity', 'address', 'generation', 'domain'},
                'shadow_shape')
        pointer = Pointer(**record)
        require(pointer.identity not in registry, 'shadow_identity', 'duplicate registry entry')
        registry[pointer.identity] = pointer
    origins = [None] * width
    previous = -1
    for record in document['origins']:
        require(isinstance(record, dict) and set(record) == {'bit', 'pointer', 'source_bit'}, 'shadow_shape')
        bit = record['bit']
        require(type(bit) is int and previous < bit < width, 'shadow_origins', 'sorted distinct bit')
        previous = bit
        require(isinstance(record['pointer'], str) and record['pointer'] in registry,
                'shadow_identity', 'unknown origin')
        origins[bit] = (registry[record['pointer']], record['source_bit'])
    return Raw(width, bits, poison, tuple(origins))
