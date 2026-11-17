"""Sequential exact typed/shadow memory oracle; production guards remain runtime."""
import hashlib

from common import require
from candidate.raw import Raw, concat, overwrite
from candidate.operations import optional
from candidate.type_system import key
from candidate.values import Pointer, Value, from_raw, raw_bits


class GuestFault(Exception):
    def __init__(self, code, language_ub=False):
        self.code, self.language_ub = code, language_ub


class Memory:
    def __init__(self, types, dependencies, max_bytes=1024 * 1024):
        self.types, self.dependencies, self.max_bytes = types, dependencies, max_bytes
        self.objects, self.next_address, self.sequence = {}, 0x10000, 0
        self.exposed = set()
        self.effects = []

    def allocate(self, size, alignment, owner=None, source_object=True, mutable=True):
        if (type(size) is not int or size < 0 or type(alignment) is not int or alignment <= 0
                or alignment & (alignment - 1) or type(mutable) is not bool):
            raise GuestFault('allocation_shape')
        if size > self.max_bytes or sum(item['size'] for item in self.objects.values() if item['live']) + size > self.max_bytes:
            raise GuestFault('resource_memory')
        address = (self.next_address + alignment - 1) & -alignment
        if not 0 < address < 2**64 or address + size > 2**64 - int(source_object):
            raise GuestFault('source_object_extent' if source_object else 'memory_bounds')
        self.sequence += 1
        self.next_address = address + max(1, size) + 16
        identity = hashlib.sha256(f'candidate-object:{self.sequence}'.encode()).hexdigest()
        self.objects[identity] = {'address': address, 'size': size, 'generation': self.sequence, 'owner': owner,
                                  'live': True, 'mutable': mutable, 'source_object': source_object, 'active': [True] * size,
                                  'bytes': [Raw.integer(8, 0, undef=255) for _ in range(size)]}
        return Pointer(address, identity, self.sequence)

    def guard(self, pointer, size, alignment=1, lifetime_check=True, write=False):
        if pointer.domain != 'data' or pointer.origin not in self.objects:
            raise GuestFault('pointer_provenance', True)
        item = self.objects[pointer.origin]
        if not item['live'] or item['generation'] != pointer.generation:
            raise GuestFault('memory_lifetime')
        offset = pointer.address - item['address']
        if size < 0 or offset < 0 or offset + size > item['size']:
            raise GuestFault('memory_bounds')
        if pointer.address % alignment:
            raise GuestFault('memory_alignment')
        if write and not item['mutable']:
            raise GuestFault('memory_permission')
        if pointer.access_range is not None and not (
                pointer.access_range[0] <= pointer.address and pointer.address + size <= pointer.access_range[1]):
            raise GuestFault('ub_inrange_access', True)
        if lifetime_check and not all(item['active'][offset:offset + size]):
            raise GuestFault('memory_lifetime')
        return item, offset

    def expose(self, pointer):
        if pointer.origin in self.objects:
            self.exposed.add(pointer.origin)

    def integer_pointer(self, address, domain='data'):
        if domain == 'data':
            for identity in self.exposed:
                item = self.objects[identity]
                if item['live'] and item['address'] <= address <= item['address'] + item['size']:
                    return Pointer(address, identity, item['generation'])
        return Pointer(address, domain=domain)

    def offset(self, pointer, delta, inbounds, nuw, nusw, inrange=None, *, check_base=False):
        require(type(check_base) is bool and (not check_base or inbounds), 'pointer_check_base')
        mathematical = pointer.address + delta
        if (nuw and pointer.address + delta % 2**64 >= 2**64) or (
                (nusw or inbounds) and not 0 <= mathematical < 2**64):
            return None
        address = mathematical % 2**64
        access = pointer.access_range
        if inrange is not None:
            lower, upper = address + inrange['lower'], address + inrange['upper']
            if lower > upper:
                return None
            from candidate.ranges import intersect
            access = intersect(access, (lower, upper))
        result = Pointer(address, pointer.origin, pointer.generation, pointer.domain, access)
        if inbounds and (delta != 0 or check_base):
            item = self.objects.get(pointer.origin)
            if (item is None or item['generation'] != pointer.generation
                    or not item['address'] <= pointer.address <= item['address'] + item['size']
                    or not item['address'] <= result.address <= item['address'] + item['size']):
                return None
        return result

    def raw_load(self, pointer, size, alignment=1):
        item, offset = self.guard(pointer, size, alignment)
        require(size > 0 and size * 8 <= 2**23, 'reference_resource', 'raw load extent')
        return concat(item['bytes'][offset:offset + size])

    def raw_store(self, pointer, raw, alignment=1):
        require(raw.width % 8 == 0, 'raw_storage_width')
        item, offset = self.guard(pointer, raw.width // 8, alignment, write=True)
        item['bytes'][offset:offset + raw.width // 8] = [raw.slice(bit, 8) for bit in range(0, raw.width, 8)]

    def storage_bytes(self, value, layout_ref):
        layout = self.dependencies.layouts[key(layout_ref)]
        kind = self.types.get(value.type)['kind']
        children = self.types.components(value.type)
        if children is None:
            raw = raw_bits(self.types, value)
            extent = layout['access_bytes'] * 8
            if extent > raw.width:
                raw = concat([raw, Raw.integer(extent - raw.width, 0)])
            return [raw.slice(bit, 8) for bit in range(0, extent, 8)]
        # Padding is undef refined to zero at this dynamic store; field poison
        # and pointer origins remain exact and independently addressable.
        if layout['access_bytes'] == 0:
            return []
        result = Raw.integer(layout['access_bytes'] * 8, 0, undef=(1 << (layout['access_bytes'] * 8)) - 1)
        values = value.data if value.state == 'concrete' else [Value(child, value.state) for child in children]
        for index, child in enumerate(values):
            field = layout['fields'][index] if kind == 'struct' else None
            child_layout = field['layout'] if field is not None else optional(layout['element'])
            offset = field['bit_offset'] if field is not None else index * layout['stride']
            data = self.storage_bytes(child, child_layout)
            if not data:
                continue
            raw = concat(data)
            extent = field['bit_width'] if field is not None else (
                self.types.width(child.type) if kind == 'vector' else raw.width)
            require(offset + extent <= result.width, 'abi_storage_bounds')
            result = overwrite(result, offset, raw if raw.width == extent else raw.slice(0, extent))
        return [result.slice(bit, 8) for bit in range(0, result.width, 8)]

    def load_value(self, reference, layout_ref, raw):
        layout = self.dependencies.layouts[key(layout_ref)]
        children = self.types.components(reference)
        if children is None:
            width = self.types.width(reference)
            if raw.width > width:
                high = raw.slice(width, raw.width - width)
                if high.bits or high.poison:
                    return Value(reference, 'poison')
                raw = raw.slice(0, width)
            return from_raw(self.types, reference, raw)
        kind = self.types.get(reference)['kind']
        result = []
        for index, child in enumerate(children):
            field = layout['fields'][index] if kind == 'struct' else None
            child_layout = field['layout'] if field is not None else optional(layout['element'])
            spec = self.dependencies.layouts[key(child_layout)]
            offset = field['bit_offset'] if field is not None else index * layout['stride']
            extent = field['bit_width'] if field is not None else (
                self.types.width(child) if kind == 'vector' else 8 * spec['access_bytes'])
            if extent == 0:
                result.append(Value(child, 'concrete', ()))
                continue
            require(offset + extent <= raw.width, 'abi_storage_bounds')
            selected = raw.slice(offset, extent)
            if selected.width < 8 * spec['access_bytes']:
                selected = concat([selected, Raw.integer(8 * spec['access_bytes'] - selected.width, 0)])
            result.append(self.load_value(child, child_layout, selected))
        return Value(reference, 'concrete', tuple(result))

    def load(self, pointer, storage, mode):
        self.types.materializable(storage['type'])
        if storage.get('nominal') is not None:
            item, _ = self.guard(pointer, storage['bytes'], mode['alignment'])
            if not item['source_object']:
                raise GuestFault('source_object_binding')
        if storage['bytes'] == 0:
            self.guard(pointer, 0, mode['alignment'])
            return Value(storage['type'], 'concrete', ())
        raw = self.raw_load(pointer, storage['bytes'], mode['alignment'])
        return self.load_value(storage['type'], storage['layout'], raw)

    def store(self, pointer, value, storage, mode):
        self.types.materializable(value.type)
        # Materialize and validate the complete write before touching memory.
        item, offset = self.guard(pointer, storage['bytes'], mode['alignment'], write=True)
        if storage.get('nominal') is not None and not item['source_object']:
            raise GuestFault('source_object_binding')
        data = self.storage_bytes(value, storage['layout'])
        require(len(data) == storage['bytes'], 'abi_storage_extent')
        item['bytes'][offset:offset + len(data)] = data

    def bulk(self, operation, destination, source, count, alignment, volatile):
        if count == 0:
            return
        target, target_offset = self.guard(destination, count, alignment, write=True)
        if operation == 'memset':
            byte = source if isinstance(source, Raw) else Raw.integer(8, source & 255)
            require(byte.width == 8 and not byte.origins, 'memset_byte')
            data = [byte] * count
        else:
            origin, source_offset = self.guard(source, count, alignment)
            if (operation == 'memcpy' and origin is target and source_offset != target_offset and
                    max(target_offset, source_offset) < min(target_offset, source_offset) + count):
                raise GuestFault('ub_memcpy_overlap', True)
            data = list(origin['bytes'][source_offset:source_offset + count])
        target['bytes'][target_offset:target_offset + count] = data
        self.effects.append((operation, count, volatile))

    def end_lifetime(self, pointer):
        item, _ = self.guard(pointer, 0)
        item['live'] = False

    def lifetime(self, pointer, size, start):
        item, offset = self.guard(pointer, size, lifetime_check=False)
        item['active'][offset:offset + size] = [start] * size
        if start:
            item['bytes'][offset:offset + size] = [Raw.integer(8, 0, undef=255) for _ in range(size)]

    def restore(self, owner, sequence):
        for item in self.objects.values():
            if item['owner'] == owner and item['generation'] > sequence:
                item['live'] = False
