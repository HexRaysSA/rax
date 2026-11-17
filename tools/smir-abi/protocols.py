#!/usr/bin/env python3
"""Draft logical calls, canonical varargs and mixed-domain unwind reference states."""

from dataclasses import dataclass, replace
import struct

from layout import ABIError, MAX_OBJECT, align_up, alignment, integer, require

HEADER = struct.Struct('<IIQQQ')
VA_LIST = struct.Struct('<QQQQ')


def classify_signature(model, params, result=None, this=False, vtt=False,
                       variadic=False):
    """Classify adjusted source types, O(parameters + cached object layout)."""
    arguments = []
    results = []
    require(not vtt or this, 'ABI_VTT_WITHOUT_THIS')

    def mode(name, returning=False):
        model.layout(name)
        kind = model.types[name]['kind']
        require(kind not in ('array', 'atomic'), 'ABI_UNADJUSTED_PARAMETER')
        if kind in ('struct', 'union'):
            return 'sret' if returning else 'indirect-copy'
        return 'direct'

    if result is not None:
        result_mode = mode(result, returning=True)
        if result_mode == 'sret':
            arguments.append({'role': 'result', 'type': result, 'mode': 'sret'})
        else:
            results.append(result)
    if this:
        arguments.append({'role': 'this', 'type': 'data-pointer', 'mode': 'direct'})
    if vtt:
        arguments.append({'role': 'vtt', 'type': 'data-pointer', 'mode': 'direct'})
    for name in params:
        arguments.append({'role': 'parameter', 'type': name, 'mode': mode(name)})
    if variadic:
        arguments.append({'role': 'varargs', 'type': 'arena-pointer', 'mode': 'direct'})
    return {'arguments': arguments, 'results': results}


@dataclass(frozen=True)
class VarType:
    ref: int
    size: int
    align: int
    kind: str = 'aggregate'
    bits: int = 0
    pointer_kind: str = 'other'

    def check(self):
        integer(self.ref, 1, (1 << 32) - 1)
        integer(self.size, 1, MAX_OBJECT)
        alignment(self.align)
        require(self.size % self.align == 0, 'ABI_VARARG_TYPE')
        require(self.kind in ('signed', 'unsigned', 'float', 'pointer', 'aggregate'),
                'ABI_VARARG_TYPE')
        if self.kind in ('signed', 'unsigned'):
            integer(self.bits, 1, self.size * 8)
        if self.kind == 'pointer':
            require(self.size == 8 and self.align == 8 and
                    self.pointer_kind in ('void', 'char', 'other'), 'ABI_VARARG_TYPE')


def encode_varargs(entries, registry):
    """O(payload bytes + entries); temporary output never exposed on failure."""
    output = bytearray()
    for type_ref, payload in entries:
        require(type_ref in registry, 'ABI_VARARG_TYPE')
        item = registry[type_ref]
        item.check()
        require(item.ref == type_ref, 'ABI_VARARG_TYPE')
        require(isinstance(payload, bytes) and len(payload) == item.size,
                'ABI_VARARG_SIZE')
        if item.kind in ('signed', 'unsigned'):
            require(int.from_bytes(payload, 'little') < 1 << item.bits, 'ABI_VARARG_VALUE')
        begin = len(output)
        payload_at = align_up(begin + HEADER.size, item.align)
        next_offset = align_up(payload_at + item.size, 8)
        output.extend(HEADER.pack(type_ref, 0, item.size, item.align, next_offset))
        output.extend(bytes(payload_at - len(output)))
        output.extend(payload)
        output.extend(bytes(next_offset - len(output)))
    return bytes(output)


@dataclass
class VarArgs:
    area: int
    cursor: int
    limit: int
    cookie: int

    def encode(self):
        return VA_LIST.pack(self.area, self.cursor, self.limit, self.cookie)

    def copy(self):
        return replace(self)

    def end(self):
        self.area = self.cursor = self.limit = self.cookie = 0

    def arg(self, expected, arena, registry, *, thread, leases):
        # thread is the ORIGINAL cookie owner's ID, resolved by the runtime
        # helper, not necessarily the executing visitor. leases is the process
        # active-owner registry: (owner thread ID, arena token, byte length).
        require(self.cookie != 0 and leases.get(self.cookie) ==
                (thread, self.area, self.limit), 'ABI_VARARG_LIFETIME')
        integer(self.area, 1, (1 << 64) - 1, 'ABI_VARARG_BOUNDS')
        integer(self.limit, 0, MAX_OBJECT, 'ABI_VARARG_BOUNDS')
        require(self.area + self.limit <= 1 << 64, 'ABI_VARARG_BOUNDS')
        require(len(arena) == self.limit and self.cursor % 8 == 0 and
                0 <= self.cursor <= self.limit - HEADER.size, 'ABI_VARARG_BOUNDS')
        ref, reserved, size, align, next_offset = HEADER.unpack_from(arena, self.cursor)
        require(reserved == 0, 'ABI_VARARG_RESERVED')
        require(ref in registry and expected in registry, 'ABI_VARARG_TYPE')
        actual_type, requested = registry[ref], registry[expected]
        actual_type.check()
        requested.check()
        require(actual_type.ref == ref and requested.ref == expected, 'ABI_VARARG_TYPE')
        require((size, align) == (actual_type.size, actual_type.align), 'ABI_VARARG_SIZE')
        require(self.area % align == 0, 'ABI_VARARG_ALIGNMENT')
        payload_at = align_up(self.cursor + HEADER.size, align)
        canonical_next = align_up(payload_at + size, 8)
        require(next_offset == canonical_next <= self.limit, 'ABI_VARARG_BOUNDS')
        require(not any(arena[self.cursor + HEADER.size:payload_at]) and
                not any(arena[payload_at + size:next_offset]), 'ABI_VARARG_PADDING')
        payload = arena[payload_at:payload_at + size]
        if actual_type.kind in ('signed', 'unsigned'):
            require(int.from_bytes(payload, 'little') < 1 << actual_type.bits, 'ABI_VARARG_VALUE')
        compatible = ref == expected
        same_integer = ({actual_type.kind, requested.kind} == {'signed', 'unsigned'} and
                        (actual_type.size, actual_type.align, actual_type.bits) ==
                        (requested.size, requested.align, requested.bits))
        if same_integer:
            # Corresponding signed/unsigned va_arg exception: value is in both
            # ranges iff its sign bit is clear, ignoring storage padding.
            bits = actual_type.bits
            value = int.from_bytes(payload, 'little') & ((1 << bits) - 1)
            compatible = value < 1 << (bits - 1)
        if actual_type.kind == requested.kind == 'pointer':
            compatible = compatible or {actual_type.pointer_kind, requested.pointer_kind} == {
                'void', 'char'}
        require(compatible, 'ABI_VARARG_TYPE_MISMATCH')
        self.cursor = next_offset
        return payload


class Transitions:
    """Per-thread LIFO with continuation generation and lease accounting.

    O(depth) worst case on nonlocal abandonment, O(1) enter/leave. This is a
    sequential protocol witness, not a parallel-runtime or native-EH test.
    """

    def __init__(self):
        self.stacks = {}
        self.leases = {}
        self.next_id = 1

    def enter(self, thread, source, target, modules):
        require(source != target, 'ABI_TRANSITION_DOMAIN')
        stack = self.stacks.setdefault(thread, [])
        require(not stack or stack[-1]['target'] == source, 'ABI_TRANSITION_CHAIN')
        record = {'id': self.next_id, 'source': source, 'target': target,
                  'modules': tuple(modules)}
        self.next_id += 1
        for module in record['modules']:
            self.leases[module] = self.leases.get(module, 0) + 1
        stack.append(record)
        return record['id']

    def leave(self, thread, continuation):
        stack = self.stacks.get(thread, [])
        require(stack and stack[-1]['id'] == continuation, 'ABI_STALE_CONTINUATION')
        record = stack.pop()
        for module in record['modules']:
            self.leases[module] -= 1
        return record

    def abandon(self, thread, keep_depth):
        stack = self.stacks.get(thread, [])
        integer(keep_depth, 0, len(stack))
        while len(stack) > keep_depth:
            self.leave(thread, stack[-1]['id'])


class ExceptionState:
    """Two-phase logical event model, innermost frame first, O(frame count).

    Handler predicates/cleanup names are externally admitted metadata. Search
    performs no cleanups. This does not decode DWARF/SEH or execute destructors.
    """

    def __init__(self, owner, type_identity, frames, references=1):
        self.owner = owner
        self.type_identity = type_identity
        self.frames = frames
        self.references = references
        self.phase = 'raised'
        self.handler = None
        self.events = []
        self.destroyed = False
        self.forced = False
        self.noexcept = False

    def search(self, *, forced=False):
        require(self.phase == 'raised' and not self.destroyed, 'ABI_UNWIND_PHASE')
        self.events.append(('search',))
        self.forced = forced
        for index, frame in enumerate(self.frames):
            if frame.get('metadata') is not True:
                raise ABIError('ABI_UNWIND_METADATA')
            if not forced and (frame.get('catch') == '*' or
                               self.type_identity is not None and
                               frame.get('catch') == self.type_identity):
                self.handler = index
                break
            if frame.get('escape') == 'terminate':
                self.noexcept = True
                break
        self.phase = 'searched'
        return self.handler

    def cleanup(self, *, throwing_cleanup=None):
        require(self.phase == 'searched', 'ABI_UNWIND_PHASE')
        if self.noexcept or self.handler is None and not self.forced:
            # C++ unhandled-exception policy: terminate after search; do not
            # claim platform-specific unwinding before termination.
            self.phase = 'terminated'
            self.events.append(('terminate', 'noexcept' if self.noexcept else 'unhandled'))
            return
        traversed = self.frames if self.forced else self.frames[:self.handler + 1]
        for index, frame in enumerate(traversed):
            path = frame.get('handler_cleanups', []) if index == self.handler else frame.get('cleanups', [])
            for cleanup in path:
                self.events.append(('cleanup', index, cleanup))
                if cleanup == throwing_cleanup:
                    self.phase = 'terminated'
                    self.events.append(('terminate', 'cleanup-throw'))
                    return
        self.phase = 'forced-exit' if self.forced else 'caught'
        self.events.append(('forced-exit',) if self.forced else ('catch', self.handler))

    def rethrow(self, continuation_frames):
        require(self.phase == 'caught' and not self.destroyed, 'ABI_UNWIND_PHASE')
        # The source adapter supplies the precise active regions after the
        # rethrow, including remaining catch-scope cleanups. Do not infer them
        # by discarding a whole physical frame.
        require(isinstance(continuation_frames, list), 'ABI_UNWIND_METADATA')
        self.frames = continuation_frames
        self.handler = None
        self.noexcept = False
        self.phase = 'raised'
        self.events.append(('rethrow',))

    def retain(self):
        require(not self.destroyed, 'ABI_EXCEPTION_LIFETIME')
        self.references += 1

    def release(self):
        require(self.references > 0 and not self.destroyed, 'ABI_EXCEPTION_LIFETIME')
        require(self.references > 1 or self.phase in ('caught', 'terminated', 'forced-exit'),
                'ABI_EXCEPTION_ACTIVE')
        self.references -= 1
        if self.references == 0:
            self.destroyed = True
            self.events.append(('destroy', self.owner))
