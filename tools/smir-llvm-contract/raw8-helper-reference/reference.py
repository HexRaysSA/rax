"""UNBOUND native per-bit helper reference; no source or callable authority."""
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / 'schema.json'
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
COMPILER = '192ac975b062d522570b5f7bd06a235a1918f7c0a0d66f70df2eecdd628d24b7'
MAX_INPUT, MAX_OUTPUT, MAX_STDERR = 32768, 262144, 65536
TIMEOUT = 10
_SECRET = object()


class HelperError(ValueError):
    def __init__(self, kind, code, detail=''):
        self.kind, self.code, self.detail = kind, code, detail
        super().__init__(code + ': ' + detail)


def need(condition, code='RAW_REFERENCE_INPUT', kind='semantic'):
    if not condition:
        raise HelperError(kind, code)


def foundation():
    override = os.environ.get('SMIR_RAW8_REFERENCE_PROJECT')
    if override is not None:
        need(type(override) is str and Path(override).is_absolute(), 'RAW_REFERENCE_FOUNDATION', 'unavailable')
        root = Path(override).resolve()
    elif HERE.name == 'smir-llvm-contract' and HERE.parent.name == 'tools':
        root = HERE.parent.parent
    elif HERE.name == 'raw8-helper-reference' and HERE.parent.name == 'smir-llvm-contract' and HERE.parent.parent.name == 'tools':
        root = HERE.parent.parent.parent
    else:
        raise HelperError('unavailable', 'RAW_REFERENCE_FOUNDATION', 'draft requires explicit SMIR_RAW8_REFERENCE_PROJECT')
    need((root / 'tools/smir-format/execution/candidate/raw.py').is_file()
         and (root / 'tools/smir-runtime-contract/source_roles/source_data.py').is_file(),
         'RAW_REFERENCE_FOUNDATION', 'unavailable')
    return root


PROJECT = foundation()
EXECUTION = PROJECT / 'tools/smir-format/execution'
for name, module in tuple(sys.modules.items()):
    if name == 'candidate' or name.startswith('candidate.'):
        file = getattr(module, '__file__', None)
        need(file is not None and Path(file).resolve().is_relative_to(EXECUTION.resolve()),
             'RAW_REFERENCE_FOREIGN_CANDIDATE', 'unavailable')
if str(EXECUTION) not in sys.path:
    sys.path.insert(0, str(EXECUTION))
from candidate.raw import Raw, concat
from candidate.memory import Memory
from candidate.type_system import Types
from candidate.values import Pointer
for name in ('candidate.raw', 'candidate.memory', 'candidate.type_system', 'candidate.values'):
    need(Path(sys.modules[name].__file__).resolve() == (EXECUTION / Path(*name.split('.'))).with_suffix('.py').resolve(),
         'RAW_REFERENCE_FOREIGN_CANDIDATE', 'unavailable')


def source_api():
    name = '_rax_smir_source_data_v1'
    path = PROJECT / 'tools/smir-runtime-contract/source_roles/source_data.py'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    module = sys.modules[name]
    need(Path(module.__file__).resolve() == path.resolve(), 'RAW_REFERENCE_BUDGET')
    return module


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def strict_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            need(name not in result)
            result[name] = value
        return result
    def reject(value):
        raise HelperError('semantic', 'RAW_REFERENCE_INPUT', 'noninteger JSON')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    except (ValueError, UnicodeError) as error:
        if isinstance(error, HelperError):
            raise
        raise HelperError('semantic', 'RAW_REFERENCE_INPUT', 'JSON') from error


def same(left, right):
    return type(left) is type(right) and left == right


def plain(value, depth=0):
    need(depth <= 32, 'RAW_REFERENCE_RESOURCE', 'resource')
    if type(value) is dict:
        need(all(type(k) is str for k in value))
        return 1 + sum(plain(k, depth + 1) + plain(v, depth + 1) for k, v in value.items())
    if type(value) is list:
        return 1 + sum(plain(v, depth + 1) for v in value)
    need(type(value) in (str, int, bool, type(None)))
    need(type(value) is not str or len(value) <= MAX_INPUT)
    return 1


def validate(rule, value, definitions):
    if '$ref' in rule:
        return validate(definitions[rule['$ref'].rsplit('/', 1)[-1]], value, definitions)
    for child in rule.get('allOf', []):
        validate(child, value, definitions)
    if 'oneOf' in rule:
        passed = 0
        for child in rule['oneOf']:
            try:
                validate(child, value, definitions)
                passed += 1
            except HelperError:
                pass
        need(passed == 1)
    if 'const' in rule:
        need(same(value, rule['const']))
    if 'enum' in rule:
        need(any(same(value, item) for item in rule['enum']))
    kind = rule.get('type')
    if kind == 'object':
        need(type(value) is dict and all(type(k) is str for k in value))
        need(set(rule.get('required', [])) <= value.keys())
        props = rule.get('properties', {})
        need(rule.get('additionalProperties', True) or value.keys() <= props.keys())
        for name, child in value.items():
            if name in props:
                validate(props[name], child, definitions)
    elif kind == 'array':
        need(type(value) is list and rule.get('minItems', 0) <= len(value) <= rule.get('maxItems', 8192))
        for child in value:
            validate(rule['items'], child, definitions)
    elif kind == 'integer':
        need(type(value) is int and rule.get('minimum', 0) <= value <= rule.get('maximum', (1 << 64) - 1))
    elif kind == 'string':
        need(type(value) is str and len(value) <= rule.get('maxLength', MAX_INPUT))
        if 'pattern' in rule:
            need(re.fullmatch(rule['pattern'], value) is not None)
    elif kind == 'boolean':
        need(type(value) is bool)
    elif kind == 'null':
        need(value is None)
    if kind is None and 'properties' in rule:
        need(type(value) is dict)
        for name, child in rule['properties'].items():
            if name in value:
                validate(child, value[name], definitions)


def bounded_digest(path, size):
    total, remaining = 0, size + 1
    digest = hashlib.sha256()
    with path.open('rb', buffering=0) as stream:
        while remaining:
            requested = min(1 << 20, remaining)
            data = stream.read(requested)
            total += len(data)
            remaining -= len(data)
            digest.update(data)
            if len(data) < requested:
                break
    return digest.hexdigest() if total == size else None


def child(command, request):
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC'}
    with tempfile.TemporaryDirectory(prefix='smir-raw8-reference-') as working:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=working, env=environment)
        stdout, stderr, pending = bytearray(), bytearray(), memoryview(request)
        poll = selectors.DefaultSelector()
        for stream, event in ((process.stdin, selectors.EVENT_WRITE), (process.stdout, selectors.EVENT_READ),
                              (process.stderr, selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False)
            poll.register(stream, event)
        deadline = time.monotonic() + TIMEOUT
        try:
            while poll.get_map():
                left = deadline - time.monotonic()
                need(left > 0, 'RAW_REFERENCE_RESOURCE', 'resource')
                for key, event in poll.select(min(left, 0.1)):
                    stream = key.fileobj
                    if stream is process.stdin:
                        if not pending:
                            poll.unregister(stream)
                            stream.close()
                            continue
                        try:
                            sent = os.write(stream.fileno(), pending[:65536])
                            pending = pending[sent:]
                        except BrokenPipeError:
                            poll.unregister(stream)
                            stream.close()
                    else:
                        limit = MAX_OUTPUT if stream is process.stdout else MAX_STDERR
                        current = len(stdout) if stream is process.stdout else len(stderr)
                        data = os.read(stream.fileno(), min(65536, limit - current + 1))
                        if not data:
                            poll.unregister(stream)
                            stream.close()
                            continue
                        target = stdout if stream is process.stdout else stderr
                        limit = MAX_OUTPUT if stream is process.stdout else MAX_STDERR
                        need(len(target) + len(data) <= limit, 'RAW_REFERENCE_RESOURCE', 'resource')
                        target.extend(data)
            status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return status, bytes(stdout), bytes(stderr)
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
        finally:
            poll.close()
            for stream in (process.stdin, process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()


@dataclass(frozen=True, eq=False)
class ReferenceRef:
    owner: object
    serial: int
    kind: str
    record: object
    token: object


@dataclass(frozen=True, eq=False)
class ReferenceEvent:
    owner: object
    serial: int
    epoch: int
    payload: bytes
    token: object


class ReferenceSession:
    _PUBLIC_FIXED = frozenset(('budget','max_events','binary','receipt','epoch','serial','refs','events',
                              'pointers','objects','native_calls','attempts','paths','expected','snapshots'))
    _PRIVATE_FIXED = frozenset(('_original_budget','_max_events','_binary','_receipt','_epoch','_serial',
                               '_refs','_events','_pointers','_objects','_native_calls','_attempts',
                               '_paths','_expected','_snapshots','_schema','_api'))

    def __setattr__(self, name, value):
        if name in self._PUBLIC_FIXED or name in self._PRIVATE_FIXED and hasattr(self, name):
            raise AttributeError('immutable reference session binding')
        object.__setattr__(self, name, value)

    budget = property(lambda self: self._original_budget)
    max_events = property(lambda self: self._max_events)
    binary = property(lambda self: self._binary)
    receipt = property(lambda self: self._receipt)
    epoch = property(lambda self: self._epoch)
    serial = property(lambda self: self._serial)
    native_calls = property(lambda self: self._native_calls)
    attempts = property(lambda self: self._attempts)
    refs = property(lambda self: MappingProxyType(self._refs))
    events = property(lambda self: MappingProxyType(self._events))
    pointers = property(lambda self: tuple(self._pointers))
    objects = property(lambda self: tuple(self._objects))
    paths = property(lambda self: frozenset(self._paths))
    expected = property(lambda self: MappingProxyType(self._expected))
    snapshots = property(lambda self: MappingProxyType(self._snapshots))
    def __init__(self, binary, receipt, *, budget, max_events=4096):
        self._api = source_api()
        need(type(budget) is self._api.SourceQueryBudget, 'RAW_REFERENCE_BUDGET')
        need(type(binary) is type(HERE) and type(receipt) is type(HERE))
        need(type(max_events) is int and 0 < max_events <= 65536)
        self._original_budget, self._max_events = budget, max_events
        self._binary, self._receipt = binary.resolve(), receipt.resolve()
        self._epoch, self._serial, self._refs, self._events = 1, 0, {}, {}
        self._pointers, self._objects = [], []
        self._native_calls, self._attempts = 0, 0
        size = self._receipt.stat().st_size
        need(0 <= size <= 4 << 20, 'RAW_REFERENCE_RESOURCE', 'resource')
        budget.charge(work=4 * size + 16, copied_bytes=4 * size + 16)
        with self._receipt.open('rb', buffering=0) as stream:
            raw = stream.read(size + 1)
        need(len(raw) == size, 'RAW_REFERENCE_CHANGED')
        build = strict_json(raw)
        need(type(build) is dict and type(build.get('exit')) is int and build['exit'] == 0
             and build.get('drift') == [] and build.get('llvm_pin') == PIN
             and PIN in build.get('compiler_version', ''))
        originals = build.get('input_hashes')
        need(type(originals) is dict and len(originals) <= 4096)
        need(build['binary']['path'] == str(self._binary))
        cpp, builder = HERE / 'raw8_reference.cpp', HERE / 'build.py'
        need(str(cpp) in originals and str(builder) in originals)
        self._paths = {self._binary, self._receipt, cpp, builder, HERE / 'reference.py', SCHEMA_PATH,
                      Path(sys.executable).resolve(), PROJECT / 'tools/smir-runtime-contract/source_roles/source_data.py'}
        self._expected = {self._binary: build['binary']['sha256'], cpp: originals[str(cpp)], builder: originals[str(builder)], self._receipt: hashlib.sha256(raw).hexdigest()}
        for name, expected in originals.items():
            if name.endswith(('.dylib', '.so')) or '.so.' in name:
                path = Path(name).resolve()
                self._paths.add(path)
                self._expected[path] = expected
        self._snapshots = {}
        initial_sizes = {path: path.stat().st_size for path in self._paths}
        total = sum(size + 1 for size in initial_sizes.values())
        budget.charge(work=(2 * max_events + 3) * total + 64 * MAX_INPUT,
                      copied_bytes=(2 * max_events + 3) * total + 8 * MAX_INPUT, edges=4 * len(initial_sizes))
        for path in sorted(self._paths):
            size = initial_sizes[path]
            digest = bounded_digest(path, size)
            need(digest is not None and (path not in self._expected or digest == self._expected[path]), 'RAW_REFERENCE_CHANGED')
            self._snapshots[path] = (size, digest)
        schema_path = SCHEMA_PATH
        schema_size = self._snapshots[schema_path][0]
        with schema_path.open('rb', buffering=0) as stream:
            schema_raw = stream.read(schema_size + 1)
        need(len(schema_raw) == schema_size, 'RAW_REFERENCE_CHANGED')
        self._schema = strict_json(schema_raw)

    def _check_budget(self, budget):
        need(budget is self._original_budget and type(budget) is self._api.SourceQueryBudget, 'RAW_REFERENCE_BUDGET')
        need(self._epoch == 1, 'RAW_REFERENCE_EPOCH')

    def _reserve_operation(self):
        # All before/after guard scans for max_events+1 attempts were prepaid
        # during session construction. Even a canonical quota failure here is
        # followed by a bounded captured-size guard scan.
        self._original_budget.charge(work=64 * MAX_INPUT + 8 * MAX_OUTPUT, edges=8192,
                           copied_bytes=8 * MAX_INPUT + 4 * MAX_OUTPUT + 4 * MAX_STDERR)

    def _label(self, value):
        if value is None:
            return None
        for index, previous in enumerate(self._objects):
            if type(previous) is type(value) and previous == value:
                return index + 1
        need(len(self._objects) < 1024, 'RAW_REFERENCE_RESOURCE', 'resource')
        self._objects.append(value)
        return len(self._objects)

    @staticmethod
    def bounds(value):
        if value is None:
            return None
        from candidate.ranges import normalize, EMPTY
        need(type(value) is tuple and normalize(value) == value, 'RAW_REFERENCE_RANGE_UNAVAILABLE', 'unavailable')
        if value == EMPTY:
            return dict(lower='0' * 16, upper='0' * 16, upper_is_limit=False, empty=True)
        lower, upper = value
        return dict(lower=f'{lower:016x}', upper='0' * 16 if upper == 1 << 64 else f'{upper:016x}',
                    upper_is_limit=upper == 1 << 64, empty=False)

    def _origin(self, pointer):
        need(type(pointer) is Pointer)
        for index, previous in enumerate(self._pointers):
            if previous is pointer:
                return index + 1
        need(len(self._pointers) < 128, 'RAW_REFERENCE_RESOURCE', 'resource')
        self._pointers.append(pointer)
        return len(self._pointers)

    def origins(self):
        result = []
        for index, pointer in enumerate(self._pointers):
            result.append(dict(id=index + 1, bits=f'{pointer.address:016x}', identity=self._label(pointer.origin),
                generation=f'{pointer.generation:016x}', domain=pointer.domain, range=self.bounds(pointer.access_range),
                permit=self._label(pointer.permit), lineage=self._label(pointer.lineage), authority=self._label(pointer.authority)))
        return result

    def raw_record(self, value):
        need(type(value) is Raw and value.width in (8, 64), 'RAW_REFERENCE_WIDTH_UNAVAILABLE', 'unavailable')
        return dict(width=value.width, bits=f'{value.bits:016x}', poison=f'{value.poison:016x}', undef=f'{value.undef:016x}',
                    origins=[dict(offset=x.offset, length=x.length, origin=self._origin(x.pointer), source=x.source) for x in value.origins])

    def _new_ref(self, kind, record):
        serial = len(self._refs) + 1
        need(serial <= 4096, 'RAW_REFERENCE_RESOURCE', 'resource')
        result = ReferenceRef(self, serial, kind, canonical(record), _SECRET)
        self._refs[serial] = result
        return result

    def capture_raw(self, value, *, budget):
        self._check_budget(budget)
        budget.charge(work=1 << 20, edges=8192, copied_bytes=1 << 18)
        record = self.raw_record(value)
        return self._new_ref('raw', record)

    def capture_pointer(self, pointer, *, budget):
        self._check_budget(budget)
        budget.charge(work=1 << 20, edges=8192, copied_bytes=1 << 18)
        need(type(pointer) is Pointer)
        record = dict(object=self._label(pointer.origin), address=f'{pointer.address:016x}',
                      generation=f'{pointer.generation:016x}', domain='data' if pointer.domain == 'data' else 'other',
                      range=self.bounds(pointer.access_range))
        return self._new_ref('access', record)

    def capture_memory(self, memory, pointer, *, budget):
        self._check_budget(budget)
        budget.charge(work=1 << 20, edges=8192, copied_bytes=1 << 18)
        need(type(memory) is Memory and type(pointer) is Pointer and pointer.origin in memory.objects)
        row = memory.objects[pointer.origin]
        need(0 <= row['size'] <= 64, 'RAW_REFERENCE_MEMORY_UNAVAILABLE', 'unavailable')
        record = dict(object=self._label(pointer.origin), base=f"{row['address']:016x}", generation=f"{row['generation']:016x}",
                      live=row['live'], mutable=row['mutable'], active=list(row['active']),
                      bytes=[self.raw_record(concat([value])) for value in row['bytes']])
        return self._new_ref('memory', record)

    def _ref(self, ref, kind):
        need(type(ref) is ReferenceRef and ref.owner is self and ref.token is _SECRET
             and self._refs.get(ref.serial) is ref and ref.kind == kind, 'RAW_REFERENCE_HANDLE')
        return strict_json(ref.record)

    def evaluate(self, operation, arguments, *, budget):
        self._check_budget(budget)
        need(self._attempts <= self._max_events, 'RAW_REFERENCE_CLOSED')
        object.__setattr__(self, '_attempts', self._attempts + 1)
        error, result = None, None
        try:
            self._reserve_operation()
            need(self._attempts <= self._max_events, 'RAW_REFERENCE_RESOURCE', 'resource')
        except BaseException as caught:
            error = caught
        if error is not None:
            drift = self._drift()
            if drift:
                raise HelperError('semantic', 'RAW_REFERENCE_CHANGED', ';'.join(drift)[:4096]) from error
            raise error
        return self._evaluate_reserved(operation, arguments)

    def _evaluate_reserved(self, operation, arguments):
        need(type(operation) is str and type(arguments) is dict and all(type(k) is str for k in arguments))
        need(self._serial < self._max_events, 'RAW_REFERENCE_RESOURCE', 'resource')
        arguments = dict(arguments)
        for name in ('value', 'memory', 'pointer'):
            if name in arguments:
                arguments[name] = self._ref(arguments[name], {'value': 'raw', 'memory': 'memory', 'pointer': 'access'}[name])
        if 'values' in arguments:
            need(type(arguments['values']) is tuple and len(arguments['values']) == 8)
            arguments['values'] = [self._ref(x, 'raw') for x in arguments['values']]
        error, result = None, None
        try:
            for path, (size, digest) in self._snapshots.items():
                need(bounded_digest(path, size) == digest, 'RAW_REFERENCE_CHANGED')
            request = dict(format='smir-raw8-helper-request', revision=1, operation=operation,
                           origins=self.origins(), arguments=arguments)
            need(plain(request) <= 8192, 'RAW_REFERENCE_RESOURCE', 'resource')
            validate(self._schema['$defs']['request'], request, self._schema['$defs'])
            raw = canonical(request)
            need(len(raw) <= MAX_INPUT, 'RAW_REFERENCE_RESOURCE', 'resource')
            object.__setattr__(self, '_native_calls', self._native_calls + 1)
            status, stdout, stderr = child([str(self._binary)], raw)
            need(status in (0, 2, 3) and stdout, 'RAW_REFERENCE_PROTOCOL', 'unavailable')
            response = strict_json(stdout)
            validate(self._schema['$defs']['response'], response, self._schema['$defs'])
            need(response['operation'] == operation, 'RAW_REFERENCE_PROTOCOL', 'unavailable')
            if response['status'] != 'ok':
                need(status == (3 if response['status'] == 'trap' else 2), 'RAW_REFERENCE_PROTOCOL', 'unavailable')
                raise HelperError(response['status'], response['code'])
            need(status == 0 and response['code'] == '', 'RAW_REFERENCE_PROTOCOL', 'unavailable')
            validate(self._schema['$defs']['operation_results'][operation], response['result'], self._schema['$defs'])
            result = canonical(response)
        except BaseException as caught:
            error = caught
        drift = []
        for path, (size, digest) in self._snapshots.items():
            try:
                if bounded_digest(path, size) != digest:
                    drift.append(str(path))
            except OSError:
                drift.append(str(path))
        if drift:
            changed = HelperError('semantic', 'RAW_REFERENCE_CHANGED', ';'.join(drift)[:4096])
            if error is not None:
                raise changed from error
            raise changed
        if error is not None:
            raise error
        object.__setattr__(self, '_serial', self._serial + 1)
        event = ReferenceEvent(self, self._serial, self._epoch, result, _SECRET)
        self._events[event.serial] = event
        return event

    def _drift(self):
        changed = []
        for path, (size, digest) in self._snapshots.items():
            try:
                if bounded_digest(path, size) != digest:
                    changed.append(str(path))
            except OSError:
                changed.append(str(path))
        return changed

    def result(self, event, *, budget):
        self._check_budget(budget)
        need(type(event) is ReferenceEvent and event.owner is self and event.token is _SECRET
             and event.epoch == self._epoch and self._events.get(event.serial) is event, 'RAW_REFERENCE_EVENT')
        budget.charge(work=4 * len(event.payload) + 16, copied_bytes=4 * len(event.payload) + 16)
        return strict_json(event.payload)['result']

    def raw_results(self, event, *, budget):
        result = self.result(event, budget=budget)
        values = result if type(result) is list else [result]
        need(all(type(v) is dict and 'width' in v for v in values))
        budget.charge(work=65536, copied_bytes=65536, edges=128)
        return tuple(self._new_ref('raw', value) for value in values)

    def expire(self):
        object.__setattr__(self, '_epoch', self._epoch + 1)
