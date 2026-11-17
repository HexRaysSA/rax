"""Pinned native source-category reference observations, never source facts.

Draft observer01..04 and CPP07. Native parsing, build/guard IO and logical byte
charges are explicit; none establish ABI, runtime or source-body admission.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors as io_selectors
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parents[1]
PROJECT = Path(os.environ.get('SMIR_BYTE_REFERENCE_PROJECT', str(PACKAGE))).resolve()
SCHEMA = PACKAGE / 'docs/specifications/smir/portable/llvm/source-byte-category.schema.json'
TARGET = PROJECT / 'docs/specifications/smir/portable/llvm/target.json'
REQUEST_SCHEMA = PROJECT / 'docs/specifications/smir/portable/llvm/request.schema.json'
SOURCE_API = PROJECT / 'tools/smir-runtime-contract/source_roles/source_data.py'
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
COMPILER = '192ac975b062d522570b5f7bd06a235a1918f7c0a0d66f70df2eecdd628d24b7'
U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
MAX_REQUEST = 4 << 20
MAX_SOURCE = 1 << 20
MAX_OUTPUT = 16 << 20
MAX_STDERR = 64 << 10
NATIVE_TIMEOUT_SECONDS = 30
CODES = {
    'BYTE_OBSERVATION_INPUT': 'semantic',
    'BYTE_OBSERVATION_BUDGET_REFERENCE': 'semantic',
    'BYTE_OBSERVATION_LOCATION': 'semantic',
    'BYTE_OBSERVATION_SOURCE_REJECTED': 'semantic',
    'BYTE_OBSERVATION_CHANGED': 'semantic',
    'BYTE_OBSERVATION_RECIPE_UNAVAILABLE': 'unavailable',
    'BYTE_OBSERVATION_LIBRARY_UNAVAILABLE': 'unavailable',
    'BYTE_OBSERVATION_LAYOUT_UNAVAILABLE': 'unavailable',
    'BYTE_OBSERVATION_ORACLE_UNAVAILABLE': 'unavailable',
    'BYTE_OBSERVATION_ORACLE_PROTOCOL': 'unavailable',
    'BYTE_OBSERVATION_RESOURCE': 'resource',
}
PROTECTED = {'__DATE__', '__TIME__', '__TIMESTAMP__'}
FLAGS = {'exceptions', 'rtti', 'plain_char', 'wchar_bits', 'wchar_signed', 'short_enums',
         'ms_compatibility', 'fp_contract', 'fast_math', 'signed_overflow',
         'threadsafe_statics', 'diagnostics', 'input_encoding', 'execution_encoding'}
# Exact actual reference libc++ closure, including generated native config.
# This is observational, never the portable sysroot.
LIBRARY_FILES = {'generated/__config_site': 'b2390ef3fc9b74ee8aa730c0b612b00cddc9346208098b2a245500706805956d', 'libcxx/__config': '2d816b84b93cebdfd5ac525ebe09709ee682e60afa0f1990f952f88ef06bcd87', 'libcxx/__configuration/abi.h': '0a95750aeb0466a50b5299f7f1b8e5fc18832d6ff03f5b906afcd26f1fba819c', 'libcxx/__configuration/attributes.h': '2ac230826dd377f18675659a8fdc2d55eb9cd4e19198c0e498d2805b684aca9e', 'libcxx/__configuration/availability.h': '400194d608079ea282bb1aefd50490447059c63a7bf6530c63ed776e95653d10', 'libcxx/__configuration/compiler.h': 'a3992ab89b80e285794350c2313980113d7fb0354a9f8fa49e4643cbc6ec6ed7', 'libcxx/__configuration/diagnostic_suppression.h': '331c70679841603599159bbe0d72fdf2ada6956a9a4ec58ab2560a0df2ce1d17', 'libcxx/__configuration/experimental.h': '591854d7040d9f0cf672ebb5c85d7b9ddd0daab7bc18286a3dff8eaa7024da53', 'libcxx/__configuration/hardening.h': '0e9d4d396a3b86bc0567b0fca03937f43b9c06bd770b66aec8342c39c4b18230', 'libcxx/__configuration/language.h': '42e6f59c706687d14dbdb5aa31a4238287f9e4deebb4c31600336db9b177b2e4', 'libcxx/__configuration/namespace.h': 'a951d1033bcc6175196c84bc7128a3eaabaf2383809650fb64756b722d8d591b', 'libcxx/__configuration/platform.h': 'c5082606d2a83ac238390ecdef46eecf17e57afff1d39a8fe602da875e9552cf', 'libcxx/__configuration/pstl.h': '9f5af4a5251a6a6364a3c0d783faccaf1b56464579fbe593b886f95c89cae91c', 'libcxx/__configuration/utility.h': 'fc0bdb0b17b4c1d3eafd2406b2297af9bffda5aeb91f8ad34defef806e589784', 'libcxx/__cstddef/byte.h': 'b4e4f7dbb20ba21e4e3a622c206b6e1d365da83d8abb086181704b67e4587aa7', 'libcxx/__fwd/byte.h': '4465d56f10be4ac0340d502ad34f4a6f772a194d08e981eadcffcea91f138670', 'libcxx/__type_traits/enable_if.h': 'e1146435700e53985c2ddf9b6218dd3ad6c71743688a1ee037881b68447de4ca', 'libcxx/__type_traits/integral_constant.h': '8db17b59c60be68ba58883596a96799ac924196a6c25805ba2d0680c2f146c96', 'libcxx/__type_traits/is_integral.h': '1519de36ca5d6edf62871b2c080a91065f460ea48e6af38daeb5b1aaa9865d86', 'libcxx/__type_traits/remove_cv.h': '76d2bcf641580f423c25d50b16088ee8cb880d20f80a511f1ffe03483035b7cf'}



class ByteObservationError(ValueError):
    __slots__ = ('_kind', '_code', '_detail')

    def __init__(self, kind, code, detail=''):
        if hasattr(self, '_kind') or type(kind) is not str or type(code) is not str or type(detail) is not str or CODES.get(code) != kind:
            raise ValueError('invalid ByteObservationError construction')
        object.__setattr__(self, '_kind', kind)
        object.__setattr__(self, '_code', code)
        object.__setattr__(self, '_detail', detail)
        super().__init__(code + (': ' + detail if detail else ''))

    def __setattr__(self, key, value):
        if key in ('_kind', '_code', '_detail', 'kind', 'code', 'detail'):
            raise AttributeError('immutable byte-observation diagnostic')
        return super().__setattr__(key, value)

    kind = property(lambda self: self._kind)
    code = property(lambda self: self._code)
    detail = property(lambda self: self._detail)


def fail(code, detail=''):
    raise ByteObservationError(CODES[code], code, detail)


def need(condition, code='BYTE_OBSERVATION_INPUT', detail=''):
    if not condition:
        fail(code, detail)


def source_api():
    name = '_rax_smir_source_data_v1'
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, SOURCE_API)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
    need(getattr(module, '__file__', None) is not None and Path(module.__file__).resolve() == SOURCE_API.resolve(),
         'BYTE_OBSERVATION_BUDGET_REFERENCE')
    return module


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def bounded_guard_digest(path, captured_size):
    """Read at most the prepaid snapshot size plus one growth sentinel."""
    remaining = captured_size + 1
    observed = 0
    h = hashlib.sha256()
    with Path(path).open('rb', buffering=0) as stream:
        while remaining:
            requested = min(1 << 20, remaining)
            block = stream.read(requested)
            observed += len(block)
            remaining -= len(block)
            h.update(block)
            if len(block) < requested:
                break
    return h.hexdigest() if observed == captured_size else None


def strict_json(raw, budget, *, canonical_required=True, maximum=MAX_REQUEST):
    need(type(raw) is bytes, detail='JSON bytes required')
    need(len(raw) <= maximum, 'BYTE_OBSERVATION_RESOURCE', 'JSON byte bound')
    budget.charge(work=4 * len(raw) + 1, copied_bytes=12 * len(raw) + 4096)
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > budget.max_depth:
                raise source_api().SourceDataError('resource', 'SOURCE_DATA_RESOURCE', 'JSON nesting')
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, detail='JSON nesting')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, detail='duplicate JSON key')
            result[key] = value
        return result
    def no_float(_):
        fail('BYTE_OBSERVATION_INPUT', 'noninteger JSON number')
    try:
        value = json.loads(raw.decode('ascii' if canonical_required else 'utf8'), object_pairs_hook=pairs,
                           parse_float=no_float, parse_constant=no_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        fail('BYTE_OBSERVATION_INPUT', str(error)[:512])
    if canonical_required:
        need(canonical(value) == raw, detail='noncanonical JSON bytes')
    return value


def exact(value, names):
    need(type(value) is dict)
    need(all(type(key) is str for key in value))
    need(len(value) == len(names) and all(key in names for key in value))


def integer(value, maximum=U32, *, positive=False):
    need(type(value) is int and (1 if positive else 0) <= value <= maximum)
    return value


def hex_value(value, size=64):
    need(type(value) is str and len(value) == size and re.fullmatch('[0-9a-f]+', value) is not None)
    return value


def file_name(value):
    need(type(value) is str)
    need(0 < len(value) <= MAX_REQUEST, 'BYTE_OBSERVATION_RESOURCE', 'path character bound')
    need(value.count('/') < 128, 'BYTE_OBSERVATION_RESOURCE', 'path component depth')
    need('\x00' not in value and '\\' not in value and not value.startswith('/')
         and all(part not in ('', '.', '..') for part in value.split('/')))
    try:
        encoded = value.encode('utf8')
    except UnicodeError:
        fail('BYTE_OBSERVATION_INPUT', 'path is not UTF-8')
    need(len(encoded) <= MAX_REQUEST, 'BYTE_OBSERVATION_RESOURCE', 'path byte bound')
    return value


def bounded_plain(value, budget):
    """Charge before copying/encoding any caller-owned selector payload."""
    need(type(value) is list)
    need(len(value) <= 4096, 'BYTE_OBSERVATION_RESOURCE', 'selector count')
    budget.charge(work=len(value) + 1, edges=3 * len(value), copied_bytes=128 * (len(value) + 1))
    total = 0
    for row in value:
        exact(row, ('file', 'offset', 'kind'))
        need(type(row['file']) is str and type(row['kind']) is str)
        need(len(row['file']) <= MAX_REQUEST, 'BYTE_OBSERVATION_RESOURCE', 'path character bound')
        budget.charge(work=8 * len(row['file']) + 128, copied_bytes=8 * len(row['file']) + 256)
        file_name(row['file'])
        integer(row['offset'], U32 - 1)
        need(row['kind'] in ('var', 'parameter', 'field', 'typedef', 'enum'))
        total += len(row['file'].encode('utf8')) + 128
        need(total <= MAX_REQUEST, 'BYTE_OBSERVATION_RESOURCE', 'selector byte bound')
    budget.charge(work=4 * total + 1, copied_bytes=4 * total + 128)
    raw = canonical(value)
    need(len(raw) <= MAX_REQUEST, 'BYTE_OBSERVATION_RESOURCE', 'selector bytes')
    return raw


def selectors_stamp(value):
    try:
        if type(value) is not list or len(value) > 4096:
            return None
        total = 0
        for row in value:
            if type(row) is not dict or not all(type(key) is str for key in row) or len(row) != 3 or not all(key in ('file', 'offset', 'kind') for key in row):
                return None
            if type(row['file']) is not str or type(row['offset']) is not int or type(row['kind']) is not str:
                return None
            total += len(row['file']) + len(row['kind']) + 128
            if total > MAX_REQUEST:
                return None
        raw = canonical(value)
        return sha(raw) if len(raw) <= MAX_REQUEST else None
    except (ValueError, TypeError, UnicodeError):
        return None


def read_charged(path, budget, maximum=MAX_REQUEST, *, reserve_guard=False):
    try:
        size = path.stat().st_size
        need(0 <= size <= maximum, 'BYTE_OBSERVATION_RESOURCE', 'metadata byte bound')
        budget.charge(work=3 * size + 1, copied_bytes=2 * size + 1)
        if reserve_guard:
            budget.charge(work=size + 1, copied_bytes=size + 1)
        with path.open('rb', buffering=0) as stream:
            value = stream.read(size + 1)
        need(len(value) == size, 'BYTE_OBSERVATION_CHANGED', str(path))
        return value
    except OSError as error:
        fail('BYTE_OBSERVATION_ORACLE_UNAVAILABLE', str(error)[:512])


@dataclass(frozen=True)
class NativeOracle:
    executable: Path
    receipt: Path


@dataclass(frozen=True)
class NativeByteCategoryObservation:
    json_bytes: bytes


def prepare_oracle(oracle, budget, guards, guard_sizes):
    need(type(oracle) is NativeOracle, 'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', 'actual oracle descriptor required')
    binary = Path(oracle.executable).resolve()
    receipt_path = Path(oracle.receipt).resolve()
    receipt_raw = read_charged(receipt_path, budget, reserve_guard=True)
    guards[receipt_path] = sha(receipt_raw)
    guard_sizes[receipt_path] = len(receipt_raw)
    try:
        receipt = strict_json(receipt_raw, budget, canonical_required=False)
    except ByteObservationError as error:
        raise ByteObservationError('unavailable', 'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', 'invalid build receipt') from error
    need(type(receipt) is dict and type(receipt.get('exit')) is int and receipt['exit'] == 0
         and receipt.get('drift') == [] and receipt.get('llvm_pin') == PIN
         and type(receipt.get('input_hashes')) is dict and len(receipt['input_hashes']) <= 4096,
         'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', 'qualified actual build required')
    compiler = receipt.get('compiler')
    need(type(compiler) is dict and compiler.get('sha256') == COMPILER
         and type(compiler.get('version')) is str and PIN in compiler['version'],
         'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', 'actual pinned compiler')
    need(type(receipt.get('binary')) is dict and type(receipt['binary'].get('path')) is str
         and Path(receipt['binary']['path']).resolve() == binary,
         'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', 'actual build binary path')
    cpp = HERE / 'source_byte_categories.cpp'
    builder = HERE / 'build_source_byte_categories.py'
    originals = receipt['input_hashes']
    budget.charge(work=4 * len(originals) + 1, edges=2 * len(originals), copied_bytes=256 * len(originals))
    need(all(type(name) is str and type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected)
             for name, expected in originals.items()), 'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', 'build input grammar')
    need(type(receipt.get('command')) is list and all(type(arg) is str for arg in receipt['command']),
         'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', 'build command grammar')
    budget.charge(work=(len(originals) + 1)**2 * (max((len(name) for name in originals), default=0) + 1))
    manifest = {'format': 'rax-source-build', 'revision': 1,
                'source_inputs': [{'name': name, 'sha256': expected} for name, expected in sorted(originals.items())],
                'compiler': COMPILER, 'options': receipt['command'],
                'outputs': [{'name': 'source-byte-category-oracle', 'sha256': receipt['binary']['sha256']}]}
    build_digest = sha(canonical(manifest))
    paths = {binary, receipt_path, cpp.resolve(), builder.resolve(), Path(__file__).resolve(),
             SCHEMA.resolve(), TARGET.resolve(), REQUEST_SCHEMA.resolve(), SOURCE_API.resolve(), Path(sys.executable).resolve()}
    for name in originals:
        if name.endswith(('.dylib', '.so')) or '.so.' in name:
            paths.add(Path(name).resolve())
    try:
        sizes = {path: path.stat().st_size for path in paths}
    except OSError as error:
        fail('BYTE_OBSERVATION_ORACLE_UNAVAILABLE', str(error)[:512])
    total = sum(sizes.values())
    # Each bounded scan includes one growth sentinel. After scans never restat
    # and then read a larger file after this reservation or a resource failure.
    budget.charge(work=2 * (total + len(paths)) + 8 * MAX_REQUEST + 1,
                  copied_bytes=2 * (total + len(paths)) + 8 * MAX_REQUEST + MAX_OUTPUT + MAX_STDERR,
                  edges=2 * len(paths))
    expected_before = {binary: receipt['binary']['sha256'], receipt_path: sha(receipt_raw)}
    for path in (cpp, builder):
        need(str(path.resolve()) in originals, 'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', 'source not in build')
        expected_before[path.resolve()] = originals[str(path.resolve())]
    for name, expected in originals.items():
        if name.endswith(('.dylib', '.so')) or '.so.' in name:
            expected_before[Path(name).resolve()] = expected
    for path in sorted(paths):
        try:
            observed = bounded_guard_digest(path, sizes[path])
        except OSError as error:
            raise ByteObservationError('semantic', 'BYTE_OBSERVATION_CHANGED', str(path)) from error
        need(observed is not None, 'BYTE_OBSERVATION_CHANGED', str(path))
        guards[path] = observed
        guard_sizes[path] = sizes[path]
        need(path not in expected_before or observed == expected_before[path],
             'BYTE_OBSERVATION_CHANGED', str(path))
    projector_digest = projector_identity(build_digest, guards)
    return binary, guards, (build_digest, projector_digest)


def projector_identity(frontend_digest, guards=None):
    paths = {'wrapper': Path(__file__).resolve(), 'schema': SCHEMA.resolve(),
             'source-budget-api': SOURCE_API.resolve(), 'request-schema': REQUEST_SCHEMA.resolve()}
    source_inputs = [{'name': 'native-frontend-build', 'sha256': frontend_digest}]
    for name, path in sorted(paths.items()):
        source_inputs.append({'name': name, 'sha256': guards[path] if guards is not None else digest(path)})
    source_inputs.sort(key=lambda row: row['name'])
    interpreter = Path(sys.executable).resolve()
    compiler_hash = guards[interpreter] if guards is not None else digest(interpreter)
    manifest = {'format': 'rax-source-build', 'revision': 1, 'source_inputs': source_inputs,
                'compiler': compiler_hash,
                'options': ['interpreted-byte-category-reference', 'observer01..04', 'CPP07', 'normal-and-O-validation'],
                'outputs': [{'name': row['name'], 'sha256': row['sha256']} for row in source_inputs]}
    return sha(canonical(manifest))


def validate_recipe(bundle, files, build_digest, target_digest):
    recipe = bundle['recipe']
    need(type(recipe) is dict and recipe.get('kind') in ('smir-source-v1', 'lp64-ast-surrogate-v1'))
    if recipe['kind'] == 'smir-source-v1':
        fail('BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'native observer is not portable TargetInfo/projector')
    exact(recipe, ('kind', 'common', 'triple', 'observational_only'))
    need(recipe['triple'] == 'x86_64-unknown-linux-gnu' and recipe['observational_only'] is True,
         'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'unsupported surrogate recipe')
    common = recipe['common']
    exact(common, ('language', 'entry', 'dialect', 'optimization', 'macros', 'includes', 'forced_includes', 'modules', 'flags', 'backend'))
    need(common['language'] == bundle['language'] and common['entry'] in files and files[common['entry']]['kind'] == 'source')
    need(common['dialect'] in ('strict', 'gnu'), 'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'dialect')
    opt = common['optimization']
    need((type(opt) is int and 0 <= opt <= 3) or type(opt) is str and opt in ('s', 'z'),
         'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'optimization')
    flags = common['flags']
    exact(flags, FLAGS)
    expected = {'exceptions': bundle['language'] == 'cpp23', 'rtti': bundle['language'] == 'cpp23',
                'plain_char': 'signed', 'wchar_bits': 32, 'wchar_signed': True,
                'short_enums': False, 'ms_compatibility': False, 'fp_contract': 'off',
                'fast_math': False, 'signed_overflow': 'language_undefined',
                'threadsafe_statics': True, 'diagnostics': 'default_at_pin',
                'input_encoding': 'utf8', 'execution_encoding': 'utf8'}
    need(all(type(flags[key]) is type(value) and flags[key] == value for key, value in expected.items()),
         'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'unsupported frontend flags')
    backend = common['backend']
    exact(backend, ('llvm_commit', 'frontend_build', 'projection_protocol', 'projector_build', 'target_contract', 'sysroot'))
    header_vector = [{'name': name, 'kind': row['kind'], 'bytes': len(bytes.fromhex(row['data'])),
                      'sha256': sha(bytes.fromhex(row['data']))} for name, row in files.items() if row['kind'] != 'source']
    need(backend['llvm_commit'] == PIN and backend['frontend_build'] == build_digest[0] and backend['projector_build'] == build_digest[1]
         and backend['projection_protocol'] == 'rax-source-projection-v1'
         and backend['target_contract'] == target_digest and backend['sysroot'] == sha(canonical(header_vector)),
         'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'backend/build/target/sysroot identity')
    need(bundle['frontend'] == sha(b'RAX-SMIR-SOURCE-BACKEND-V1\x00' + canonical(backend)))
    need(type(common['modules']) is list)
    need(not common['modules'], 'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'module recipes unsupported')
    std = ('gnu23' if common['dialect'] == 'gnu' else 'c23') if bundle['language'] == 'c23' else ('gnu++23' if common['dialect'] == 'gnu' else 'c++23')
    arguments = ['-std=' + std, '-O' + str(opt)]
    if common['dialect'] == 'strict':
        arguments.append('-pedantic-errors')
    need(type(common['macros']) is list and len(common['macros']) <= 4096)
    for macro in common['macros']:
        need(type(macro) is dict and macro.get('kind') in ('define', 'undef'))
        exact(macro, ('kind', 'name') if macro['kind'] == 'undef' else ('kind', 'name', 'parameters', 'variadic', 'replacement'))
        name = macro['name']
        need(type(name) is str and re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', name) is not None,
             'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'non-ASCII macro identifier profile')
        need(name not in PROTECTED and not name.startswith('_') and not name.startswith(('RAX_', 'SMIR_')),
             'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'protected predefine')
        if macro['kind'] == 'undef':
            arguments.append('-U' + name)
            continue
        params, variadic, replacement = macro['parameters'], macro['variadic'], macro['replacement']
        need(type(variadic) is bool and type(replacement) is str and not any(x in replacement for x in ('\r', '\n', '\x00')))
        if params is None:
            need(not variadic)
            definition = name
        else:
            need(type(params) is list and len(params) <= 4096 
                 and all(type(x) is str and re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', x) for x in params)
                 and len(set(params)) == len(params))
            definition = name + '(' + ','.join(params + (['...'] if variadic else [])) + ')'
        arguments.append('-D' + definition + '=' + replacement)
    need(type(common['includes']) is list and len(common['includes']) <= 4096)
    for include in common['includes']:
        exact(include, ('kind', 'path'))
        need(include['kind'] in ('quote', 'user', 'system', 'after') and type(include['path']) is list)
        parts = include['path']
        need(all(type(part) is str and part not in ('', '.', '..') and not any(x in part for x in ('/', '\\', '\x00')) for part in parts))
        option = {'quote': '-iquote', 'user': '-I', 'system': '-isystem', 'after': '-idirafter'}[include['kind']]
        arguments += [option, '/rax-source-v1/' + '/'.join(parts)]
    need(type(common['forced_includes']) is list and len(common['forced_includes']) <= 4096)
    for forced in common['forced_includes']:
        file_name(forced)
        need(forced in files, 'BYTE_OBSERVATION_RECIPE_UNAVAILABLE', 'forced virtual include missing')
        arguments += ['-include', '/rax-source-v1/' + forced]
    return common['entry'], arguments


def verify_library_closure(files, budget):
    # Only this explicitly registered native reference closure can supply the
    # library category. A self-consistent caller sysroot hash is not registration.
    total = sum(len(files[name]['data']) // 2 for name in LIBRARY_FILES if name in files)
    budget.charge(work=2 * total + len(LIBRARY_FILES), copied_bytes=total)
    for name, expected in LIBRARY_FILES.items():
        need(name in files and files[name]['kind'] == 'header'
             and sha(bytes.fromhex(files[name]['data'])) == expected,
             'BYTE_OBSERVATION_LIBRARY_UNAVAILABLE', 'known library/config closure: ' + name)


def native_run(command, request):
    """Bound all three pipes before retaining bytes; kill only this child on cap."""
    environment = {'PATH': '/usr/bin:/bin', 'SOURCE_DATE_EPOCH': '0', 'TZ': 'UTC', 'LC_ALL': 'C', 'LANG': 'C'}
    with tempfile.TemporaryDirectory(prefix='smir-byte-observe-') as working:
        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       cwd=working, env=environment)
        except OSError as error:
            raise ByteObservationError('unavailable', 'BYTE_OBSERVATION_ORACLE_UNAVAILABLE', str(error)[:512]) from error
        stdout, stderr = bytearray(), bytearray()
        pending = memoryview(request)
        selector = io_selectors.DefaultSelector()
        for stream, event in ((process.stdin, io_selectors.EVENT_WRITE), (process.stdout, io_selectors.EVENT_READ), (process.stderr, io_selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event)
        deadline = time.monotonic() + NATIVE_TIMEOUT_SECONDS
        try:
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    fail('BYTE_OBSERVATION_RESOURCE', 'native process timeout')
                for key, event in selector.select(min(left, 0.1)):
                    stream = key.fileobj
                    if stream is process.stdin:
                        if not pending:
                            selector.unregister(stream)
                            stream.close()
                            continue
                        try:
                            count = os.write(stream.fileno(), pending[:65536])
                            pending = pending[count:]
                        except BrokenPipeError:
                            selector.unregister(stream)
                            stream.close()
                    else:
                        block = os.read(stream.fileno(), 65536)
                        if not block:
                            selector.unregister(stream)
                            stream.close()
                            continue
                        target = stdout if stream is process.stdout else stderr
                        maximum = MAX_OUTPUT if stream is process.stdout else MAX_STDERR
                        need(len(target) + len(block) <= maximum, 'BYTE_OBSERVATION_RESOURCE', 'native pipe byte bound')
                        target.extend(block)
            try:
                status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                fail('BYTE_OBSERVATION_RESOURCE', 'native process timeout')
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
        finally:
            selector.close()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        return status, bytes(stdout), bytes(stderr)


def validate_rows(rows, selected, files):
    need(type(rows) is list and len(rows) == len(selected), 'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'row coverage')
    names = ('selector', 'canonical_kind', 'category', 'value_bits', 'storage_bits', 'alignment_bits',
             'signed', 'cv', 'declaration', 'library_definition')
    for row, selector in zip(rows, selected):
        exact(row, names)
        need(row['selector'] == selector and type(row['canonical_kind']) is str, 'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'row identity')
        need(row['category'] in ('char', 'signed_char', 'unsigned_char', 'char8_t', 'std_byte', 'numeric', 'unsupported'))
        need(row['cv'] in ('none', 'const', 'volatile', 'const_volatile'))
        for key, maximum in (('value_bits', U32), ('storage_bits', U64), ('alignment_bits', U64)):
            if row[key] is not None:
                integer(row[key], maximum, positive=True)
        need((row['storage_bits'] is None) == (row['alignment_bits'] is None))
        need(row['signed'] is None or type(row['signed']) is bool)
        for key in ('declaration', 'library_definition'):
            if row[key] is None:
                continue
            location = row[key]
            exact(location, ('file', 'offset', 'file_sha256'))
            need(location['file'] in files)
            data = bytes.fromhex(files[location['file']]['data'])
            integer(location['offset'], U32 - 1)
            need(location['offset'] < len(data) and location['file_sha256'] == sha(data))
        if row['category'] == 'std_byte':
            need(row['declaration'] is not None and row['library_definition'] is not None)
        if row['category'] in ('char', 'signed_char', 'unsigned_char', 'char8_t', 'std_byte'):
            need(row['value_bits'] == row['storage_bits'] == row['alignment_bits'] == 8)


def validate_schema(rule, value, definitions, budget):
    budget.charge(work=1)
    if '$ref' in rule:
        return validate_schema(definitions[rule['$ref'].split('/')[-1]], value, definitions, budget)
    if 'oneOf' in rule:
        matches = 0
        for branch in rule['oneOf']:
            try:
                validate_schema(branch, value, definitions, budget)
                matches += 1
            except ByteObservationError as error:
                if error.code != 'BYTE_OBSERVATION_INPUT':
                    raise
        need(matches == 1, detail='schema oneOf')
        return
    if 'const' in rule:
        expected = rule['const']
        need(type(value) is type(expected) and value == expected, detail='schema const')
        return
    if 'enum' in rule:
        need(type(value) is str and value in rule['enum'], detail='schema enum')
        return
    kind = rule.get('type')
    if kind == 'object':
        exact(value, rule['required'])
        for key, child in value.items():
            validate_schema(rule['properties'][key], child, definitions, budget)
    elif kind == 'array':
        need(type(value) is list and len(value) <= rule['maxItems'])
        budget.charge(work=len(value), edges=len(value))
        for child in value:
            validate_schema(rule['items'], child, definitions, budget)
    elif kind == 'integer':
        integer(value, rule['maximum'])
        need(value >= rule['minimum'])
    elif kind == 'string':
        need(type(value) is str)
        need(len(value) >= rule.get('minLength', 0))
        if 'pattern' in rule:
            need(re.fullmatch(rule['pattern'], value) is not None)
    elif kind == 'boolean':
        need(type(value) is bool)
    elif kind == 'null':
        need(value is None)
    else:
        fail('BYTE_OBSERVATION_ORACLE_PROTOCOL', 'unsupported observation schema rule')


def observe_byte_categories(bundle_bytes, selectors, *, oracle, budget):
    api = source_api()
    need(type(budget) is api.SourceQueryBudget, 'BYTE_OBSERVATION_BUDGET_REFERENCE')
    selector_raw = bounded_plain(selectors, budget)
    selector_hash = sha(selector_raw)
    guards = {}
    guard_sizes = {}
    error = None
    result = None
    try:
        bundle = strict_json(bundle_bytes, budget)
        exact(bundle, ('format', 'revision', 'language', 'frontend', 'options', 'inputs', 'recipe', 'files'))
        need(bundle['format'] == 'rax-smir-source-evidence-bundle' and type(bundle['revision']) is int and bundle['revision'] == 1)
        need(bundle['language'] in ('c23', 'cpp23'))
        for key in ('frontend', 'options', 'inputs'):
            hex_value(bundle[key])
        need(type(bundle['files']) is list and len(bundle['files']) <= 4096)
        files = {}
        vectors = []
        previous = None
        total = 0
        for row in bundle['files']:
            exact(row, ('name', 'kind', 'data'))
            name = file_name(row['name'])
            need(previous is None or previous.encode('utf8') < name.encode('utf8'))
            previous = name
            need(row['kind'] in ('source', 'header', 'module', 'resource'))
            need(type(row['data']) is str and len(row['data']) % 2 == 0 and re.fullmatch('[0-9a-f]*', row['data']) is not None)
            total += len(row['data']) // 2
            need(total <= MAX_SOURCE, 'BYTE_OBSERVATION_RESOURCE', 'aggregate source payload')
            data = bytes.fromhex(row['data'])
            files[name] = row
            vectors.append({'name': name, 'kind': row['kind'], 'bytes': len(data), 'sha256': sha(data)})
        need(bundle['inputs'] == sha(canonical(vectors)) and bundle['options'] == sha(canonical(bundle['recipe'])))
        if any(name in files for name in ('libcxx/__fwd/byte.h', 'libcxx/__cstddef/byte.h')):
            verify_library_closure(files, budget)
        selected = json.loads(selector_raw)
        need(len({(row['file'], row['offset'], row['kind']) for row in selected}) == len(selected))
        for row in selected:
            need(row['file'] in files and row['offset'] < len(bytes.fromhex(files[row['file']]['data'])))
        binary, guards, build_digest = prepare_oracle(oracle, budget, guards, guard_sizes)
        target_digest = guards[TARGET.resolve()]
        entry, arguments = validate_recipe(bundle, files, build_digest, target_digest)
        request = canonical({'language': bundle['language'], 'entry': entry,
                             'files': [{'name': name, 'data': row['data']} for name, row in files.items()],
                             'selectors': selected, 'arguments': arguments})
        need(len(request) <= MAX_REQUEST, 'BYTE_OBSERVATION_RESOURCE', 'native request bytes')
        budget.charge(work=len(request), copied_bytes=len(request))
        status, stdout, stderr = native_run([str(binary)], request)
        need(0 <= status <= 4 and stdout, 'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'native signal/status/empty output')
        try:
            native = strict_json(stdout, budget, canonical_required=False, maximum=MAX_OUTPUT)
        except ByteObservationError as invalid:
            if invalid.code == 'BYTE_OBSERVATION_INPUT':
                raise ByteObservationError('unavailable', 'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'native JSON') from invalid
            raise
        need(type(native) is dict and native.get('format') == 'smir-native-byte-category-core'
             and type(native.get('revision')) is int and native['revision'] == 1,
             'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'native envelope')
        if native.get('status') == 'error':
            try:
                exact(native, ('format', 'revision', 'status', 'kind', 'code', 'detail'))
            except ByteObservationError as invalid:
                raise ByteObservationError('unavailable', 'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'native error shape') from invalid
            need(status in (2, 3, 4) and type(native['code']) is str and type(native['kind']) is str and CODES.get(native['code']) == native['kind'] and type(native['detail']) is str,
                 'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'closed native error')
            raise ByteObservationError(native['kind'], native['code'], native['detail'])
        try:
            exact(native, ('format', 'revision', 'status', 'binding', 'source_fact_authority', 'semantic_admission',
                           'runtime_authority', 'recipe_profile', 'library_version', 'language', 'input_sha256', 'rows'))
        except ByteObservationError as invalid:
            raise ByteObservationError('unavailable', 'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'native success shape') from invalid
        need(status == 0 and native['status'] == 'ok' and native['binding'] == 'unbound'
             and native['source_fact_authority'] is False and native['semantic_admission'] is False
             and native['runtime_authority'] is False and native['language'] == bundle['language']
             and native['input_sha256'] == sha(request) and type(native['library_version']) is str and PIN in native['library_version'],
             'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'native identity/authority')
        try:
            validate_rows(native['rows'], selected, files)
        except (ByteObservationError, TypeError, KeyError) as invalid:
            raise ByteObservationError('unavailable', 'BYTE_OBSERVATION_ORACLE_PROTOCOL', 'native rows') from invalid
        if any(row['category'] == 'std_byte' for row in native['rows']):
            verify_library_closure(files, budget)
        output = {'format': 'smir-native-byte-category-observation', 'revision': 1, 'binding': 'unbound',
                  'source_fact_authority': False, 'semantic_admission': False, 'runtime_authority': False,
                  'llvm_pin': PIN, 'oracle': guards[binary], 'bundle': sha(bundle_bytes),
                  'frontend': bundle['frontend'], 'options': bundle['options'], 'inputs': bundle['inputs'],
                  'language': bundle['language'], 'recipe_profile': 'lp64-ast-surrogate-v1', 'rows': native['rows']}
        schema = strict_json(read_charged(SCHEMA, budget), budget, canonical_required=False)
        validate_schema(schema, output, schema['$defs'], budget)
        encoded = canonical(output)
        budget.charge(work=len(encoded), copied_bytes=len(encoded))
        result = NativeByteCategoryObservation(encoded)
    except BaseException as caught:
        error = caught
    drift = []
    for path, expected in guards.items():
        try:
            if bounded_guard_digest(path, guard_sizes[path]) != expected:
                drift.append(str(path))
        except OSError:
            drift.append(str(path))
    if selectors_stamp(selectors) != selector_hash:
        drift.append('original selectors')
    if drift:
        changed = ByteObservationError('semantic', 'BYTE_OBSERVATION_CHANGED', ';'.join(drift)[:4096])
        if error is not None:
            raise changed from error
        raise changed
    if error is not None:
        raise error
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--selectors', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    budget = source_api().SourceQueryBudget(max_work=10**13, max_edges=10**9,
                                           max_copied_bytes=10**13, max_depth=128)
    try:
        observed = observe_byte_categories(read_charged(args.bundle, budget), strict_json(read_charged(args.selectors, budget), budget),
                    oracle=NativeOracle(args.oracle, args.receipt), budget=budget)
        sys.stdout.buffer.write(observed.json_bytes + b'\n')
    except (ByteObservationError, source_api().SourceDataError) as error:
        print(json.dumps({'kind': error.kind, 'code': error.code, 'detail': error.detail}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
