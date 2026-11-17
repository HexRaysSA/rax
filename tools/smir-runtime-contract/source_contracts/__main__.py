"""Explicit-budget, inspection-only CLI. See README.md for the exact contract."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from . import ContractToolError

ROOT = Path(__file__).resolve().parents[3]
SPEC = ROOT / 'docs/specifications/smir/portable/schema'
FLAGS = dict(format='smir-source-contracts-static-report', revision=1, binding='unbound',
             source_fact_authority=False, runtime_authority=False, active_v3_verified=False)
U64 = 2**64 - 1
BUDGET_KEYS = {'max_work', 'max_edges', 'max_copied_bytes', 'max_depth'}

# Exact finite-profile refusals; a substring is not a diagnostic classification.
UNAVAILABLE_CONSTRAINTS = frozenset({
    'ASC_ORIGINAL_FACTORY_PROFILE',
    'ASC_IDENTITY_SYMBOL_TARGET_PROFILE',
    'ASC_IDENTITY_TARGET_CLOSURE_PROFILE',
    'ASC_IDENTITY_ORDINARY_ID_PROFILE',
    'ASC_IDENTITY_SOURCE_CONTEXT_PROFILE',
    'ASC_IDENTITY_PROFILE_BOUND',
    'E-SOURCE-RETURN-ADOPTION-AMBIGUOUS',
    'E-SOURCE-RETURN-SCOPE-AMBIGUOUS',
    'E-SOURCE-PHYSICAL-ALIAS-REQUIRES-CLONE',
})


def fail(code, detail='', kind='input'):
    raise ContractToolError(kind, code, detail)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        fail('SCV_USAGE', message)


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            fail('SCV_USAGE', 'duplicate ' + option_string)
        setattr(namespace, self.dest, values)


def arguments(argv):
    parser = Parser(description='Finite static source constraints; no execution authority.',
                    allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True, parser_class=Parser)
    verify = commands.add_parser('verify', allow_abbrev=False)
    verify.add_argument('module'); verify.add_argument('contract')
    verify.add_argument('--budget', required=True, action=Once)
    compare = commands.add_parser('compare', allow_abbrev=False)
    for name in ('left_module', 'left_contract', 'right_module', 'right_contract'):
        compare.add_argument(name)
    compare.add_argument('--function', required=True, action=Once)
    compare.add_argument('--budget', required=True, action=Once)
    args = parser.parse_args(argv)
    if args.command == 'compare':
        value = args.function
        if re.fullmatch('[0-9]+', value, re.ASCII) is None:
            fail('SCV_FUNCTION', 'decimal non-sentinel u32 required')
        value = value.lstrip('0') or '0'
        if len(value) > 10:
            fail('SCV_FUNCTION', 'decimal non-sentinel u32 required')
        value = int(value)
        if value >= 2**32 - 1:
            fail('SCV_FUNCTION', 'decimal non-sentinel u32 required')
        args.function = value
    return args


def read_file(path, cap, budget=None):
    """Stat, precharge, bounded read and descriptor/path mutation checks."""
    path = Path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
        fail('SCV_INPUT_BOUND', 'regular file within byte cap required')
    size = before.st_size
    if budget is not None:
        budget.charge(work=8 * (size + 1), edges=size + 1, copied_bytes=8 * (size + 1))
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(size + 1)
        after = os.fstat(stream.fileno())
    current = path.stat()
    def key(value):
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if len(raw) != size or any(key(x) != key(before) for x in (opened, after, current)):
        fail('SCV_INPUT_CHANGED', 'input changed while reading')
    return raw


def lexical_depth(raw, maximum, budget=None):
    if budget is not None:
        budget.charge(work=len(raw))
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
            if depth > maximum:
                fail('SCV_JSON_DEPTH', 'JSON nesting exceeds policy',
                     'resource' if budget is not None else 'input')
        elif byte in (93, 125):
            depth -= 1


def parse_json(raw, maximum, budget=None):
    lexical_depth(raw, maximum, budget)
    if budget is not None:
        budget.charge(work=16 * (len(raw) + 1), edges=4 * (len(raw) + 1),
                      copied_bytes=64 * (len(raw) + 1))
    def pairs(rows):
        out = {}
        for key, value in rows:
            if key in out:
                fail('SCV_JSON_DUPLICATE', 'duplicate object key')
            out[key] = value
        return out
    def integer(text):
        if len(text) > 21:
            fail('SCV_JSON_INTEGER', 'integer exceeds u64 range')
        value = int(text)
        if not 0 <= value <= U64:
            fail('SCV_JSON_INTEGER', 'integer exceeds u64 range')
        return value
    def noninteger(text):
        fail('SCV_JSON_NUMBER', 'only unsigned integer JSON numbers supported')
    try:
        text = raw.decode('utf-8', errors='strict')
        # Escaped lone surrogates are rejected as well as malformed UTF8 bytes.
        result = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                            parse_float=noninteger, parse_constant=noninteger)
        text.encode('utf-8', errors='strict')
    except (UnicodeError, json.JSONDecodeError) as error:
        fail('SCV_JSON', type(error).__name__)
    stack = [result]
    while stack:
        item = stack.pop()
        if type(item) is str:
            try:
                item.encode('utf-8', errors='strict')
            except UnicodeError:
                fail('SCV_JSON', 'surrogate in UTF8 string')
        elif type(item) is dict:
            stack.extend(item); stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
    return result


def bootstrap(path):
    # Fixed lexical cap is applied before json.loads and before any ledger/owner.
    policy = parse_json(read_file(path, 4096), 1)
    if type(policy) is not dict or set(policy) != BUDGET_KEYS:
        fail('SCV_BUDGET', 'all four budget fields required; no extra fields')
    if any(type(value) is not int or not 0 <= value <= U64 for value in policy.values()) or \
            not 1 <= policy['max_depth'] <= 128:
        fail('SCV_BUDGET', 'invalid budget counts or depth')
    name = '_rax_smir_source_data_v1'
    path = ROOT / 'tools/smir-runtime-contract/source_roles/source_data.py'
    module = sys.modules.get(name)
    if module is not None:
        if type(getattr(module, '__file__', None)) is not str or Path(module.__file__).resolve() != path.resolve():
            fail('SCV_IMPORT_CONTEXT', name)
    else:
        specification = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(specification)
        sys.modules[name] = module
        try:
            specification.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
    return module.SourceQueryBudget(**policy)


def precharge_schemas(budget):
    # Existing reference modules load these grammar constants when imported.
    # Reserve their finite bytes/parse work before their import-time allocations.
    names = ['execution/records.json', 'execution/exceptions.json', 'execution/types.json',
             'execution/candidate.json', 'runtime/candidate.json', 'abi/candidate.json']
    for name in names:
        raw = read_file(SPEC / name, 2**20, budget)
        lexical_depth(raw, min(64, budget.max_depth), budget)
        size = len(raw)
        budget.charge(work=32 * (size + 1), edges=8 * (size + 1),
                      copied_bytes=64 * (size + 1))


def load_owner(path, schemas, budget):
    from . import checker as C
    from codec import CandidateCodec, RecordLimits
    raw = read_file(path, 16 * 1024 * 1024, budget)
    budget.charge(work=256 * (len(raw) + 1), edges=64 * (len(raw) + 1),
                  copied_bytes=128 * (len(raw) + 1))
    limits = RecordLimits(max_depth=min(64, budget.max_depth))
    module = CandidateCodec(schemas, limits).decode(raw)
    # Root keys are integers; preflight each declared root, not a forged JSON map.
    for root in module.roots.values():
        C.preflight(root, budget)
    precharge_schemas(budget)
    return C.RootContext(module.roots)


def execute(args):
    budget = bootstrap(args.budget)
    precharge_schemas(budget)
    from . import api
    schemas = {name: parse_json(read_file(SPEC / name / 'candidate.json', 2**20, budget),
                               min(64, budget.max_depth), budget)
               for name in ('abi', 'execution', 'runtime')}
    def document(path):
        return parse_json(read_file(path, 8 * 1024 * 1024, budget),
                          min(64, budget.max_depth), budget)
    if args.command == 'verify':
        owner = load_owner(args.module, schemas, budget)
        value = api.verify(owner, document(args.contract), budget=budget)
        return api.report(value, budget=budget), 0
    left = load_owner(args.left_module, schemas, budget)
    left_document = document(args.left_contract)
    right = load_owner(args.right_module, schemas, budget)
    right_document = document(args.right_contract)
    value = api.compare(left, left_document, right, right_document, args.function, budget=budget)
    return api.report(value, budget=budget), 0 if value.result else 1


def diagnostic(error):
    """Known original errors retain codes; unexpected exceptions remain internal."""
    if isinstance(error, ContractToolError):
        kind, code, detail = error.kind, error.code, error.detail
    elif isinstance(error, OSError):
        kind, code, detail = 'input', 'SCV_IO', str(error)
    else:
        sd = sys.modules.get('_rax_smir_source_data_v1')
        lifetimes = sys.modules.get('candidate.source_lifetimes')
        common = sys.modules.get('common')
        codec = sys.modules.get('codec')
        checker = sys.modules.get('source_contracts.checker')
        abi_errors = sys.modules.get('_rax_smir_call_comparison_errors_v1')
        layout = sys.modules.get('layout')
        if sd is not None and isinstance(error, sd.SourceDataError):
            kind, code, detail = error.kind, error.code, error.detail
        elif abi_errors is not None and isinstance(error, abi_errors.CallComparisonError):
            kind, code, detail = error.kind, error.code, error.detail
        elif layout is not None and isinstance(error, layout.ABIError):
            kind, code, detail = 'semantic', str(error), str(error)
        elif lifetimes is not None and isinstance(error, lifetimes.ContractError):
            code, detail = error.code, error.detail
            kind = 'resource' if code == 'SL_RESOURCE' else error.kind
        elif checker is not None and isinstance(error, checker.ConstraintError):
            code, detail = error.code, str(error)
            kind = 'unavailable' if code in UNAVAILABLE_CONSTRAINTS else 'semantic'
        elif common is not None and isinstance(error, common.Reject):
            code, detail = error.code, error.detail
            kind = 'resource' if code == 'limit' else 'semantic'
        elif codec is not None and isinstance(error, (codec.DecodeError, codec.RecordError)):
            kind, code, detail = 'input', str(error).split(':')[0], str(error)
        else:
            kind, code, detail = 'internal', 'SCV_INTERNAL', type(error).__name__
        if re.fullmatch('[A-Za-z0-9_:-]{1,128}', code, re.ASCII) is None:
            kind, code, detail = 'internal', 'SCV_INTERNAL', type(error).__name__
    encoded = str(detail).encode('utf-8', errors='replace')[:4096]
    detail = encoded.decode('utf-8', errors='ignore')
    return dict(FLAGS, status='error', **{'class': kind}, code=code, detail=detail), \
        {'input': 2, 'semantic': 2, 'unavailable': 3, 'resource': 4, 'internal': 70}[kind]


def main(argv=None):
    try:
        output, code = execute(arguments(sys.argv[1:] if argv is None else argv))
    except Exception as error:
        output, code = diagnostic(error)
    print(json.dumps(output, ensure_ascii=True, separators=(',', ':')))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
