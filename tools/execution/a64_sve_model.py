"""Qualify primary SVE decode syntax and derive selected-profile clauses.

Instruction bits occupy bits 0..31 of an augmented word. Independent Boolean
feature predicates occupy bits 32..44. Compression must preserve every enumerated
assignment and yield only positive feature requirements for native admission.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from a64_fpsimd_allocation import compress
from asl_decode_allocation import enumerate_encoding, evaluate

FEATURES = (
    ('FEAT_SVE', 'SVE', 13),
    ('FEAT_SVE2', 'SVE2', 14),
    ('FEAT_SVE_AES', 'SVE2_AES', 15),
    ('FEAT_SVE_SHA3', 'SVE2_SHA3', 16),
    ('FEAT_SVE_SM4', 'SVE2_SM4', 17),
    ('FEAT_SVE_BitPerm', 'SVE2_BITPERM', 18),
    ('FEAT_SME', 'SME', 19),
    ('FEAT_SME2', 'SME2', 20),
    ('FEAT_SVE2p1', 'SVE2P1', 30),
    ('FEAT_SVE_B16B16', 'SVE_B16B16', 31),
    ('FEAT_BF16', 'BF16', 10),
    ('FEAT_I8MM', 'I8MM', 11),
    ('FEAT_F32MM', 'SVE_F32MM', 39),
)
PARAMETERS = {name: (32 + index, 1) for index, (name, _, _) in enumerate(FEATURES)}
# Arm 109697_2025_12_en pp.119-120 makes these capabilities mutually
# dependent. Their separate instruction predicates share the existing policy
# bit; introducing independently selectable flags would permit invalid profiles.
FEATURE_ALIASES = {'FEAT_SVE_PMULL128': 'FEAT_SVE_AES'}
FEATURE_SPEC = (Path(__file__).resolve().parents[2] /
                'docs/specifications/arm/a64-sve-2025-12/feature-names-109697_2025_12_en.pdf')
FEATURE_SPEC_SHA256 = '223e5c00d5a498ae3b8cab2d7b6237605efb291122d1d78897a69f80cf7f9a00'
AST_SHA256 = '4a1d6199ee721d71a0b34aee738d0ace4af9a8cecc43f1f1c366431d3e403784'
NORMALIZED_SHA256 = 'e16af1e7fdb32c95f9ff42285cab84ff65b28bfef805d79ee36314e1c38f6693'
DECLARATION = re.compile(
    r'\b(let|var)\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:\s*'
    r'([A-Za-z_]\w*(?:\([^;\n=]*\))?(?:\{\})?)\s*(=\s*)?')


def normalize_decode(text):
    """Translate only qualified modern spellings into the existing ASL parser."""
    text = re.sub(r'//[^\n]*', '', text)

    def declaration(match):
        kind, names, ty, assignment = match.groups()
        ty = ty.replace('{}', '')
        if kind == 'let':
            if not assignment or ',' in names:
                raise ValueError(('unqualified let', match[0]))
            return f'constant {ty} {names} = '
        return f'{ty} {names} ' + ('= ' if assignment else '')

    # Generic DecodeBitMasks is effectful. Its width is checked independently
    # of the destination declaration rather than erased as dead data.
    original = text

    def generic(match):
        name, parameter = match.groups()
        if name not in {'DecodeBitMasks', 'FPPointFive', 'FPOne', 'VFPExpandImm', 'FPTwo'}:
            raise ValueError(('unqualified generic call', match[0]))
        if name == 'DecodeBitMasks':
            if parameter == 'esize':
                if not re.search(r'\blet esize\s*:\s*integer(?:\{\})?\s*=\s*64\s*;', original):
                    raise ValueError('unqualified DecodeBitMasks generic width')
            elif parameter != '64':
                raise ValueError('unqualified DecodeBitMasks generic width')
        return name + '('

    text = DECLARATION.sub(declaration, text)
    text = re.sub(r'\b(Zeros|Ones)\{([^{}]+)\}(?!\s*\()', r'\1(\2)', text)
    text = re.sub(r'\b(\w+)\{([^{}]*)\}\s*\(', generic, text)
    text = text.replace('EndOfDecode(Decode_UNDEF)', 'UNDEFINED')
    text = re.sub(r'\bend\s*;', '', text)
    text = text.replace('::', ':')
    if re.search(r'\b(let|var)\b|EndOfDecode|\{\}', text):
        raise ValueError(('untranslated decode construct', text))
    return '\n'.join('            ' + line.rstrip() for line in text.splitlines() if line.strip())


def normalized_source(records):
    chunks = []
    for index, row in enumerate(records):
        fields = []
        for name, parts in row['fields'].items():
            if len(parts) != 1 or not re.fullmatch(r'[A-Za-z_]\w*', name):
                raise ValueError(('unqualified field', row['file'], name, parts))
            low, width = parts[0]
            fields.append(f'        __field {name} {low} +: {width}')
        pattern = ''.join(str((row['value'] >> bit) & 1) if row['mask'] & (1 << bit)
                          else 'x' for bit in range(31, -1, -1))
        chunks.append(f'__instruction primary_{index}\n    __encoding primary_{index}\n'
                      '        __instruction_set A64\n' + '\n'.join(fields) +
                      f"\n        __opcode '{pattern}'\n        __guard TRUE\n        __decode\n" +
                      normalize_decode(row['decode']) + '\n    __execute\n\n')
    return ''.join(chunks)


def parse(records, parser=None, saved_ast=None):
    source = normalized_source(records)
    if hashlib.sha256(source.encode()).hexdigest() != NORMALIZED_SHA256:
        raise ValueError('unqualified normalized primary source')
    if saved_ast:
        raw = saved_ast.read_bytes()
        if hashlib.sha256(raw).hexdigest() != AST_SHA256:
            raise ValueError('unqualified saved primary decode AST')
    else:
        with tempfile.TemporaryDirectory(prefix='rax-sve-decode-') as directory:
            path = Path(directory) / 'primary.asl'
            path.write_text(source)
            raw = subprocess.check_output([str(parser), 'instructions', str(path), '--format', 'json'])
    parsed = json.loads(raw)
    if len(parsed) != len(records):
        raise ValueError('changed primary decode count')
    encodings = []
    for index, (row, instruction) in enumerate(zip(records, parsed)):
        if (len(instruction['encodings']) != 1 or instruction['post_decode']
                or instruction['execute']):
            raise ValueError('unexpected derived instruction structure')
        encoding = instruction['encodings'][0]
        fields = {field['name']: (field['begin'], field['width']) for field in encoding['fields']}
        pattern = ''.join({'Zero': '0', 'One': '1', 'Either': 'x'}[x] for x in encoding['opcode'])
        mask = int(''.join('0' if x == 'x' else '1' for x in pattern), 2)
        value = int(pattern.replace('x', '0'), 2)
        if (encoding['name'] != f'primary_{index}' or encoding['iset'] != 'A64'
                or fields != {name: tuple(parts[0]) for name, parts in row['fields'].items()}
                or (mask, value) != (row['mask'], row['value'])):
            raise ValueError('changed primary field/opcode identity')
        encodings.append(encoding)
    return encodings


def feature_expression(text):
    """Parse the primary positive feature grammar; reject every unknown token."""
    tokens = re.findall(r'FEAT_\w+|&&|\|\||[()]', text)
    if ''.join(tokens) != re.sub(r'\s+', '', text) or not tokens:
        raise ValueError(('unqualified feature expression', text))
    position = 0

    def primary():
        nonlocal position
        if position >= len(tokens):
            raise ValueError(('incomplete feature expression', text))
        token = tokens[position]
        position += 1
        if token == '(':
            result = disjunction()
            if position >= len(tokens) or tokens[position] != ')':
                raise ValueError(('unclosed feature expression', text))
            position += 1
            return result
        if not token.startswith('FEAT_'):
            raise ValueError(('unqualified feature token', token))
        return {'Call': {'name': {'qualifier': 'Any', 'name': 'IsFeatureImplemented'},
                         'args': [{'Var': {'qualifier': 'Any',
                                           'name': FEATURE_ALIASES.get(token, token)}}]}}

    def combine(op, left, right):
        return {'Binary': {'op': op, 'lhs': left, 'rhs': right}}

    def conjunction():
        nonlocal position
        result = primary()
        while position < len(tokens) and tokens[position] == '&&':
            position += 1
            result = combine('And', result, primary())
        return result

    def disjunction():
        nonlocal position
        result = conjunction()
        while position < len(tokens) and tokens[position] == '||':
            position += 1
            result = combine('Or', result, conjunction())
        return result

    result = disjunction()
    if position != len(tokens):
        raise ValueError(('trailing feature tokens', text))
    return result


def normal_access_policy(row):
    """Classify access for the represented normal (PSTATE.SM=0) execution state.

    Both SVE access helpers first call CheckSVEEnabled in this state. The
    twelve streaming-predicate classes select that path only with SVE2p1.
    Scalar SME length instructions instead use CheckSMEEnabled directly.
    """
    operation = row['operation']
    calls = set(re.findall(r'\b(Check\w+(?:Enabled|State))\(', operation))
    if calls == {'CheckSMEEnabled'}:
        return 2
    if calls <= {'CheckSVEEnabled', 'CheckNonStreamingSVEEnabled'} and calls:
        return 1
    if calls == {'CheckSVEEnabled', 'CheckStreamingSVEEnabled'}:
        prefix = ' '.join(operation.split())
        expected = ('if IsFeatureImplemented(FEAT_SVE2p1) then CheckSVEEnabled(); '
                    'else CheckStreamingSVEEnabled(); end;')
        if prefix.startswith(expected):
            return 3
    raise ValueError(('unqualified selected normal-access policy', row['file'], sorted(calls)))


def derive(records, parsed):
    if hashlib.sha256(FEATURE_SPEC.read_bytes()).hexdigest() != FEATURE_SPEC_SHA256:
        raise ValueError('unqualified feature dependency specification')
    if len(records) != len(parsed):
        raise ValueError('changed primary decode count')
    terms, proof, unsupported = {}, [], []
    for row, original in zip(records, parsed):
        encoding = copy.deepcopy(original)
        def bind_aliases(value):
            if isinstance(value, dict):
                if 'Var' in value:
                    name = value['Var']['name']
                    value['Var']['name'] = FEATURE_ALIASES.get(name, name)
                for part in value.values():
                    bind_aliases(part)
            elif isinstance(value, list):
                for part in value:
                    bind_aliases(part)

        bind_aliases(encoding['decode'])
        all_names = {FEATURE_ALIASES.get(name, name) for name in re.findall(
            r'\bFEAT_\w+', ' '.join(row['features']) + ' ' + row['decode'])}
        constants = {name: False for name in all_names - PARAMETERS.keys()}
        conditions = [feature_expression(text) for text in row['features']]
        condition = conditions[0]
        for other in conditions[1:]:
            condition = {'Binary': {'op': 'Or', 'lhs': condition, 'rhs': other}}
        # The grammar is positive. If every representable predicate being
        # true still rejects the class, no currently selectable profile admits it.
        if not evaluate(condition, constants | dict.fromkeys(PARAMETERS, True)):
            unsupported.append(dict(file=row['file'], iclass=row['iclass'],
                                    features=row['features'], absent=sorted(constants)))
            continue
        policy = normal_access_policy(row)
        pre = [{'If': {'branches': [[{'Unary': {'op': 'Not', 'operand': condition}},
                                    ['Undefined']]], 'else_body': None}}]
        for number, (mask, value) in enumerate(row['constraints']):
            low, high = (mask & -mask).bit_length() - 1, mask.bit_length() - 1
            if low < 0:
                raise ValueError('empty diagram constraint')
            name = f'constraint_{number}'
            encoding['fields'].append(dict(name=name, begin=low, width=high - low + 1))
            pattern = ['One' if value & (1 << bit) else 'Zero' if mask & (1 << bit)
                       else 'Either' for bit in range(high, low - 1, -1)]
            pre.append({'If': {'branches': [[{'Binary': {'op': 'Eq',
                'lhs': {'Var': {'name': name, 'qualifier': 'Any'}},
                'rhs': {'LitMask': pattern}}}, ['Undefined']]], 'else_body': None}})
        encoding['decode'] = pre + encoding['decode']
        result = enumerate_encoding(encoding, constants=constants, parameters=PARAMETERS)
        mask = result['mask'] | sum(1 << bit for bit in result['positions'])
        cubes = compress(mask, result['accepted'], bits=64)
        accepted = set(result['accepted'])
        for assignment in range(result['assignments']):
            word = result['value'] | sum(((assignment >> j) & 1) << bit
                                        for j, bit in enumerate(result['positions']))
            if any(word & mask == value for mask, value in cubes) != (word in accepted):
                raise ValueError('compression changed primary decode admission')
        for mask, value in cubes:
            if (mask >> 32) & ~(value >> 32):
                raise ValueError('negative feature clause needs a different native contract')
            requirements = sum(1 << flag for index, (_, _, flag) in enumerate(FEATURES)
                               if value & (1 << (32 + index)))
            key = mask & 0xffff_ffff, value & 0xffff_ffff, requirements, policy
            terms.setdefault(key, []).append([row['file'], row['iclass']])
        proof.append({key: value for key, value in result.items() if key != 'accepted'} |
                     dict(file=row['file'], iclass=row['iclass'], access_policy=policy,
                          accepted_assignments=len(accepted),
                          cubes=[dict(mask=m, value=v) for m, v in sorted(cubes)]))
    if len(proof) + len(unsupported) != len(records):
        raise ValueError('unaccounted primary classes')
    return terms, proof, unsupported
