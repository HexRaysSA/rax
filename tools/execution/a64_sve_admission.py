#!/usr/bin/env python3
"""Derive SVE admission from pinned Arm A-profile XML, with strict input checks.

Primary decoding, optional capability conditions, and access policy are separate
parts of admission. Unknown diagram or decode constructs stop derivation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
REVISION = '2025-12'
PREFIX = f'ISA_A64_xml_A_profile-{REVISION}/'
SOURCE = ROOT / 'docs/specifications/arm/a64-sve-2025-12/primary-xml.tar.gz'
SOURCE_SHA256 = 'c556529ec751bd91e59038cf10faae1ff81c8fc5c4ae531df3c168a9e04ae81e'
ORIGINAL_SHA256 = '845ed227a6692ddb6b602da2ecbbac776620195a9c001ec576ced3a9a53dc26b'


def may_be_sve(node):
    """Preselect major-2 diagrams without interpreting unrelated low fields."""
    mask = value = 0
    for box in node.findall('box'):
        high = int(box.attrib['hibit'])
        cells = []
        for cell in box.findall('c'):
            cells.extend([(cell.text or '').strip()] * int(cell.attrib.get('colspan', '1')))
        for index, bit in enumerate(cells):
            position = high - index
            if 25 <= position <= 28 and bit in ('0', '1'):
                mask |= 1 << position
                value |= int(bit) << position
    return ((2 << 25) ^ value) & mask == 0


def diagram(node):
    """Read every bit and retain explicit inequality constraints."""
    mask = value = covered = 0
    fields, constraints, unknown = {}, [], []
    for box in node.findall('box'):
        high = int(box.attrib['hibit'])
        width = int(box.attrib.get('width', '1'))
        low = high - width + 1
        if not 0 <= low <= high < 32:
            raise ValueError(('diagram range', box.attrib))
        region = ((1 << width) - 1) << low
        if covered & region:
            raise ValueError(('overlapping diagram fields', box.attrib))
        covered |= region
        constraint = box.attrib.get('constraint')
        if constraint:
            match = re.fullmatch(r'!= ([01x]+)', constraint)
            if not match or len(match[1]) != width:
                raise ValueError(('unqualified diagram constraint', box.attrib))
            pattern = match[1]
            cmask = int(''.join('0' if bit == 'x' else '1' for bit in pattern), 2) << low
            cvalue = int(pattern.replace('x', '0'), 2) << low
            constraints.append((cmask, cvalue))
            cells = ['x'] * width
        else:
            cells = []
            for cell in box.findall('c'):
                cells.extend([(cell.text or '').strip()] * int(cell.attrib.get('colspan', '1')))
            if len(cells) != width:
                raise ValueError(('diagram cell width', box.attrib, cells))
        for index, bit in enumerate(cells):
            if bit in ('0', '1'):
                mask |= 1 << (high - index)
                value |= int(bit) << (high - index)
            elif bit not in ('', 'x'):
                unknown.append((box.attrib, bit))
        name = box.attrib.get('name')
        if name:
            fields.setdefault(name, []).append((low, width))
    if covered != 0xffff_ffff:
        raise ValueError(('incomplete diagram', hex(covered)))
    return mask, value, fields, constraints, unknown


def primary_records(archive=SOURCE):
    """Select the requested revision, canonical major-2 classes only."""
    records = []
    aliases = []
    if hashlib.sha256(archive.read_bytes()).hexdigest() not in {SOURCE_SHA256, ORIGINAL_SHA256}:
        raise ValueError('unqualified primary archive revision')
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            if not member.isfile() or not member.name.startswith(PREFIX):
                continue
            name = member.name[len(PREFIX):]
            if '/' in name or not name.endswith('.xml') or name == 'shared_pseudocode.xml':
                continue
            raw = source.extractfile(member).read()
            if b'<regdiagram' not in raw:
                continue
            root = ET.fromstring(raw)
            for instruction in root.findall('.//iclass'):
                encoding = instruction.find('regdiagram')
                if encoding is None or not may_be_sve(encoding):
                    continue
                mask, value, fields, constraints, unknown = diagram(encoding)
                # The CPU entrypoint dispatches exactly the major-2 domain.
                mask |= 15 << 25
                value = (value & ~(15 << 25)) | (2 << 25)
                if unknown:
                    raise ValueError(('unqualified SVE diagram cells', name, unknown))
                if root.attrib.get('type') == 'alias':
                    aliases.append(dict(file=name, iclass=instruction.attrib['id']))
                    continue
                if root.attrib.get('type') != 'instruction':
                    raise ValueError(('unqualified SVE document type', name, root.attrib))
                pseudos = instruction.findall('./ps_section/ps')
                if len(pseudos) != 1:
                    raise ValueError(('unqualified decode sections', name, len(pseudos)))
                features = [row.attrib['feature'] for row in instruction.findall('./arch_variants/arch_variant')]
                if not features:
                    raise ValueError(('missing primary feature condition', name))
                operations = root.findall('./ps_section/ps')
                if len(operations) != 1 or operations[0].attrib.get('secttype') != 'Operation':
                    raise ValueError(('unqualified operation section', name))
                records.append(dict(file=name, member=member.name, bytes=len(raw),
                                    sha256=hashlib.sha256(raw).hexdigest(),
                                    iclass=instruction.attrib['id'], mask=mask, value=value,
                                    fields=fields, constraints=constraints, features=features,
                                    decode=''.join(pseudos[0].itertext()).strip(),
                                    operation=''.join(operations[0].itertext()).strip(),
                                    encodings=[row.attrib['name'] for row in instruction.findall('encoding')]))
    # Vendor ordering places underscore after letters. Make that ordering
    # explicit so the reduced package and original archive derive identical
    # instruction identities, independent of tar member order or host locale.
    records.sort(key=lambda row: row['file'].replace('_', '{'))
    identities = [(row['file'], row['iclass']) for row in records]
    if not records or len(set(identities)) != len(identities):
        raise ValueError('empty or duplicate primary SVE classes')
    return records, aliases


def outputs(rows, parsed):
    from a64_sve_model import FEATURES, FEATURE_ALIASES, FEATURE_SPEC_SHA256, derive

    terms, proof, unsupported = derive(rows, parsed)
    buckets = [[] for _ in range(256)]
    records = []
    for (mask, value, requirements, policy), names in sorted(terms.items()):
        records.append(dict(mask=mask, value=value, requirements=requirements,
                            access_policy=policy, sources=sorted(names)))
        # Major bits [28:25] are fixed to 0010, leaving sixteen high bytes.
        for high in range(16):
            top = ((high >> 1) << 5) | 4 | (high & 1)
            if top & (mask >> 24) != value >> 24:
                continue
            for opcode in range(16):
                if opcode & ((mask >> 12) & 15) == (value >> 12) & 15:
                    buckets[(high << 4) | opcode].append((mask, value, requirements, policy))
    offsets, entries = [0], []
    for bucket in buckets:
        entries.extend(bucket)
        offsets.append(len(entries))
    if len(entries) > 65535:
        raise ValueError('SVE bucket offsets no longer fit u16')
    lines = ['// Generated by tools/execution/a64_sve_admission.py; do not edit.',
             f'// Primary XML SHA-256: {SOURCE_SHA256}',
             'const PROFILE_FEATURES: u64 = ' + hex(sum(1 << bit for _, _, bit in FEATURES)) + ';',
             'const PROFILE_OFFSETS: &[u16; 257] = &[']
    line = '    '
    for offset in offsets:
        token = f'{offset},'
        if len(line + token) > 100:
            lines.append(line.rstrip())
            line = '    '
        line += token + ' '
    if line.strip():
        lines.append(line.rstrip())
    lines += ['];', 'const PROFILE_ENCODINGS: &[(u32, u32, u64, u8)] = &[']
    for mask, value, requirements, policy in entries:
        lines.append(f'    (0x{mask:08x}, 0x{value:08x}, 0x{requirements:016x}, {policy}),')
    lines += ['];', '']
    metadata = dict(revision=REVISION, primary_sha256=SOURCE_SHA256,
                    scope='Primary decode and selected capabilities for represented normal-execution profiles; full streaming/ZA state and unrepresented extensions remain outside this table.',
                    descriptions=len(rows), derived=len(proof), unsupported=unsupported,
                    assignments=sum(row['assignments'] for row in proof),
                    distinct_clauses=len(records), bucket_entries=len(entries),
                    maximum_bucket_entries=max(map(len, buckets)),
                    features=[dict(primary=name, rust=rust, bit=bit) for name, rust, bit in FEATURES],
                    feature_aliases=FEATURE_ALIASES,
                    feature_dependency_specification_sha256=FEATURE_SPEC_SHA256,
                    access_policies={'1': 'CheckSVEEnabled at PSTATE.SM=0',
                                     '2': 'CheckSMEEnabled',
                                     '3': 'SVE2p1 selects SVE; otherwise CheckStreamingSVEEnabled'},
                    records=records)
    return '\n'.join(lines), json.dumps(metadata, indent=2) + '\n', json.dumps(proof, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=SOURCE)
    parser.add_argument('--inventory', type=Path)
    intermediate = parser.add_mutually_exclusive_group()
    intermediate.add_argument('--parser', type=Path)
    intermediate.add_argument('--ast', type=Path)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    rows, aliases = primary_records(args.archive)
    if args.parser or args.ast:
        from a64_sve_model import parse

        generated = outputs(rows, parse(rows, args.parser, args.ast))
        paths = (ROOT / 'src/isa/arm/aarch64/cpu/sve/profile_encodings.rs',
                 ROOT / 'docs/development/a64-sve-profile/encodings.json',
                 ROOT / 'docs/development/a64-sve-profile/admission-proof.json')
        for path, expected in zip(paths, generated):
            if args.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(expected)
            elif path.read_text() != expected:
                raise ValueError(f'stale generated output: {path}')
        metadata = json.loads(generated[1])
        print(json.dumps({key: metadata[key] for key in
                          ('descriptions', 'derived', 'assignments', 'distinct_clauses',
                           'bucket_entries', 'maximum_bucket_entries')}))
        return
    if args.inventory is None or args.write:
        parser.error('select --inventory, --parser or --ast; --write requires parser/AST input')
    files = {row['file']: row['bytes'] for row in rows}
    result = dict(revision=REVISION, classes=len(rows), files=len(files),
                  raw_bytes=sum(files.values()), aliases=aliases, records=rows,
                  status='primary inventory; runtime rule generation not yet qualified')
    args.inventory.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['revision', 'classes', 'files', 'raw_bytes']}))


if __name__ == '__main__':
    main()
