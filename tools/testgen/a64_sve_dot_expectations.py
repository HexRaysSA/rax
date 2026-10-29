#!/usr/bin/env python3
"""Correct a qualified historical SDOT/UDOT subset from Arm XML and QEMU.

The original full-corpus input/revision remain unknown. This focused correction
does not call RAX or obtain expected results from its admission table.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / 'docs/development/a64-sve-profile/legacy-dot-correction.json'
MANIFEST = ROOT / 'tests/generated/manifest.toml'
OLD = '''!matches!(exit, Ok(CpuExit::Undefined(_)))
            && !matches!(exit, Err(ArmError::UndefinedInstruction(_))),
        "expected allocated encoding'''
NEW = '''matches!(exit, Ok(CpuExit::Undefined(_)))
            || matches!(exit, Err(ArmError::UndefinedInstruction(_))),
        "expected Undefined for selected base-SVE profile'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def primary_classes(record):
    archive = ROOT / record['primary_archive']
    if digest(archive.read_bytes()) != record['primary_archive_sha256']:
        raise ValueError('changed primary archive')
    classes = []
    with tarfile.open(archive, 'r:gz') as source:
        for document in record['primary_documents'].values():
            raw = source.extractfile(document['member']).read()
            if digest(raw) != document['sha256']:
                raise ValueError('changed primary dot-product document')
            for instruction in ET.fromstring(raw).findall('.//iclass'):
                mask = value = covered = 0
                for box in instruction.find('regdiagram').findall('box'):
                    high = int(box.attrib['hibit'])
                    width = int(box.attrib.get('width', '1'))
                    if box.attrib.get('constraint') or not 0 <= high - width + 1 <= high < 32:
                        raise ValueError('unqualified dot-product diagram')
                    cells = []
                    for cell in box.findall('c'):
                        cells += [(cell.text or '').strip()] * int(cell.attrib.get('colspan', '1'))
                    if len(cells) != width or any(x not in ('0', '1', '', 'x') for x in cells):
                        raise ValueError('unqualified dot-product cells')
                    for index, bit in enumerate(cells):
                        position = high - index
                        if covered & (1 << position):
                            raise ValueError('overlapping primary diagram')
                        covered |= 1 << position
                        if bit in ('0', '1'):
                            mask |= 1 << position
                            value |= int(bit) << position
                if covered != 0xffff_ffff:
                    raise ValueError('incomplete primary diagram')
                features = [x.attrib['feature'] for x in instruction.findall('./arch_variants/arch_variant')]
                if len(features) != 1 or not re.fullmatch(r'FEAT_\w+ \|\| FEAT_\w+', features[0]):
                    raise ValueError('unqualified primary feature expression')
                classes.append((mask, value, set(features[0].split(' || '))))
    if len(classes) != 6:
        raise ValueError('changed primary class count')
    return classes


def qualified_input():
    record = json.loads(INPUT.read_text())
    selected = set(record['selected_primary_features'])
    absent = set(record['unselected_primary_features'])
    if selected != {'FEAT_SVE'} or absent != {
            'FEAT_SME', 'FEAT_SVE2p1', 'FEAT_SME2', 'FEAT_SVE2p3', 'FEAT_SME2p3'}:
        raise ValueError('changed historical feature profile')
    if digest((ROOT / record['test_helper']).read_bytes()) != record['test_helper_sha256']:
        raise ValueError('changed historical CPU setup')
    classes = primary_classes(record)

    def allocated(word):
        matches = [(features & selected) != set() for mask, value, features in classes
                   if word & mask == value]
        if any(features - selected - absent for _, _, features in classes) or len(matches) > 1:
            raise ValueError('unqualified primary profile or overlapping class')
        return any(matches)

    tests = record['tests']
    if len(tests) != 68 or len({x['name'] for x in tests}) != 68:
        raise ValueError('changed historical case set')
    bad = {x['word'] for x in tests}
    good = {x['word'] for x in record['unchanged_positive_tests']}
    if len(bad) != 22 or not good or bad & good or any(allocated(w) for w in bad):
        raise ValueError('primary does not reject the historical cases')
    if any(not allocated(w) for w in good):
        raise ValueError('primary does not allocate a positive control')
    probes = set()
    for case in record['oracle_cases']:
        word, zen = case['word'], case['zen']
        if word not in bad | good or zen not in (0, 3):
            raise ValueError('unexpected oracle input')
        expected = ('119I0' if zen == 0 else '13cA0') if word in good else '100I0'
        if (case['code'] != 0 or case['actual'] != expected
                or case['model'] != 'max,sve-max-vq=1,sme=off'):
            raise ValueError('independent oracle disagrees with primary classification')
        probes.add((word, zen))
    if len(record['oracle_cases']) != 52 or probes != {(w, z) for w in bad | good for z in (0, 3)}:
        raise ValueError('incomplete independent oracle matrix')
    return record


def function(source, name):
    matches = list(re.finditer(r'(?ms)^fn ' + re.escape(name) + r'\(\) \{.*?^\}', source))
    if len(matches) != 1:
        raise ValueError(('missing or duplicate historical case', name))
    return matches[0]


def corrected_source(record):
    output = ROOT / record['output']
    source = output.read_text()
    if digest(source.encode()) not in {record['original_sha256'], record['corrected_sha256']}:
        raise ValueError('unqualified historical output revision')
    for case in record['tests']:
        match = function(source, case['name'])
        body = match.group()
        if f"let encoding: u32 = 0x{case['word']:08X};" not in body:
            raise ValueError('changed historical word')
        if body.count(OLD) == 1:
            body = body.replace(OLD, NEW, 1)
        elif body.count(NEW) != 1:
            raise ValueError('changed historical assertion')
        source = source[:match.start()] + body + source[match.end():]
    for case in record['unchanged_positive_tests']:
        if digest(function(source, case['name']).group().encode()) != case['body_sha256']:
            raise ValueError('positive control changed')
    if digest(source.encode()) != record['corrected_sha256']:
        raise ValueError('unexpected correction outside qualified cases')
    return output, source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    record = qualified_input()
    output, source = corrected_source(record)
    entries = {
        'sve_dot_correction': 'tools/testgen/a64_sve_dot_expectations.py',
        'sve_dot_correction_input': str(INPUT.relative_to(ROOT)),
        'sve_dot_correction_sha256': digest(source.encode()),
    }
    manifest = MANIFEST.read_text()
    for key, value in entries.items():
        entry = f'{key} = "{value}"'
        pattern = rf'(?m)^{key} = "[^"\n]*"$'
        if re.search(pattern, manifest):
            manifest = re.sub(pattern, entry, manifest)
        else:
            anchor = '\n[corpora.arm_aarch32_oracle_cases]'
            if manifest.count(anchor) != 1:
                raise ValueError('changed corpus manifest structure')
            manifest = manifest.replace(anchor, entry + '\n' + anchor, 1)
    if args.write:
        output.write_text(source)
        MANIFEST.write_text(manifest)
    elif output.read_text() != source or MANIFEST.read_text() != manifest:
        raise ValueError('stale focused dot-product correction; use --write')
    print(json.dumps(dict(tests=68, unchanged_positive_tests=len(record['unchanged_positive_tests']),
                          oracle_cases=52, output=record['output'], sha256=digest(source.encode()))))


if __name__ == '__main__':
    main()
