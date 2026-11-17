"""Validate explicit portable import descriptors against the draft catalog."""
import json

from schema import SCHEMAS, require

CATALOG = json.loads((SCHEMAS / 'import-catalog.json').read_text())
BY_NAME = {entry['name']: entry for entry in CATALOG['records']}


def verify_import(record, signature=None):
    require(record['name'] in BY_NAME, 'UNKNOWN_PORTABLE_IMPORT')
    expected = BY_NAME[record['name']]
    for field in ('namespace', 'name', 'capability', 'blocking', 'cancellation',
                  'reentry', 'buffers'):
        require(record[field] == expected[field], 'IMPORT_DESCRIPTOR', field)
    if signature is not None:
        require(signature == (expected['params'], expected['results']), 'IMPORT_SIGNATURE')
    # Type-ID-to-actual-ABI-signature equality is required at whole-module admission;
    # this local validator can only check it when the caller supplies the shape.
