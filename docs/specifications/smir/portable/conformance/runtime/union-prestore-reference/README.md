# Unbound union pre-store reference fixtures

`cases.json` contains 14 authored expected observations and the complete explicit
reference-test inventory. `provenance.json` identifies their original tool/schema
inputs. Neither product is source evidence or executable SMIR. No SMO is generated.

The local schema is `schema/runtime/union_prestore_reference.schema.json`. Run
`PYTHONPATH=tools/smir-runtime-contract python3 -B -m union_prestore.reference --check --selftest`
from the checkout root; repeat with `-O`. The check is nonwriting and compares actual
verified-core-backed observations against authored expectations. Generic atomic,
phase/source/private event, production runtime and full compiler gates remain false.
The package README states exact finite scope and falsification probes.
