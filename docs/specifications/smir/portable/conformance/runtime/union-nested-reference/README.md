# Nested pre-store reference fixtures

cases.json contains9authored core-backed observations and the complete30-test
inventory. provenance.json records original input identities. No SMO is generated
or admitted. The executable closed local schema is runtime/union_nested_reference.
schema.json; all source/runtime/admission/cost authority flags remainfalse.

Run PYTHONPATH=tools/smir-runtime-contract python3 -B -m union_nested.reference
--check --selftest (repeat -O/-OO). Nonwriting fixtures --check is also supported.
The package README states the fixed16B/8B layout, explicit quiescent assumptions,
actual-store/copy/index/refusal controls and missing private/source/runtime scope.
