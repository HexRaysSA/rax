# CodeAddress static conformance

From the repository root:

```
python3 tools/smir-format/execution/function_addresses/generate.py
python3 tools/smir-format/execution/function_addresses/check.py
python3 -m unittest discover -s tools/smir-format/execution -p test_candidate_function_addresses.py
```

The generator writes only SEM-owned logical cases, standalone `.smo` counterparts,
and the Rust execution test corpus. Expectations are authored in
`candidate/function_address_contract.py`; generation rejects disagreement with the
actual reference verifier. Local cases exercise execution typing without claiming
the enclosing source ABI is admitted. Source cases run genuine ABI and execution
verification on all ten actual roots. Neither scope issues runtime authority.

The current interpreter refuses `code_bind`, `code_erase`, noncall address lookup
and source-plan entry until actual registry and source-site producers are attached.
Null/copy/raw transport checks are separate from target/permit admission. Numeric
permit tags used in raw transport tests are not registered permits. Preserved old
wire bytes remain under `conformance/execution/legacy-cuts/cc-fnaddr-01`; decoding
those controls at the new revision does not count as semantic conformance.

New static missing-plan diagnostics preserve each verifier's existing namespace
boundary. The corpus explicitly authors both expected codes:

| Case | Python | Rust |
|---|---|---|
| Missing SELF caller/bind plan | source_plan_reference | P2_LOCAL_REFERENCE |
| DEP nominal used as call plan | source_plan_reference | P2_DEPENDENCY_NAMESPACE |

Other cases compare the same authored code. These are static diagnostics; this
mapping does not change any runtime trap or accept a malformed object.
