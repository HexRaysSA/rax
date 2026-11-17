# CodeAddress literal values

Contract: accepted S-PROD016REV7, aligned by
P1-CODEADDRESS-LITERAL-CONSISTENCY-01. Every exactly 64-bit CodeAddress pattern is
a defined noncall value. Its literal carries no origin, target registration,
exposure, generation, permit or lease. DataPtr and typed CodePtr nonzero literal
rejection is unchanged. No layout, wire tag, version or source nominal hash changes.

The ten independently authored cases cover 0, 1, 2 and UINT64_MAX, vector/struct
recursion, wrong widths and the other pointer kinds. The ordered full-object bytes
are local execution-type/body witnesses; their enclosing source ABI is not claimed
admitted. Rust independently decodes/checks these bytes. Python also exercises the
actual literal constructor, Machine copy/equality, real guarded typed memory and
the existing raw64-to-CodeAddress pure bitcast without exposure.

The same-token negative obtains a target from the real source-backed CodeRegistry,
checks its actual chosen bits against the literal, and executes a genuine admitted
Machine with the original source plan and code_bind operation. It must trap
code_address_invalid before call/result publication, with no callable permit or
entry. An arbitrary constant is never labeled an issued target. This is finite
reference execution, not the production RAX engine, native guest execution or JIT.

The legacy reject-nonnull-literal identifier and its SMO bytes are preserved. Its
current expected static outcome explicitly changes from literal_pointer to ok;
expectation_migrations records the accepted policy and reason in both old corpus
views. Original receipts and authoring-source identities remain historical. They
are not relabeled current qualification and no old binary is regenerated here.

Run from checkout root with an empty external PYTHONPYCACHEPREFIX:

    python3 -B -m unittest discover -s tools/smir-format/execution -p test_candidate_code_address_literals.py -v
    python3 -B -O -m unittest discover -s tools/smir-format/execution -p test_candidate_code_address_literals.py -v
    python3 -B tools/smir-format/execution/function_addresses/literals.py --check

The producer authors only this new cases.json. A nonwriting check compares every
byte. Rust validation uses the execution_tests::function_addresses test filter.

Assumptions: LIT1 original S016 semantics [exact accepted proposal/hash and explicit
legacy migration]; LIT2 bits confer no authority [literal/Memory field assertions
and genuine same-target bind trap]; LIT3 pointer categories remain distinct [wrong
width and DataPtr/CodePtr rejection]; LIT4 pure from-bits is value transport [real
raw-bitcast equality with exposure sets empty]. High: any target/permit inference
blocks integration. Medium: Python/Rust predicate/expectation migration must land
coherently. Low: no host/performance or full source3 admission claim follows.
