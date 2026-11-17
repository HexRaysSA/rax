# Static source observer witnesses

These authored expectations test actual original-v3 ordinary body and source graph
constraints. The binary is SEM's original `execution/source-observer` fixture;
this directory does not copy or regenerate it. The callee uses legal inline scope
entry and binding around actual `journal_begin`; its physical function returns
only a pointer. The caller adopts once, observes its declared logical association,
then closes the source scope at its retained return. Observation is not a new binding.

Run from the repository root, using one explicit original ledger:

```sh
python3 -B docs/specifications/smir/portable/conformance/runtime/source-observer/witness.py \
  --budget docs/specifications/smir/portable/conformance/runtime/source-contracts/explicit-budget.json
PYTHONPATH=tools/smir-runtime-contract python3 -B -m source_contracts.observer_fixtures --check
```

`cases.json` lists test-method expectations, including actual rejection controls;
it is not a successful verification receipt. `provenance.json` records exact input
bytes. Every reference result remains unbound with source/runtime/active-v3 flags
false. Full source-operation truth, lifetime/generation/Journal facade issuance,
registry identity, interpreter/JIT and native guest execution remain unavailable.

The finite caller profile is one block, exactly direct call then observer then
ordinary return. The callee is one block with actual journal begin then ordinary
return and legal inline enter/bind/exit phases. Unsupported preludes, CFG, source
lineages, epochs, outcomes or unrepresentable source coordinates explicitly refuse.
Actual comparison is selected function plus supported closure; all its body fields
participate, and only observer scope/adoption source IDs follow private alpha maps.
