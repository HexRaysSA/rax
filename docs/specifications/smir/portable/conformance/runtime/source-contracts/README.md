# Source-contract witnesses

The `.source.json` files are declarative ten-root module blueprints; `.smo` files
are their exact encodings. `.source-contract.json` files attach raw static carrier
constraints. These are reference fixtures, not compiler-origin evidence or runtime
capabilities. No observed receipt is used as its own verifier oracle.

`original-pointer` supplies the unchanged original 6558-octet pointer witness.
`original-pointer-scoped` attaches copy/select/phi/exit carrier rows to that same
ordinary body; it differs statically from the unscoped attachment.

| Witness | Expected static outcome |
|---|---|
| baseline, equivalent-execution-dataptr-id | Conditional constraints; execution type aliases compared structurally |
| generic-caller-own-abi-none | Conditional constraints using actual callsite/callee plan |
| source-class/subject-root/formal-static-pointer/returned-static-pointer compatible-alias | Conditional constraints under strict original nominal compatibility |
| missing-all-adoptions | ASC_ADOPTION_COMPLETE_SET |
| return-scope-not-exit-scope | ASC_RETURN_SCOPE_EXIT |
| scope-program-differs-actual-journal-begin | ASC_SCOPE_JOURNAL_PROGRAM |
| negative-top-cv | ASC_STATIC_POINTEE |
| negative-reference-category | ASC_FORMAL_SOURCE |
| negative-definition-digest | Original ABI_CC_DEFINITION_HASH |
| negative-different-class | ASC_STATIC_POINTEE |
| negative-wrong-namespace | ASC_ORIGINAL_NAMESPACE |
| sret-published-factory + published-sret-terminal | Conditional complete published-result constraints |
| sret-source-factory + partial-sret-retention-reject | ASC_SRET_REQUIRES_COMPLETE_PUBLISH |
| pointer-partial-factory-and-caller + pointer-partial-return-adoption | Conditional actual caller/callee/adoption constraints |
| valid-two-normal-returns | Original ABI/execution pass; E-SOURCE-RETURN-ADOPTION-AMBIGUOUS is unavailable/exit 3 |
| address-only-source-closure left/right | Comparison includes address-taken callee; unequal source attachment is false |

The exact Journal diagnostic is asserted by the executable independent regression
suite; the table does not replace execution. `cases.json` contains the original
small pointer/CFG rejection matrix. `*-expected.json` are authored expectations,
not claims of an observed pass. The full suite also creates temporary malformed,
oversized and valid unsupported modules and exercises every CLI exit class.

Reproduce from the repository with `PYTHONPATH=tools/smir-runtime-contract`:

```sh
python3 -B -m source_contracts.fixtures --check
python3 -B -m source_contracts.schema --check
```

Both checks preserve products. Run the focused tests using the commands in the
package README. Normal and optimized Python must both pass. Neither mode proves
active root3 carrier encoding, actual source-lifetime admission or native execution.
