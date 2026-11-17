# Internal Null source-call reference witness

`null-diamond-source.json` is explicit editable ten-root source;
`null-diamond.smo` is its canonical 7038-octet encoding. Entry 1 takes no arguments
and returns Int1 `01` in 14 observed guest steps, using the policy in the parent
directory. Reassemble with `tools/smir-format/smir.py assemble`; run with the
public `run --entry-function 1 --reference-policy` command.

The original pointer function, source plan, source layouts and diamond phi from
`crates/smir-portable/tests/abi/ordinary-pointer-fixtures/original-pointer.source.json`
are retained exactly. The new wrapper explicitly creates typed Null, obtains the
original function CodeAddress, binds its actual source plan, enters the indirect
source call, and compares the returned DataPtr with Null. Its module identity
changes. The original 6558-octet object remains unchanged.

Assumptions N1--N5 and falsification probes are recorded in the accepted
REFERENCE-NULL-DATAPTR-CALLS-01 proposal: genuine typed Null, all-body producer
closure, exact original nominal/source checks, genuine registry/Machine transport,
and integer-only public boundaries. Positive transport, freeze/select/copy,
wrong-pointee and forbidden-producer controls are executable tests in
`tools/smir-format/test_portable_cli.py`. Before-effects probes delegate actual
Machine and registry constructors and require zero observed calls on rejection.

The 14-step result passed fresh normal and optimized source-cut qualification:
27 public CLI methods per mode, 83 consumed inputs and 106 audited processes per
mode, with zero drift/unwatched inputs and correct actual child optimization.
The original seven byte-CLI methods also passed in both modes. Exact receipts
are recorded in `status.json`, `validation.json` and the integrator handoff.
No allocation, dereference, runtime source alias, foreign/native call, parallel
execution, JIT or compiler-freeze capability follows from Null transport.
