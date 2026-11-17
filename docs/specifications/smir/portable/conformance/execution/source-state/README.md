# Conditional source-state reference fixtures

Executable Python verification of an UNBOUND model, not executable SMIR payload,
source facts, C++ definedness proof or runtime admission. This new package keeps
all prior source-lifetimes fixtures/schema/code READONLY and preserves their exact
historical70-case qualification.

Run from checkout root:

```sh
python3 -B -m unittest discover -s tools/smir-format/execution -p test_candidate_source_state.py
python3 -B -O -m unittest discover -s tools/smir-format/execution -p test_candidate_source_state.py
```

`candidate.source_state.verify(document,budget=actual_canonical_ledger)` returns
frozen StaticSourceState with tuple state, bindingunbound and both source/runtime
authority flagsfalse. It requires an explicit genuine SourceQueryBudget; no default,
reset or substitute. Reusing a cumulative ledger is valid. No envelope is executed.

`cases.json` is GENERATED from independently hand-authored cases() in the owned
test_candidate_source_state.py. Expected results are authored without invoking
verify; generation only serializes those input/expected records. Full documents
are intentionally repeated; expanded size is generated fixture data, not a large
hand-maintained source file. Tests compare stored cases exactly with the table.

The model separates original selected initialization prefix from CURRENT live
ranges and latest ENDED cells. Source end keeps history, creates holes; replacement
requires actual modeled ended cells and old+1 lifetime generation, retains original
source position and never retags an old alias. Root publication checks original
history; it can preserve current holes and cannot invent missing initialization.
Observe/current cleanup require exact current generation. Cleanup skips ended
holes and follows reverse current source ordinals, including interleaved patterns.

Ordering domain is original source anchor+object generation+cleanup schedule,
independent of inherited complete owner. Nested domains may each have ordinal1.
Canonical CURRENT cells in the same domain have unique positive ordinals. ENDED
history may retain an ordinal also used by another current pattern; it is not a
live collision. Restoring that ended cell would reject if it created a current
collision. Source INDEX intervals across current+ended must remain disjoint; a
new pattern/schedule label cannot duplicate the same canonical source cell.

Original anchors/schedules/canonical paths/selection/counts and every effect are
CONDITIONAL hypotheses. Model labels do not authenticate real source ownership,
ABI layout, class/path/union legality, generations, source effects or original
historical schedule ranks. Required initialization prefix is uniformly0 orcount
per source pattern, not proof of arbitrary nonuniform implicit/union creation.
Original source/ABI typed joins and static producer obligations remain unresolved;
actual source/alias/object/claim/view/J/scope issuers remain separate runtime work.
No result may be consumed as a private fact, permit or completed compiler gate.

Schema: closed JSON Schema2020-12, local draft revision1, exact nonbool u64,
ASCII labels1..128, lists<=4096. Pattern counts/ranges symbolic, checked mathematical
u64; count1 ordinal_step0, repeated step>0, no wrap. Ordinal CRT uses bounded256bit
intermediates and charges4096logicalwork/1edge/256bytes before pair arithmetic.
Independent arithmetic oracle compares44100small AP pairs against expanded sets
of at most5points, plus4large/u64edge cases; production-model validation never
loops over a source array extent or sizeof.

Inputs use the existing bounded shape preflight and are privately copied. Caller
JSON must stay stable while being captured; this does not promise a genuine source
snapshot. Each action checks/charges a candidate then commits; logical Resource or
semantic refusal preserves that action's old model state and caller input while
keeping budget consumption. Success requires metered own-schema before/after
checks. Refusal may stop without after guard; no new/default budget or unmetered
exhaustion guard. Catastrophic host OOM/asynchronous termination are excluded.

SS1..6 assumptions/probes and exact change surface are in the role coordination
SOURCE-STATE-assumptions.md. High: no actual source truth/identity from these
hypotheses. Medium: exact source schedule/class/path/selection carriers and typed
joins still required before full compiler freeze. Low: finite protocol/arithmetic
checks do not qualify native guest, parallel execution, JIT, host matrix or speed.
