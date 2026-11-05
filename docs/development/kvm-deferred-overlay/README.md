# Preserve deferred native results across public register updates

A successful KVM public register overlay now preserves the CPU's deferred exit.
The old setter cleared it after publishing the banks, losing a completion-time
fault or terminal event before normal delivery. Register publication does not
acknowledge the event. Existing delivery rules remain: shutdown/system events
repeat; other deferred results are consumed once; a wake cannot consume them.

An exclusive native-core control includes the actual production public-bank,
XSAVE, special-register, I/O, event and native-run modules. It seeds six valid
native result variants in independent 1/2/4-CPU graphs, with and without the
kernel IRQ chip. The original setter lost all84 results despite successful
register writes. The corrected setter preserves all84. The control checks
exact delivery and terminal repetition, then executes a real memory/output
canary after nonterminal delivery. Temporary executables were removed.

These are **seeded deferred protocol states**, not84 independently induced
kernel I/O-completion faults. Actual native GET/SET and canary execution are
used; the small exclusive FD-owner fixture does not establish managed VM-wide
exclusion. The new production regression repeats this matrix through the real
managed wrappers and their entry workers. Its complete owning library gate
remains required before publication.

The [qualification record](qualification.json) preserves the observed baseline,
source identities, corrected control and pending gates. The setter correction
uses O(1) time and space; the fixture matrix uses O(CPUs) native owners.

Assumption DE1: a represented-register update does not acknowledge an unrelated
queued exit. Stress probes cover all six native direct-result kinds, spurious
wake, repeated terminal delivery and guest entry only after consumption. Any
lost/changed result or early canary write falsifies it. The exclusive control
passes; managed-wrapper and complete-library qualification remain pending.

High impact: this correction does not serialize deferred results or complete
kernel-controller/timer phase, native I/O capture, rollback, or the public
checkpoint producer. Those C-STATE requirements remain open.
