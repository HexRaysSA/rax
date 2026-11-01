# S3C checkpoint publication

Complete private S3C checkpoints retain `RAXS3C02` and the legacy `RAXS3C01`
reader. Each CPU record still carries its represented UART image. Capture
locks each distinct UART owner before owned GICs and physical RAM, then reads
all CPU images through that frozen scope. Controlled console writers cannot
change the UART between CPU records.

Restore constructs CPU/bridge replacements without changing live owners.
Admission compares complete serialized UART images for each shared target
owner. A disagreement rejects before RAM, CPU replacements or device fields
are published. Permits assign raw UART fields once per owner after RAM
publication, without replaying register writes, output or interrupt callbacks.
Dropping a permit has no live effect. Detached CPUs reject guest entry and
private capture until publication; a zero retirement budget remains a no-op.
Repeated publication cannot rewind input consumed or queued since the first
commit. Target host diagnostic settings remain in effect.

For C CPUs, U distinct UART owners, P aggregate private CPU/bridge/queue bytes,
and Q aggregate distinct UART image bytes, owner sorting costs O(C log C) time.
Capture and restore admission take O(P + C U) time and O(P + Q + C + U) space,
excluding RAM, its compression and host diagnostic copies. Each CPU context
retains the existing 16,777,216-byte limit; queue cloning is bounded before
allocation. Exact image
comparison avoids a hash-equality assumption. Publication performs no fallible
setter, lock acquisition, allocation or guest callback.

The three predecessor regressions observed CPU/UART prefix mutation after a
later setter failure, acceptance of conflicting shared images, and admission
of a controlled UART writer inside complete capture. Current test results and
source hashes are recorded in [qualification.json](qualification.json).
The actual file test resumes one, two and four S3C adapters through CPACR,
PWM/VIC and queued UART observations.

Scope limits: standalone per-CPU imports and projection-only legacy paths do
not promise a whole-VM transaction. Injected wrapper failures qualify the
coordinated S3C replacement path, not arbitrary native setters. Independent
raw memory writers still require coordination. These modeled device results
do not establish physical Samsung/ARM hardware fidelity, native CPU retirement,
SMP startup, record/replay or physical Intel HVF validation. The original four
full audit findings remain open.

Validation: the complete root library ran 11,609 passing tests with 35 ignored;
the selected actual native file continuation was explicitly rerun and passed
one test covering one, two and four CPUs. C API: 225 passed. Fresh C/C++:
19 programs and seven ABI compilation checks. Workspace formatting, all-target
check/build and Clippy passed. Doctests executed zero examples, with five
ignored. The ignored native CPU-profile module and physical Intel execution
were not qualified by this group; the known streaming FPSR issue remains open.

Decorators forwarding scoped S3C capture must also forward
`checkpoint_owned_s3c_uarts`. An unlisted UART owner rejects admission rather
than acquiring an untracked lock inside the physical boundary.
