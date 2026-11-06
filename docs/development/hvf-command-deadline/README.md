# Native Intel command deadlines

Native run [42189441259](https://github.com/HexRaysSA/rax/actions/runs/42189441259)
compiled and signed the combined 968-case consumer at
`550ff80d0f53af53dfb17e5ec323a459469f6425`. Its build artifact independently
matches all 4,509 engine inputs and four consumer files. The job then exceeded
its 3,600 s limit during the execution step. No execution artifact was uploaded;
the workflow log ZIP is empty and the individual job log returns HTTP 404.
The last guest phase, case and hardware behavior are unknown. This run provides
build evidence and zero qualified guest cases.

A separate subprocess fixture demonstrates an unbounded supervisor path: a
parent exits after starting a new session whose child retains stderr. The old
relay thread waits for that pipe after the command deadline. A 0.3 s deadline
still leaves the supervisor live at the 3 s outer observation bound; only the
fixture's recorded process groups are terminated. `baseline.json` retains the
observed result. This counterexample does not establish the cause of the native
SDK stall.

The command supervisor now reads stderr through a nonblocking selector. Process
completion and pipe drainage share the original command deadline. On timeout or
interruption it signals the owned process group, gives direct-child reaping a
5 s limit and drains immediately available stderr for at most 0.1 s. An unreaped
child is recorded explicitly. Raw stderr remains byte-for-byte output; the live
UTF-8 relay preserves characters split across reads. The original exception
propagates, and no timeout or cancellation can qualify guest execution.

The workflow separately limits compilation to 2,100 s and native verification to
1,800 s. The 4,500 s job limit leaves 600 s beyond those step budgets for setup,
upload and cleanup. These are supervision limits; process creation, host I/O and
OS scheduling do not constitute a hard real-time guarantee.

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| D1 | A stderr writer may outlive its parent or move to a separate session | Owned subprocess fixture; old timeout path | Parent exits, descendant retains stderr | Supervisor remains live beyond the outer observation bound | Confirmed counterexample; corrected complete harness passes |
| D2 | A newly created process group identifies this invocation's normal descendants | `start_new_session=True`; scoped termination | Live parent, exited parent, and interruption | A fixture outside the group is signalled | Existing group controls pass; the separate-session fixture is cleaned explicitly by its test owner |
| D3 | Native execution remains unqualified without complete observations | Strict 16/952/968 profile admission | Cancelled run with signed build only | A build or partial profile is accepted as guest success | Confirmed; no execution qualification claimed |
| D4 | The CI policy source is std-only | Initial isolated compiler assumption | Compile the exact complete source | Unresolved `toml` dependency | Falsified; locked `toml` is built with Cargo and linked explicitly |

All 52 Python harness tests pass. All 16 tests from the exact CI policy target
source pass unfiltered, compiled directly with `rustc --test` and the locked
`toml` dependency built using `cargo build --locked -p toml`. No RAX library or
C/C++ build is repeated for this Python/workflow-only group. The earlier complete
MMIO/owner and library qualification remains attached to its original source.

For b stderr bytes, relay work is O(b) with a 65,536 B read buffer and constant
auxiliary decoder state. Log storage is O(b).

Primary API contracts are retained under `primary/` with URLs and SHA-256:
Python `Popen.wait(timeout)`, nonblocking pipe I/O and selector timeouts.
`qualification.json` records commands and source hashes.

High-impact remaining work: identify the native execution stall using a new
exact-source run with preserved partial output; complete the original A32-FP,
C-STATE, C-SMP and C-HVF requirements. Medium-impact limits: kernel/host failures
can prevent reaping, and escaped sessions require their explicit owner's cleanup.
No low-impact adjacent implementation is included. All four findings remain
partial.
