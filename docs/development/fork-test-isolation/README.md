# Host-process test isolation

The parallel library suite previously allowed host-fork tests to retain socket
peers belonging to other tests. A ptrace-stop fixture dropped its tracer and
expected immediate EOF; concurrent process creation could keep another reference
alive. The full library suite and two minimal pairs reproduced the failure.

Four tests that call the host `fork` and the EOF-sensitive ptrace test now run in
separate invocations of the same libtest executable. Each child selects exactly
one test and runs its original body. The parent requires a successful exit and a
summary of one passed, zero failed, zero ignored. Production transport, tracing,
and fork behavior are unchanged.

Isolating only the four fork callers was insufficient: the pair containing a
subprocess launch failed on repetition 33. The ptrace fixture must also create
its links after entering its own selected child. That test passed 1000 standalone
runs before the final correction; this diagnostic does not erase the observed
concurrent failures. The final contention campaign repeats all four pairs and
the combined five-test selection 100 times each.

| Resource/test | Process that creates its resources |
| --- | --- |
| Shared atomic mapping across fork | Selected shared-words test child |
| Readiness level across fork | Selected readiness test child |
| Host process watch | Selected pidfd test child |
| pidfd guest syscall fixture | Selected pidfd test child |
| Tracer and tracee sockets | Selected ptrace-stop test child |

The sockets in the last row are never present in the parent test process's
descriptor table. Fork or launch activity there cannot inherit those sockets.
The parent helper uses a per-test environment marker to enter each child's
original body once. Renaming or ignoring a selected test produces a failure
instead of a zero-test success. Separate negative probes exercise both empty
selection and propagation of a child assertion failure.

The helper uses O(B) captured-output space and O(B) summary-scanning time, in
addition to process startup and the original test, where B is child output bytes.
It adds no production state, API, wire record, or scheduling policy.

Primary provenance: Apple's [fork(2) source](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/man/man2/fork.2)
describes descriptor copying, and the [rustc test-harness manual](https://doc.rust-lang.org/rustc/tests/index.html)
defines exact selection and test-thread controls. Retrieved bytes and SHA-256
hashes are retained with the local evidence. See [qualification.json](qualification.json)
for exact commands, reconciled assumptions, counts, failed iterations, and scope.

This group qualifies the test-isolation correction on the recorded macOS host.
It does not close A32-FP, C-STATE, C-SMP, or C-HVF. The previous FP group's root
failure remains part of its historical evidence; the new full-root result is
recorded separately here. Linux/Windows execution and physical Intel
qualification are not implied by this macOS run.

| Gate | Final local outcome |
| --- | --- |
| Full library | 11944 passed; 0 failed; 35 ignored |
| Unix integration | 43 passed; 0 failed; 1 Docker-dependent ignored |
| Ptrace stops | 12 passed; 0 failed; 0 ignored |
| Contention campaign | 500 invocations; 1300 parent and 1300 isolated child cases; 0 failures |
| Negative selection/failure probes | 2 passed |
| Formatting, all-target build/check/Clippy | Passed |
| Doctests | 0 executed; 5 ignored |
