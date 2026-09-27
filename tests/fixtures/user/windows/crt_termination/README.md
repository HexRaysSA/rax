# CRT runtime-global registration fixtures

These 30 custom-entry PE images test x86 ILP32 and x64/ARM64 LLP64 for
`ucrtbase.dll` and `api-ms-win-crt-runtime-l1-1-0.dll`. They import actual
UCRT registrar names `_crt_atexit` and `_crt_at_quick_exit`. They do not link
compiler CRT startup objects or invent UCRT `atexit`, `_onexit`, or
`at_quick_exit` imports. Runtime API-set bindings are distinct from the stdio
API set. Native Windows execution is unknown.

`register_zero` registers null function pointers. `register_65` and
`register_1057` add the same function repeatedly to both independent global
queues, crossing the SDK registry's initial 32-entry allocation, doubling
steps, and 512-entry growth cap. Successful registration returns zero. Neither
registrar invokes callbacks. The programs write `registered\n` directly with
`WriteFile` and use raw desktop `ExitProcess`, which does not request the EXE
CRT's `exit` or `quick_exit` queues.

`explicit` uses an explicit onexit table to call both global registrars while
the recursive CRT exit lock is held. It executes an independent nested table,
then initializes its detached outer table as an independent next generation.
It checks LIFO order, ignored callback integer results, and the existing
explicit-table personality's invalid-table rejection after its second drain.
Global callbacks are not drained. This explicit-table compatibility profile
differs from the publisher SDK's mutable active-table algorithm; it is not a
native UCRT explicit-table equivalence claim.
`concurrent` starts a guest worker that calls the registrars while the main
thread owns the same lock in an explicit-table callback. Event synchronization
and a 20 ms guest sleep allow the worker to reach the registrar; it must finish
after the main callback returns and releases the exit lock. This is a
personality scheduling/locking witness; no native timing equivalence is claimed.

Build and record old-RAX rejection:

```sh
ruby tests/fixtures/user/windows/crt_termination/build.rb
ruby tests/fixtures/user/windows/crt_termination/baseline.rb /absolute/path/to/preserved/rax-user
```

The builder records source, tool, PE, and parsed IAT hashes in `manifest.json`.
Each IAT observation includes machine type and imports, observed directly from
the generated PE. Link timestamps are zero and all compiler inputs are owned
source. The baseline recorder requires 60 nonzero old-RAX missing-registrar
failures across scheduling slices of 1 and 4,096 instructions, with empty
stdout and a 30 s external watchdog per run. It fails on a timeout, success,
different export failure, or mismatched fixture hash.

Primary input receipts, prototypes, global-queue traversal, callback ownership,
and limits are in [the CRT termination reference archive](../../../../../docs/specifications/windows/crt-termination/README.md).
The SDK source itself is retrieved for temporary inspection and is not included
in this fixture graph or feature commits.

Assumptions: A1 is that the default desktop application CRT state is the target
of these bindings; the SDK global-state documentation and publisher export
observations support this scope. Falsification: an actual app/system-isolation
mode import or native recording with different queue ownership. A2 is that
20 ms plus event synchronization reaches the blocked registrar in the
deterministic guest scheduler; test both prescribed slices and require the
worker's done event to remain unsignaled during the callback. The runner must
report any violated assumption as a failed witness.

Bounded findings: high—full Windows CRT startup and native equivalence remain
outside these custom-entry registration fixtures; medium—MSVC global-state
isolation and the internal exit-lock selector body are not supplied by the SDK
source package; low—larger queue stress is possible but is not a runtime
performance measurement. The fixture producer includes no proprietary SDK
source code.
