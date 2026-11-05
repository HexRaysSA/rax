# Deferred native results in checkpoint banks

The managed native-bank composition records a result returned while completing
native I/O, before that result has been delivered to the VMM. The record owns
its data and contains no native run-mapping pointer. Register overlays and wake
notifications do not acknowledge the result.

The initial deferred-only owner envelope was version 3. The subsequent
[terminal-state supplement](../kvm-terminal-checkpoint/README.md) uses version
4; CPU-bank version 2 is unchanged.
The owner stores exactly one optional result per ordered CPU bank. Version 2
owner envelopes cannot represent these queues and are rejected; this internal
composition has not enabled the public KVM checkpoint producer.

| Native result | Retained fields | Delivery |
|---|---|---|
| HLT | Kind | Once; userspace halt state remains independently retained |
| Shutdown | Kind | Repeated terminal result |
| System event | `type_: u32`, `flags: u64` | Repeated terminal result |
| Entry failure | `reason: u64` | Once |
| Internal error | Kind | Once |
| Unknown exit | UTF-8 diagnostic, at most 65,536 bytes | Once |

I/O requests, software exceptions, system calls, and debugger exits are not
admitted as settled native direct results. Native input/output completion must
still finish through its actual device service and KVM completion path. Unknown
diagnostics use a bounded byte sequence, validated as UTF-8 before mutation.

Admission checks every CPU and diagnostic before the first native setter. A
successful restore replaces the destination queue, including clearing a queue
when the source has none. Queues are installed after native CPU/controller
banks succeed. The raw bank installer still requires a disposable destination
or an enclosing complete rollback transaction.

```text
native I/O completion -> owned deferred result -> capture / encode
                                             -> fresh owner / decode
                                             -> userspace delivery
                                             -> native guest entry
```

A deferred result does not consume the common first-entry epoch. Another CPU
may activate that epoch while a peer still owns a queued direct result; the
peer must deliver its result before entering KVM. The activation preflight
continues to reject native I/O completion and sticky protocol failures.

The new tests cover both codecs, absent results, all six admitted kinds,
malformed records, UTF-8/length boundaries, source-free 1/2/4-CPU restoration
with both controller profiles, replacement of destination queues, and delivery
before per-CPU memory canaries. A standalone control using the production
owner/CPU/shared/clock/deferred/run modules observed 84 pre-change capture
rejections, then 196 source-free restored CPU-result cases across both codecs.
Its complete module test binary passed 32 tests with no failures, ignores, or
filters. The fixture owns its FDs exclusively; it does not qualify the managed
exclusion implementation or private deadline worker. The new managed-owner
tests and complete affected Cargo binaries remain pending.

This change does not establish complete kernel timer/private-controller state,
whole-VM rollback, physical RAM publication, or public KVM checkpoint support.
The existing native-private-state counterexamples remain applicable.
