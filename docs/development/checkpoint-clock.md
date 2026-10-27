# Required timing state in snapshot bundles

Default bundle capture now records the VM timing-helper mode, integer
nanoseconds, retired total, fractional phase, diagnostic ticks and coalesced
pending-timer flag. Clock time and phase are sampled together before copying
memory; that same sampled nanosecond value populates the base metadata.
The existing base `Snapshot` fields and six-section writer retain their shape.

Required tagged-v8 section 12/schema 1 is exactly 44 bytes:

| Offset / bytes | Encoding | Meaning |
|---|---|---|
| 0 / 8 | `RAXCLK01` | Component tag |
| 8 / 8 | little-endian u64 | 3,000,000,000 retirement units/s |
| 16 / 1 | u8 | 0 wall, 1 retired |
| 17 / 1 | u8 | Phase in {0,1,2} retirement units |
| 18 / 1 | u8 | Pending flag, 0 or 1 |
| 19 / 1 | u8 | Reserved, zero |
| 20 / 8 | little-endian u64 | Integer nanoseconds |
| 28 / 8 | little-endian u64 | Wrapping retired total |
| 36 / 8 | little-endian u64 | Diagnostic tick count |

This component follows base control records and precedes CPU sets, PCI, physical
memory, media and reported RAM. The reader admits its exact size, frequency,
mode, phase, flags and agreement with base elapsed time before reading heavy
payloads. Duplicate records, optional aliases, unsupported schemas, late order
and conflicting metadata are rejected. Base-only and older readers reject the
required component at its header before payload consumption. Pair/base extraction
requires explicit handling of the clock component.

Restore validates the target clock mode before CPU/RAM/device mutation. A prepared
clock object binds the admitted state to its immutable-mode target. Its commit
allocates nothing and cannot return an admission error. It installs the fields
alongside represented data publication. Independent writers must be quiescent;
this does not establish native setter/resource rollback or full platform state.

Current VMM constructors select wall mode. Typed construction rejects a retired
clock file before construction until deterministic coordinator support is
selected. The codec and standalone context APIs already preserve every retired
phase and continue it exactly. Legacy files without this component retain their
previous elapsed-base projection and unrepresented tick/notification behavior.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| K1 | Clock/base timestamps describe one sample. | Default capture samples once; metadata equality, wire mutation and complete-file tests expose disagreement. |
| K2 | Clock admission precedes represented mutation. | Mode/phase/frequency checks and prepared publication; invalid mode and late MXCSR failure preserve target counters, notification and RAM. |
| K3 | A timing component cannot replace other required state. | Multi-vCPU bundles still require every CPU context; a regression checks rejection with a clock present. |
| K4 | The fixed record is bounded and explicit. | 44-byte manual encoding; malformed fields, huge/wrong lengths, aliases/schemas/order/duplicates and header-only reader cases. |
| K5 | Full state survives file transport and continuation. | Five files cover wall/all retired phases/full-width fields; 220 exact wire bytes and 176 live continuation/notification bytes are independently modeled. |
| K6 | Existing public base behavior remains available. | Original base writer/readers and old public API bodies remain; the prior full-file consumer is compared directly with current code. |
| K7 | Independent writers remain quiescent. | Existing capture/restore contract and private-target fixtures; complete scheduler/native/replay integration remains separate. |

Initial prototype failures are retained: a mechanical condition edit routed a
clock-only bundle to legacy restore and altered the independent secondary-CPU
guard. Both conditions were corrected and an explicit missing-CPU regression
added. Runtime fixtures also need the always-present x86 host bridge. The typed
constructor proof uses its existing accepted 128 MiB minimum; codec/micro-VM tests
retain 4 KiB coverage. Production input limits were unchanged.

Clock framing/admission/publication add O(1) work and 44 payload bytes. Existing
CPU/media/physical-memory costs and admitted byte domains remain unchanged.
The independent parser is linear in its five small files. Clock imports require
quiescence of independent diagnostic/notification writers as documented by the
context API.

High impact: deterministic default/coordinator selection, complete backend
counter/timer routing, private/platform/scheduler state, native transactions and
replay remain open. Medium impact: unsupported timing modes fail explicitly
before construction. Low impact: future rates or clock layouts require an
explicit compatible format identity.
