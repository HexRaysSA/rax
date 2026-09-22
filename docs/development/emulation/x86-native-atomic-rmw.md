# Native x86 scalar atomic transactions

## Contract

An admitted SMIR `AtomicRmw` executes through one
`GuestRegs.atomic_rmw_fn` callback. Ordinary scalar load/store callbacks are
not a fallback for that transaction. A null callback or `ok == 0` exits at
the current guest instruction PC without committing arithmetic flags or the
optional register writeback.

This changes the native transaction boundary, not the admitted instruction
set. Existing `Add`, `Or`, `And`, `Sub`, `Xor`, and `Swap` forms retain
1-, 2-, 4-, and 8-byte widths, register and immediate sources, O0/O1/O2
recognition, exact virtual-use closure, and the existing `INC`/`DEC` flag
replays and `XADD`/`XCHG` writeback tails. Ordinary unlocked ALU RMW sequences
retain their separate checked load and store callbacks.

The existing architectural writeback restriction is unchanged: 2-, 4-, or
8-byte identity-mapped GPR destinations, excluding RSP/RBP. Byte writeback
and state-backed destinations are not newly admitted by this callback.

The callback ABI is defined by
[`X86AtomicRmwFn`](../../../src/smir/lower/runtime/x86_atomic_rmw.rs):

```text
fn(ctx, address: u64, operand: u64, size_bytes: u32, operation: u32)
    -> { old_value: u64, ok: u64 }
```

On supported SysV x86-64 hosts, the five arguments use RDI, RSI, RDX, ECX,
and R8D; the two 8-byte return fields use RAX and RDX. Operation numbers are
explicit: Add=0, Or=1, And=2, Sub=3, Xor=4, Swap=5. They do not depend on
Rust's `AtomicOp` enum layout. Successful return values are zero-extended
from the selected width. The operand matches the SMIR source value: a folded
immediate materializer is truncated to its declared width, whereas an
architectural GPR source retains all 64 bits. A failing callback must not
write guest memory, commit architectural state, or unwind across the ABI.

Only `MemoryOrder::SeqCst` sequences reach this path. Concurrent memory
backends must supply a transaction synchronized with every overlapping
access and preserve the total order of sequentially consistent operations.
The callback is not a lock around otherwise unsynchronized ordinary RAM.
The relevant semantic sources are the
[`SmirMemory::atomic_rmw` interface](../../../src/smir/ir/memory.rs),
[`MemoryOrder` definition](../../../src/smir/ir/types.rs), and Rust's
[sequential consistency contract](https://doc.rust-lang.org/std/sync/atomic/enum.Ordering.html#variant.SeqCst).

## Canonical CPU and fault behavior

The canonical CPU callback retains the existing serial MMU execution
contract. It validates the operation, byte width, complete address range,
code-page exclusions, and read/write plain-RAM permissions before reading
guest data. MMIO and self-modifying-code frontiers defer to direct execution.
It then performs exactly one `read_mem` and one `write_mem`. Verification
records the original value once and publishes one read plus one write trace
only after success; no bookkeeping reread is required.

This is not an SMP/MMU redesign. The VM execution loop currently schedules
vCPU 0; the canonical MMU's raw RAM accesses do not gain cross-thread
synchronization from this callback. Custom memory backends can provide an
indivisible transaction, as they already can through `SmirMemory`.

The native emitter snapshots all architectural GPRs before computing the
address and source, preserving source/address aliases including RSP, RBP,
and R16-R31. A 32-byte caller frame plus the 16-byte helper spill preserves
16-byte pre-CALL stack alignment. Flags are saved before bookkeeping and
restored after the callback; only success reaches the arithmetic replay and
register writeback. Existing helper-state marshalling preserves live MMX
and, when the containing region requires it, vector/opmask/MXCSR state.

For `n` bytes, the element width is `N = 8n` bits and arithmetic reduces
modulo `2^N`. Narrow transactions update only their selected bytes. The
emitter, callback preflight, and arithmetic require O(1) time and auxiliary
space; existing verification-vector appends are amortized O(1). A custom
CAS-loop backend may retry under contention and has no bounded retry count.

## Evidence and validation

The pre-change diagnostic used two host threads, separate `GuestRegs`, and
one shared `AtomicU64`. Ordinary load callbacks synchronized at a barrier
after both read zero, before either store. Both callbacks then stored `k`:
the native result was `k`, whereas two atomic additions produced `2k`.
This held for `k = 1` and `k = 0x1_0000_0000`, with both immediate operand
variants. All shared mutable data used atomics or mutexes; no canonical CPU,
MMU, or non-atomic RAM was shared concurrently. The diagnostic establishes a
generic callback-backend defect, not a supported CLI SMP regression.

The checked-in regression uses
[`AtomicU64::fetch_update`](https://doc.rust-lang.org/std/sync/atomic/type.AtomicU64.html#method.fetch_update)
with SeqCst success and failure orderings. Both threads enter their callback
before either transaction completes. Tests compare both returned original
values and the final memory value against one independently calculated
serial history. A pure retry closure prevents repeated CAS attempts from
duplicating guest effects or instrumentation.

Focused x86-64 execution under Rosetta passed all 16 new tests, without
skips: 25,344 width/GPR/address-alias success/failure/null-callback cases;
6,120 unary-flag and register-writeback cases; 1,242 narrow-immediate
operand cases; 576 synchronized two-thread transactions; three live-MMX
callback cases; six live-YMM0-15/MMX/MXCSR callback cases, also preserving
dormant opmask and upper-ZMM fields; and eight CPU tests including 216
callback arithmetic and 18 noncontiguous-physical cross-page cases. The
CPU-entry regression executes 256 actual native transactions and checks 32
unchanged byte-form refusals, with exact memory, register/flag, PC, and
read/write/undo-trace comparisons.
The broader atomic-name filter passed 136 tests. The retained scalar suite
passed 18 tests and all 460,152 existing native
executions, including 30,744 atomic success/fault cases. Seven existing
atomic-admission tests also passed. These are translated-host execution
results, not a physical x86 hardware-oracle claim.

On the shared AArch64 worktree, the all-target portable build and Clippy
passed with `--no-default-features --features x86_64-suite,smir-jit`;
the all-target `--no-default-features` check also passed. These validate the
combined worktree, including independently owned concurrent changes.
The final all-target Clippy check for `x86_64-apple-darwin` passed with the
same portable feature selection. No physical-x86 or complete AVX-512 runtime
coverage is inferred from compilation.

Reproduction commands, from the repository root on an Apple-Silicon host
with the installed x86-64 Rust target and Rosetta:

```sh
cargo +stable test --no-default-features --features x86_64-suite,smir-jit --target x86_64-apple-darwin --lib atomic_callback -- --test-threads=1 --nocapture
cargo +stable test --no-default-features --features x86_64-suite,smir-jit --target x86_64-apple-darwin --lib scalar_alu_immediate -- --test-threads=1 --nocapture
cargo +stable test --no-default-features --features x86_64-suite,smir-jit --target x86_64-apple-darwin --lib atomic -- --test-threads=1 --nocapture
```

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Canonical CPU/MMU execution remains serial for overlapping guest memory and mapping changes. | Direct atomic handlers and VM vCPU-0 execution loop. | Canonical callback's preflight-to-store guarantee. | Cross-page permissions and noncontiguous physical mappings. | Introduce a supported concurrent canonical RAM/mapping writer without a shared synchronization protocol. | Retained; no SMP claim. |
| A2 | A custom callback implements the documented indivisible SeqCst and no-write-on-failure contract. | Unsafe callback ABI and SMIR atomic-memory interface. | Native equivalence for concurrent custom backends. | Two synchronized host threads, narrow and full-width arithmetic, all six operations, callback failure. | Return two identical original values for nonzero additive updates from the same starting value, or mutate memory on `ok == 0`. | Confirmed for the regression backend; retained for arbitrary callbacks. |
| A3 | Existing GuestRegs helper marshalling remains the authoritative live-state mapping. | Shared GPR/state helpers and append-only field layout. | Alias, flags, MMX, and fault-frontier preservation. | All 32 GPRs, source/address aliases, INC/DEC CF, XADD/XCHG writeback, null callback, MMX clobber. | Full GuestRegs comparison or offset assertions fail. | Confirmed by focused execution and ABI tests. |

## Change surface and bounded exclusions

| Plane | Effect |
|---|---|
| Direct decode/execute, CPU architectural state | No instruction or state semantics changed. CPU installs one internal callback. |
| Memory/MMU | Existing plain-RAM preflight and serial MMU APIs reused; no new pointer access, mapping, ordering primitive, or SMP guarantee. |
| SMIR lift, IR, interpreter, optimizer | Unchanged; existing AtomicRmw operation and exact sequence recognition retained. |
| Native lowering/JIT | One callback transaction, precise failure exit, existing flags/writeback replay and helper-state preservation. |
| Backend/machine/device | No interface or wiring change beyond the canonical software CPU callback installation. |
| Oracle/analysis/C ABI/snapshots | Unchanged; GuestRegs callback is internal execution metadata, not serialized architectural state. |
| Tests/docs | New transaction/ABI/concurrency tests; existing scalar matrix adapted without reducing cases. |

- High, non-blocking for this transaction-boundary repair: concurrent canonical
  MMU access remains unsupported without a shared RAM/mapping synchronization
  contract. Running two canonical CPUs against raw shared RAM is not a valid
  data-race-free reproduction.
- High, non-blocking: `CmpXchg`/`CmpXchgPair` and `CMPccXADD` have separate native
  paths. This callback does not establish their concurrent-backend semantics.
- High, pre-existing and unchanged: the direct memory `XCHG` handlers write
  the source GPR before the checked memory store in
  [`execute/data/xchg.rs`](../../../src/isa/x86_64/execute/data/xchg.rs).
  Direct execution is therefore used here only as a successful-transaction
  oracle; native failure/refusal checks require the original entry state.
- High, pre-existing and unchanged: generic scalar ALU/XADD direct and lifted
  paths do not uniformly implement the optional x86 `#AC` policy. The separate
  CMPccXADD path has its own live-state alignment guard. This repair neither
  expands generic instruction admission nor claims complete exception-policy
  coverage beyond existing admitted SMIR semantics.
- Medium, pre-existing and non-blocking: an optimized narrow live flag replay
  may normalize its immediate without normalizing the retained materializer
  (for example, W32 `-1` versus `0xFFFF_FFFF`). The existing matcher compares
  those literals exactly and rejects the sequence. This repair preserves
  that fallback boundary; width-equivalent replay admission is separate work.
- Medium, pre-existing and non-blocking: byte `INC`/`DEC` reuse the atomic
  result virtual as the flag-result destination, violating the native
  matcher's single-definition requirement. Byte `XCHG` retains unsupported
  byte writeback even before a later full-register overwrite. Saved register
  sources for `XADD` also remain outside its immediate/architectural-source
  grammar unless optimization exposes a supported materializer; the CPU
  regression uses a tracked `MOV ECX,imm32` prelude. These lifter/optimizer
  boundaries remain unchanged; the callback-level tests exercise the
  supported IR shapes directly.
