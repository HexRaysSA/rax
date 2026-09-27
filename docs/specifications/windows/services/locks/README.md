# Address-keyed synchronization source record

The retained Microsoft documentation and exact content hashes are listed in
`sources.json`. Retrieval date: 2026-09-27. Attribution: Microsoft Corporation
and MicrosoftDocs contributors. Both source repositories supply CC BY 4.0;
their matching license text is retained as `LICENSE`. Exact upstream commits
are unknown. The manifest distinguishes downloaded and retained hashes and
records trailing-whitespace/terminal-newline changes; no substantive source
text was changed. These documents specify public API contracts, not private
lock-word encodings or native malformed-input error outcomes.

## Implemented personality profile

`src/user/windows/dll/locks/` provides 23 Win32 exports: critical-section
initialization/deletion/enter/try/leave/spin APIs; shared/exclusive SRW
initialization/acquisition/try/release APIs; condition-variable
initialization/wake/sleep APIs; and WaitOnAddress/WakeByAddress APIs. Root DLL
registration supplies reachability. No native/JIT instruction admission is
changed and no Rtl* equivalent export is implied.

- Critical sections support recursive ownership and reject non-owner release,
  deleted/uninitialized use, active deletion, and unsupported reinitialization.
  Spin count is effectively zero because process startup exposes one processor
  in PEB, KUSER_SHARED_DATA, and NUMBER_OF_PROCESSORS. There is no host busy-spin.
- SRW locks support multiple distinct shared owners, exclusive ownership,
  checked owner release, and queued-writer preference. Exclusive recursive
  Try fails; recursive Acquire remains blocked. Recursive shared acquisition
  is unsupported: Try fails, and a blocked recursive-shared grant is rejected
  explicitly. Upgrade from shared to exclusive does not succeed. No fairness
  or native ordering equivalence is claimed.
- CV sleep releases the associated lock exactly once before parking, including
  zero timeout, and reacquires in the original mode before returning success or
  ERROR_TIMEOUT. Wake/timeout does not skip reacquisition when another thread
  has acquired the lock. CS sleep requires recursion count exactly one.
- WaitOnAddress reads exactly 1, 2, 4, or 8 bytes from both pointers; inequality
  succeeds immediately, equality parks or times out. WakeByAddressSingle wakes
  the oldest registered address waiter; All wakes every registered waiter.
  Explicit wake succeeds without changing the compared value. Address waits
  and CV waits use disjoint u128 host keys: the guest address occupies bits
  0..63 and the CV namespace uses bit 64. No forged u64 wake address aliases a
  CV key. WaitOnAddress byte addresses need not be pointer-aligned.

Guest CS/SRW/CV storage is opaque to this personality. CS storage is 24 bytes
on x86 and 40 bytes on x64/ARM64; SRW/CV storage is one guest pointer. CS
DebugInfo uses the synthetic no-debug sentinel; no native debug-information
allocation, LockSemaphore object, or undocumented lock protocol is modeled.
In particular, guest code manipulating these private fields inline is outside
the implemented contract. Effective spin-count/private-state equivalence to
other processor profiles is unknown. Lock/CV storage must be non-null,
naturally pointer-aligned, and fully contained within the guest pointer width.
Invalid ownership, private storage, or counter state produces a configured
personality diagnostic, not a fabricated native Windows exception/status.
Invalid public WaitOnAddress widths, CV flags, and CSEx flags instead return
FALSE with ERROR_INVALID_PARAMETER through their documented failure branches.

Each guest-storage transition prepares a complete replacement and uses one
checked AddressSpace write before publishing host ownership/counter changes.
AddressSpace::write materializes/checks every accessed page before copying any
byte. A read/write/permission/backing fault therefore does not partially change
the guest lock image or host lock state for that transition. CV storage is
read/write-probed before lock release. Cancellation that must update an
inaccessible live lock word can itself fail; the scheduler terminates that path
with a diagnostic instead of reporting successful cleanup. Process termination
instead discards all synchronization state and object wait pins without any
guest lock access, retaining the address space only for diagnostics.

Wait registration pins every object exactly once through checked retain_many;
successful poll consumes the wait and marks it completed; cleanup releases
pins without consuming/decrementing the lock registration again. Cancellation
before completion releases pins and removes waiter counts without acquiring
the lock. Cleanup is idempotent; mismatched registered wait descriptors and
repeated completed polls are rejected. The immediate object-wait helper now
checks mutex recursion overflow before any wait-all consumption. Wait-any uses
the lowest signaled index. For abandoned wait-all this profile returns
WAIT_ABANDONED_0: Microsoft public documentation permits the abandoned status
range without defining an index meaning for wait-all; exact native value is
unknown.

## Arithmetic and complexity

CS recursion uses a positive signed 32-bit field; increment above 0x7fffffff
fails before mutation. Host waiter counters are checked u32. The synthetic
held-CS count is -2 - 4*n, requiring n <= floor((2^31 - 2)/4) = 0x1fffffff
waiters; an unrepresentable value fails before writing. SRW shared count uses
bits 4 and above of one pointer word: n <= (2^pointer_bits - 1) >> 4. Timeout
inputs are u32 milliseconds (1 ms = 0.001 s); 0xffffffff means infinite.
Finite Instant addition is checked. No arbitrary unbounded host sleep occurs.

Expected hash-map costs: CS transition O(1) time/space (at most 40 guest bytes);
SRW transition O(r) time and temporary space because the reader-owner set is
cloned before commit, with r active shared owners; address wake O(w) time for
w woken threads; queue cancellation O(q) time for q queued threads and O(1)
auxiliary space. Object waits/retains/releases take O(k) expected time and
O(k) temporary space for k <= 64 object IDs. Stored ownership/queue state is
O(number of initialized locks + active SRW owners + registered waits + pinned
object IDs) for live entries. HashMap/HashSet/queue allocations can retain
capacity at their prior high-water marks; removing entries does not establish
a shrinking allocation bound. Process-exit draining visits the stored state
without guest-memory access; hash-table traversal can also visit retained
capacity.

## Public installed-header probe

Run `bash docs/specifications/windows/services/locks/check-layout.sh`.
It executes these compile-only commands with a new temporary `task_dir` and
removes exactly the three resulting COFF objects at exit:

```sh
i686-w64-mingw32-gcc -std=c11 -Werror -c "$probe_dir/layout-probe.c" -o "$task_dir/x86.obj"
x86_64-w64-mingw32-gcc -std=c11 -Werror -c "$probe_dir/layout-probe.c" -o "$task_dir/x64.obj"
zig cc -target aarch64-windows-gnu -std=c11 -Werror -c "$probe_dir/layout-probe.c" -o "$task_dir/arm64.obj"
```

Verified 2026-09-27 on AArch64 macOS: nine sizeof/offsetof assertions passed
per guest, including all accessed named CRITICAL_SECTION offsets, CS size,
and pointer-sized SRWLOCK/CONDITION_VARIABLE. Compilers: x86/x64 GCC 16.2.0;
ARM64 Zig 0.16.0 delegating Homebrew clang 21.1.8. Installed headers are
MinGW-w64 declarations, not native Microsoft SDK/runtime results. The x86/x64
MinGW version is 14.0.0 alpha; Zig bundles 13.0.0 alpha. The parent public
layout probe records actual winnt.h input hashes in
`tests/fixtures/user/windows/layout/README.md`; installed upstream commits are
unknown. Probe SHA-256:
`17006a2a7d898074eef75eeb80d20f3fc97deb1c396b3027ce0320909d815970`.
Script SHA-256:
`6720547303dfd70b75c849af95c47555a2ef9a1f90b5436626aa1293db892058`.

## Assumption register and bounds

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | Guest threads and address-space mutations remain serialized; no embedder remaps concurrently with a built-in call. | Current one-host-thread process contract and AddressSpace checked chunk construction. | Transactional read/prepare/write/publication. | A cross-page lock write whose second page is read-only must preserve all bytes and host ownership. | Concurrent remap between AddressSpace chunks validation and copy_in would disprove transaction atomicity; instrument or embed that interleaving. | retained |
| A2 | Supported guest programs treat lock structures as opaque and use the exposed APIs; recursive shared SRW acquisition is not required. | Microsoft opaque-storage API contract and warning against shared recursion; synthetic ownership protocol. | Public API compatibility for the admitted guest program. | Inline private-field mutation, copied active lock storage, or recursive shared acquisition. | A program requiring native private-field inline manipulation or a successful recursive shared acquisition disproves compatibility for that program; execute its lock path under the personality. | retained |
| A3 | Process profile exposes one processor. | Startup writes processor count 1 in PEB/KUSER_SHARED_DATA and NUMBER_OF_PROCESSORS=1. | Zero effective CS spin count. | Initialize with a nonzero spin count, then SetCriticalSectionSpinCount must report the previous effective count as zero. | Inspect startup processor values; a changed count or introduced multi-processor profile requires rechecking the spin API behavior. | confirmed for current profile |

High-impact scope limits: native private encodings, unsupported shared recursion,
and remapping concurrency are not validated by these tests; all are explicit
profile constraints rather than advertised native equivalence. Medium-impact
limit: SRW owner-set snapshots have O(r) transition cost. Native low-power timeout
accounting and exact malformed-input fault/status outcomes are unknown. None
authorizes a native-admission expansion.

Validation ownership: this agent ran exact-file rustfmt and the compile-only
layout probe. Rust test/Cargo gates are coordinated by the root agent. Focused
filters: `user::windows::dll::locks::tests` and `user::windows::sync::tests`.
Tests use the three retained smoke PE fixtures, actual guest protections and
TEB LastError writes; no native Windows execution oracle is claimed.
