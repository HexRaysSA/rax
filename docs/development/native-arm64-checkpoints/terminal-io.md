# Pending native I/O at VM shutdown

VM-wide SYSTEM_OFF marks every native CPU terminal, including a peer paused at
an MMIO frontier. The previous context validator rejected that peer because it
combined shutdown with a pending transaction. All four signed physical-host
baseline cases failed at coordinated capture with `terminal CPU has an
unfinished I/O transaction`.

The context now retains valid transactions alongside terminal state. Existing
native entry checks return Shutdown before processing those transactions, so
repeated terminal runs preserve the complete private context. After a fresh VM
restores the CPU/shared/device/RAM file, explicit `wake` permits the transaction
to continue. This uses the existing RAX embedding API; it does not add a PSCI
architectural return from SYSTEM_OFF.

The four actual native file cases cover:

- An unserviced UART byte read: FIFO bytes remain available until restart.
- A consumed byte with a failed SDK destination write: both the reply and
  original error survive; the error is delivered once after restart.
- A consumed reply whose error was already delivered: retry writes the saved
  value without requesting another UART read.
- An undispatched UART register write: repeated handoff preserves the saved
  bytes until dispatch/acknowledgement; a second acknowledgement is rejected.

Each uses two native CPUs, guest-driven SYSTEM_OFF from a different CPU,
coordinated capture, real file save/load, fresh native VM construction and
post-wake guest execution. Actual PL011 FIFO contents distinguish a retained
reply from duplicate input consumption. The output case verifies absence of a
second handoff after acknowledgement. LLVM independently verifies the guest
instruction encodings. `terminal-io-qualification.json` records exact commands,
source hashes, signed executable verification and raw evidence locations.

The current selection passed seven signed physical native tests and 96 portable
format/snapshot/power/configuration tests. The additional native regressions cover
standalone terminal graphs and pending-I/O register overlays. Synthetic portable
file tests explicitly retain opaque synthetic GIC data; their role is complete
file/producer admission rather than SDK execution.

Wire fields, tags and public ABI remain unchanged. Previously valid records
remain accepted. Older readers reject the newly accepted terminal/pending
combination. Existing checks still reject invalid register/width metadata,
orphaned errors, missing or wrongly sized replies, conflicting input/output requests,
projection inconsistencies and CPU/shared terminal-state disagreement. Portable
negative controls exercise the retained reader and writer checks.

The runtime test module is `src/vm/runtime/native_terminal_io_tests.rs`. Build the
library test executable with `cargo test --locked --lib --no-default-features
--features x86_64-suite,smir-jit,hvf --no-run --message-format=json`. Use Cargo's
reported `executable` path, sign that exact file with `rax.entitlements`, verify
its signature, and run it with `terminal_io:: --ignored --nocapture
--test-threads=1`. The qualification record supplies the actual build/sign/run
arguments and environment used on Apple M4 Max/macOS 27.2. Native cases run
serially. A normal filtered Cargo run that leaves these cases ignored does not
establish hardware validation.

## Pending peer MMIO in a parallel round

RAX latches VM-wide PSCI shutdown inside the AArch64 HVF owner. The
coordinator preserves each undispatched peer MMIO transaction when the round
includes a terminal exit or the power owner reports a latched shutdown. This
covers partial collection results whose terminal exit is missing. The check
scans O(V) collected vCPU exits, queries the latch in constant time, and uses
O(1) additional space. Explicit embedding wake permits the saved transaction
to continue after restoration.
[Arm PSCI DEN0022, §5.10](../../specifications/arm/psci-den0022.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Both vCPUs entered the SDK before shutdown. | The peer waits for a guest release store by the caller before issuing its UART access. The host releases the caller only after collecting the peer's MMIO exit. |
| A terminal round preserves unserviced transactions in either collection order. | Dispatch the two actual exits in both orders. Compare the terminal private record, then save and restore it into a fresh VM with the source and its kernel gone. Check the guest's next PC, the saved UART bytes and write acknowledgement. |
| The power owner establishes terminal state independently of the result list. | Latch `SYSTEM_OFF` with a real HVC and retain only the peer's MMIO exit to model partial collection. Require dispatch to report termination and leave the peer's read or write pending through a detached file restore. |

On baseline `b977e0d39`, the peer-first order installed byte `0xab` in X0,
advanced the peer PC from `0x40002008` to `0x4000200c`, and cleared its pending
read after the shared terminal state was latched. The signed baseline log
SHA-256 is `7db97002f9740a99da119c14ffa7d46b390be12505063465726a8b3dd69f4291`.

The corrected test passed all four read/write and dispatch-order combinations
on an Apple M4 Max running macOS 27.3 build `26C5035r`. An independent parser
verified both saved PCs, the shared terminal bit, the exact pending read or
unacknowledged write, and the untouched PL011 FIFO and control register in
all four `.rxc` files. Its log SHA-256 is
`2d06834cd9d40e2370726ac701bb11590d7fff62312b25fd92c5187b5d609e73`.
The complete signed `terminal_io` module passed all five tests in 387.05 s.
Its log SHA-256 is `851ddad988f9e6397738bdd532e8557e8df25bd4ab6070c40c186486b4b6c382`.
The signed nonterminal PL011 dispatch regression also passed at two and four vCPUs.
The modeled native scheduling suite passed all 11 cases. Its log SHA-256 is
`50781088fa15c41b867437dad4472f300fc99ab82b97818730091a7168343845`.

On baseline `0e0d3dc95`, the dispatcher reported that the round could continue
with the shared shutdown latch set and only a peer read in its result list.
On an Apple M4 Max running macOS 27.3 build `26C5047e`, the corrected signed
harness passed both parallel terminal tests. The tests exercised six
read/write and collection combinations, including two with the terminal
exit omitted from the dispatcher input after the real guest HVC. Each
transaction completed once after detached restore and explicit wake. An
independent parser verified the pending I/O, saved PCs, terminal state and
untouched PL011 state in all six files. Its log SHA-256 is
`20f0952bfc15220a02a06a4da2ab43d6c62f1214c94bd8756ef59fa93d561312`.
Two signed nonterminal parallel tests and all 16 native scheduling tests
also passed. Apple Silicon Clippy and the Intel HVF cross-check passed.

Previously qualified scope and assumption probes are in the qualification JSON.
High-impact open requirements include broader terminal I/O profiles,
entered-VM reconstruction, SDK streaming FPSR behavior, full backend private
state, registered writer coordination, clock/debug/replay integration and
physical Intel HVF validation. A32 capability and control coverage and the
remaining HVF MMIO and intercept profiles stay open.
