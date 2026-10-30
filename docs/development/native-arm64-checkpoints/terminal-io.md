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

Assumption probes and the change-surface map are in the qualification JSON.
Remaining high-impact requirements include concurrent independently entered SDK
CPU shutdown, entered-VM reconstruction, SDK streaming FPSR behavior, full
backend/platform/private-state coverage, all registered writer coordination,
complete clock/debug/replay integration and physical Intel HVF validation. The
remaining A32 capability/control and HVF MMIO/intercept requirements also retain
their original scope. This component does not close the four-finding objective.
