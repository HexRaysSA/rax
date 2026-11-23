# Native backend power state without configured topology

The public backend API permits creating native vCPUs without first calling
`configure_cpu_topology`. Such VMs now retain one VM-wide terminal state for
PSCI SYSTEM_OFF/RESET. Previously only the calling core retained its terminal
latch, while shared checkpoint capture synthesized `shutdown=false`. A peer
could therefore enter again, and the private and shared checkpoint records
disagreed.

When no explicit power graph exists, CPU terminal reads, firmware shutdown and
explicit restart use a VM-owned atomic flag. The stopped checkpoint boundary
excludes entry and backend mutation while this flag is projected into the
existing `GlobalContext.power.shutdown` field. No checkpoint version or public
ABI changes. Once a graph is restored, its terminal state takes precedence.

Shared capture now synthesizes the default all-created-CPUs-on graph only when
no graph exists. The previous unconfigured-topology branch overwrote restored
CPU states while retaining pending transitions, producing an inconsistent graph
and rejecting a subsequent capture. Restored offline/transition states are now
retained.

`standalone-power-qualification.json` records the two signed physical-host
baseline failures, corrected results, source hashes, signature verification and
targeted regression/compiler gates. The host is Apple M4 Max, macOS 27.2.
`src/vm/runtime/native_standalone_tests.rs` exercises one/two unconfigured CPUs,
guest-driven SYSTEM_OFF, agreement of CPU/shared records at one stopped
boundary, restoration into a fresh backend VM, blocked entry without register
effects, explicit wake, and preservation of a restored pending CPU_OFF graph.
Existing configured native shutdown/CPU power file continuations are separate
regression gates. These backend API tests do not transport RAM through a file.

An owner with a posted slice also checks the standalone terminal flag before
each SDK reentry. A guest on a second owner can set that flag with SYSTEM_OFF
while the first is still in the guest. The first owner returns a shutdown exit
when it next reaches a host boundary and observes the flag. The periodic SDK
cancellation provides a boundary for a guest that keeps running. Cancellation
and host scheduling determine the elapsed time.

Before the change, a signed Apple Silicon backend probe returned
`Some(Shutdown)` on the caller and a plain yield on a peer after about 254 ms.
The peer had published a RAM marker and was spinning before the caller invoked
SYSTEM_OFF. The signed regression uses two and four native vCPUs. The caller
waits for every peer's marker, each peer reports shutdown in the same posted
slice, and stopped capture records the VM-wide terminal state.

Primary architectural context is the retained Arm PSCI specification
`docs/specifications/arm/psci-den0022.pdf`; source hash and host commands are in
the qualification record. The existing Apple SDK state/owner-thread references
and qualification boundaries remain in this directory's README.

Assumptions and falsification probes for the original standalone capture
changes are recorded in the qualification JSON. High-impact remaining
requirements include concurrent shutdown with peer MMIO, full file/RAM and
external writer coordination, entered-VM reconstruction, SDK streaming FPSR
behavior, clocks/debug/replay and native Intel execution. Full C-STATE, C-SMP,
C-HVF and A32-FP remain open.

The terminal/peer-pending-I/O capture candidate found during this group was
subsequently reproduced and repaired. See [terminal-io.md](terminal-io.md) for
the four signed physical file/restart cases and their evidence boundaries.
