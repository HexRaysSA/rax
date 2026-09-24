# Source layout

The source tree is organized by responsibility rather than by historical
implementation path:

| Directory | Owns |
|---|---|
| `isa/` | Guest instruction decoding and architectural semantics |
| `machine/` | Guest platform selection, boot, address maps, and device wiring |
| `backend/` | Execution mechanisms and their `VCpu` adapters |
| `devices/` | Device models and I/O buses |
| `vm/` | Architecture-neutral VM runtime, memory, snapshots, and vCPU contracts |
| `smir/` | Cross-ISA IR, lifting, interpretation, optimization, and lowering |
| `oracle/` | Static ISA decode/lift oracle output |
| `user/` | Userland (process-level) emulation: executable images, guest address spaces, OS personalities |
| `debug/` | Interactive debugger protocols |
| `observability/` | Tracing and profiling |
| `host/` | Host console and terminal integration |

The primary collaboration graph is:

```text
cli -> vm/runtime -> machine -> devices
                  -> backend -> isa
                             -> smir
oracle ---------------------> isa + smir
rax-user -> user -----------> isa
```

This is not a strict directed acyclic graph: machine initialization exposes a
KVM hook, while platform-specific backend adapters consume machine constants
and runtimes. That bounded `machine <-> backend` coupling is explicit; ISA and
device ownership remain in their respective directories.

Compatibility re-exports in `lib.rs` and thin files under `backend/emulator/`
preserve former public paths during the migration; they own no implementation.
New code should use the canonical directories above.

Device ownership is intentionally unchanged by this reorganization. Machine
modules wire device models but do not duplicate or redistribute them.
