# Native ARM64 Windows context fields

`profile-29704-v1.json` records naturally completed controls on the native
ARM64 Windows 10.0.29704 kernel. The sources, unmodified output, executable
hashes, and both actual PE inputs in the ZIP are retained. These observations
describe the native API and kernel boundary, not a RAX-generated oracle.

The CPSR control creates an owned suspended thread. Each CONTROL-only setter
is read back and then the original complete context is restored before the
thread executes. Ten inputs include zero, all bits set, NZCV, each investigated
PSTATE extension, single-step, and all DAIF bits. Every setter/getter succeeds.
Observed CPSR is `(input & 0xf0200000) | 0x40`: NZCV and SS survive, F is forced,
and the other tested bits are cleared. This is the Windows context conversion;
the OS-neutral AArch64 CPU retains its own architectural PSTATE contract.

The separate loader control arms an instruction comparator at the owned
thread's LdrInitializeThunk. Its handler copies the actual initial CONTEXT
argument, clears the comparator, and continues. The saved flags are 0x40000f,
including DEBUG and excluding the independently selectable X18 group. The X18
payload remains present in the fixed layout. The saved PC equals the initial
GetThreadContext PC, and the saved bank contains the newly armed comparator.
Both producers and all owned worker threads terminate successfully.

The debug-resume rows are retained for the subsequent bank lifecycle adapter.
Immediate setter readback preserves fields that actual context switching later
normalizes. Disabled-only banks become zero. With an active comparator,
address-only and context-aware slots have different control/address masks.
These hardware-dependent masks must not be inferred solely from an OS build
number or applied to the initial saved loader context prematurely.

| Assumption | Dependent result | Stress/falsification probe | Status |
| --- | --- | --- | --- |
| CPSR conversion follows the measured public control mask. | Windows ARM64 context capture/restore and initial status. | All-bit input, selected/unselected groups, paired native view, and actual installed-library exception context. | Native ten-case conversion confirmed; model validation recorded separately. |
| Kernel-generated context groups differ from the maximum API group mask. | Initial loader and scheduler-created exception contexts. | Capture initial loader argument with a newly armed comparator; retain independently requested X18 in the ordinary API path. | Initial kernel flags confirmed as 0x40000f. |
| Resume debug masks depend on implemented comparator capabilities. | Future bank lifecycle adapter. | Disabled fields, unaligned addresses, context-aware slots and inactive bank. | Native records retained; no generalization to other CPUs. |

The sources use only Windows SDK headers and kernel32/ntdll import libraries.
Compile for ARM64 with clang-cl or MSVC, C++20, static CRT, `/GS-`, and a console
link with `/entry:entry`. The compile/link command receipts are preserved in the
task qualification evidence. The profile binds source, output and actual PE
input hashes independently of compiler paths.

Scope limits: this corpus does not establish behavior on every Windows kernel,
AMD64 compatibility RF conversion, native AMD64-on-ARM64 exception-frame/XSTATE
layout, or data-watchpoint delivery. Those remain separate validation surfaces.
