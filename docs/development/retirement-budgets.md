# Explicit retirement-budget execution

`VCpu::run_retirement_budget(budget)` adds bounded execution over existing
single-instruction stepping. It returns both previously completed retirement
units and the reason execution stopped. One Hexagon packet is one unit. The
constant `DEFAULT_RETIREMENT_QUANTUM` is 1,000 units; existing `run()` methods
and the VMM run loop retain their prior behavior until a coordinator explicitly
uses this interface.

| Stop | Meaning | Retired units |
|---|---|---|
| BudgetExhausted | Requested budget reached without an architectural exit | Exactly the budget |
| Exit | Original halt, I/O, shutdown or other synchronous exit | Includes the successful final step if it retired |
| StateChange | Successful step delivered/transferred state without retirement | Includes earlier completed steps |
| Fault | Backend error, preserving its original error value | Includes earlier completed steps; excludes the failed attempt |

A zero budget performs no backend entry. A positive budget on a backend without
single stepping returns an error before entry. There is no fallback to unbounded
`run()`. Native KVM/HVF retirement-limited entry remains separate work.
A zero-retirement transition returns control immediately, preventing an
unbounded loop through exception or interrupt delivery. An exit at the exact
budget boundary retains its payload and takes precedence over exhaustion.

Existing eBPF/SBPF instruction meters charge an attempt before fetch. A failed
attempt remains charged in that meter while the budget result excludes it from
retirement. The implementation observes counter deltas only after successful
steps; errors return a structured stop with prior progress instead of erasing
that progress in an outer error. Counter wrapping from u64::MAX to zero is
admitted. A successful step claiming more than one retirement reports an
interface-contract fault; no rollback for a defective backend is implied.

For a conforming backend, each continued step retires one unit. A zero-retirement
transition, exit or error returns immediately. A budget B therefore makes at
most B + 1 step calls, with O(B + 1) time and O(1) additional space. Individual
step cost depends on instruction semantics. The arithmetic accumulator cannot
overflow: before an increment, retired < budget <= u64::MAX, and the admitted
increment is at most one.

| ID | Assumption and dependent result | Basis; stress/falsification probe |
|---|---|---|
| B1 | Successful stepping commits at most one instruction/packet. | Existing VCpu contract; twelve actual profiles exercise 0/1/999/1000/1001 budgets and exact PCs. A synthetic two-unit jump must report a contract fault. |
| B2 | A failed instruction does not retire. | Backend error contracts; actual eBPF/SBPF bad opcodes preserve prior progress while charging the legacy meter. Failures after partial architectural effects remain a backend issue. |
| B3 | Zero-retirement transitions must relinquish control. | Delivered exception/interrupt behavior; a scripted transition after retirement must return after exactly two calls; actual RISC-V software-interrupt delivery must return with zero retirements and exact mepc/mcause/handler PC, then resume one handler instruction. |
| B4 | Unsupported entry cannot be replaced with an unbounded run. | Capability admission before entry; scripted run panics if called, unsupported stepping rejects and zero budget remains a no-op. |
| B5 | Exit identity and prior progress remain observable. | Last-unit x86 HLT/OUT and BPF EXIT; scripted MMIO exit and backend error with both counter-charge states. |
| B6 | Execution is exclusively borrowed during a budget call. | Existing &mut VCpu and Send interface; concurrent coordinators, thread-safe requests and exact native entry remain separate work. |

LLVM 23 encoding probes retain the actual NOP/packet/ALU-zero inputs used by the
fixtures. The independent model calculates 60 exact rows across twelve profiles:
plane, requested budget, returned retirements, backend meter and PC. It checks
all 2,400 bytes and rejects a one-bit mutation in each of 300 output words.
This proves the bounded fixture domain; it does not establish arbitrary-program
semantics, scheduler fairness, checkpoint/replay or native virtualization.

High impact: deterministic/concurrent coordinator wiring, per-VM clocks, worker
coordination, IRQ delivery and native retirement boundaries remain open. Medium
impact: successful-step counters must retain the single-unit contract as new
backends/fast tiers are added. Low impact: future budget-aware JIT paths can
replace stepping only with direct boundary-equivalence evidence.
