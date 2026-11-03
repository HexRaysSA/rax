# Shared RISC-V AMOs, Zacas and admission

RISC-V W/D AMOs and W/D/Q compare-and-swap now execute one typed transaction in
the physical RAM writer domain. System, embedded, translated C API, Linux process
and GSC adapters use the same boundary as tracked writes, LR/SC and stopped RAM
checkpoint publication. Direct execution and the existing native helper ABI use
that transaction. No callback, page translation or HTIF notification runs under
the RAM locks.

RV32 AMOCAS.D admits even register pairs. Both halves of an x0 source pair read
zero; an x0 destination discards both results. Address, compare and replacement
are captured before any destination write. The SMIR lifter packs the two words
into an existing 64-bit scalar CAS and splits its result, including register
aliases. RV32 atomic addresses and register results are masked to 32 bits.

Zacas enables Zaamo independently of A/Zalrsc. Direct decode and the public SMIR
lifter reject reserved LR fields, disabled LR/SC and invalid XLEN/width/pair
forms through the shared decoder. This does not add a separately selectable
Zaamo or Zalrsc configuration field.

CAS requires read and write admission even on a comparison miss. Shared RAM
omits the failed comparison store after admission. The private Memory default
may write the old value back, which Zacas permits; this also enforces write
access for private providers whose probe does not report asymmetric permissions.
Shared/device providers must override that default with their owner transaction.
Process Write translation still performs code invalidation and private-copy
charging before the operand is read under the RAM lock. Physical mapping changes
still require stopped CPUs.

UART and GSC peripheral/core-local atomic operands reject before device effects.
An actual RAM write invalidates peer reservations, including a same-value AMO
or successful same-value CAS. A failed shared CAS does not invalidate the peer
reservation. HTIF notification and GSC RAM trace publication follow a committed
write outside the lock. Atomic aq/rl fences may provide stronger ordering than
RVWMO; this is not a complete RVWMO model qualification.

## Primary source and independent evidence

The retained RISC-V Unprivileged Architecture version 20250508, sections 13.2,
13.4 and 15.1, defines the selected behavior:
[local primary](../../specifications/riscv/riscv/riscv-unprivileged.txt).
Its SHA-256 is
`15cf782ec980195c28fc3085b88bf5eb5c408b366f77ead536f10151e71f467f`.
LLVM matched 128 encodings across widths, operations and aq/rl fields and accepted
Zacas AMOs without A enabled.

Four original tests were observed failing before the implementation. Two
additional raw-SMIR regressions failed before its admission fix: reserved LR
with nonzero rs2 and Zacas-only admission. All are retained as red/green evidence.

The installed QEMU 11.1.2 executes four-hart RV32 and RV64 programs that check
unique AMOADD.W old values 0..255, all nine scalar AMOs and pair CAS hit/miss.
RAX executes the same instruction bytes through four backend harts interleaved
by the witness host. This qualifies backend instructions, not VMM startup.

The full RV64 program exposes an installed-QEMU discrepancy after AMOCAS.Q
x0,x0: a following ADDI using x0 reads a nonzero value within the translated
block. The trace and failing original program are retained. The common RV64
comparison excludes those x0 cases; it does not convert the original failure
into a pass. RAX separately checks the full program and x0 cases against section
15.1. The installed binary's source implementation is unknown.

## Validation

The unfiltered root library passed 12125 tests, with 0 failures and 35 ignored.
The 43 affected integration executables passed 803 tests, with 0 failures and
8 ignored, including all 245 C API tests. Four host-gated targets contain no
runtime tests here: riscv_diff, riscv_vector, riscv_smir_x86_jit and hvf_intel_owner.
The focused checks passed 33 test functions; seven supplemental checks include
the raw-SMIR profile retry, three exact-program mirrors, first-touch CAS at all
widths, four contending process harts on demand-populated pages, and actual
direct/native execution under a Zacas-only profile. Native cases assert
actual O0/O1/O2 execution without interpreter fallback. The matrices cover all
nine guest scalar AMOs, twelve native helper operations, all modeled CAS widths,
read-only and write-only admission, zero pairs, aliases, fragmented backing,
competing harts, same-value writes, and UART/GSC/HTIF effect boundaries.

Workspace formatting, all-target build/check/Clippy and no-debug/no-JIT checks
passed. Doctest commands executed zero examples and left five ignored. All 19
C/C++ consumers ran, and seven C ABI translation units compiled. The initial
all-target build records 6000 project inputs; the final audit across all profiles
records 6001, including Cargo.toml. No untracked unowned source was consumed,
and all recorded input bytes remain unchanged.

Complete commands, executable identities, compiler input hashes, actual skips
and retained raw receipts are in [qualification.json](qualification.json).
No C declaration, C layout, SMIR opcode or private checkpoint format changes.

## Assumption register

| ID | Assumption and dependent result | Stress/falsification probe | Disposition |
| --- | --- | --- | --- |
| A1 | A naturally aligned N-byte operand, N=4/8/16, fits a 4096-byte translation page | Because N divides 4096, its maximum aligned offset is 4096-N and last byte is 4095; test final operands and fragmented physical backing | Confirmed for the existing translation contract |
| A2 | Read/Write translation can populate or charge a private page and invalidate code | Test asymmetric permissions, logical private-copy charging, code epoch and differing Read/Write physical results; physical map mutation during entry would falsify the owner contract | Confirmed; map mutation still requires stopped CPUs |
| A3 | A failed Zacas comparison may omit a store or write back its old value | Section 15.1 and read-only providers with/without an accurate probe | Confirmed; both policies still require write admission |

The pure operand transform takes O(1) time/space for operands of at most 16 bytes.
The shared transaction retains the existing O(R) physical-range lock acquisition
and relevant monitor-slot invalidation cost. Large fragmented-map performance is
unqualified.

| Impact | Remaining scope |
| --- | --- |
| High | Complete RISC-V VMM secondary startup/controllers/clocks/replay; remaining A32-FP, C-STATE and C-HVF profiles; actual native Intel HVF validation |
| Medium | Installed-QEMU x0-pair discrepancy; fragmented-map performance; raw writers or aliases at different host virtual addresses require owner coordination |

All four original findings remain open. Shared AMO/Zacas transactions are an SMP
prerequisite and do not establish complete platform SMP.
