# UCRT bootstrap policy witnesses

Six compiler-produced custom-entry PEs cover x86 ILP32 and x64/ARM64 LLP64
against `ucrtbase.dll` and genuine distinct runtime, locale, and math API-set
families. Sixty-six mode cells execute at scheduling slices of 1 and 4,096 guest
instructions (132 executions). No ordinary CRT startup objects, static startup
substitutions, native Windows execution, or successful unsupported stubs are
part of this corpus.

The policy calls are `_set_app_type`, `_query_app_type`, `_configthreadlocale`,
`__setusermatherr`, and `_fpreset`; `__pxcptinfoptrs` independently tests its
pointer-width thread-owned exception-pointer cell. Runtime API-set imports
cannot supply locale or math names; their own two API sets are emitted in the
actual IAT. The builder verifies exact per-DLL named imports from independent
`llvm-readobj` PE observations. Primary binding/publisher receipts are archived
in [CRT bootstrap references](../../../../../docs/specifications/windows/crt-bootstrap/README.md).

| Mode | Independent assertion |
|---|---|
| 0 | Raw `ExitProcess` control, with no CRT bootstrap call |
| 1 | App type initially 0; unconditional signed 32-bit store/query at enum and integer extrema; process-global cross-thread state |
| 2 | Locale 0 queries, 1 enables, 2 disables; returns old mode; -1 global-status operation does not change the caller's locale bit |
| 3 | Invalid locale values set errno 22 before the returning five-argument invalid-parameter handler; the callback's errno 73 replacement survives return -1; keep caller locale mode |
| 4 | Valid, non-executable-data, and NULL math handler registrations never eagerly invoke or validate a callback |
| 5 | Assembly-only raw FP before/after snapshots and genuine subsequent scalar FP arithmetic |
| 6 | Non-NULL exception-pointer cell; x86 ContextFlags mask 0x00010008 selects only DWORD StatusWord at byte offset 0x20 and TagWord at 0x24; x64/ARM64 leave this saved context untouched and never dereference a later pointer value 1 |
| 7 | Locale bit isolated between parent and worker threads |
| 8 | Default invalid locale handling terminates rather than returning fabricated success |
| 9 | Exception-pointer cell stable on repeated access and isolated between threads |
| 10 | Private assembly ISA-reset instrumentation control; same raw snapshot and scalar postcheck, but NOT exported `_fpreset` or ordinary startup |

FP mode deliberately poisons pending x87 ES/B, TOP=5, tags, opcode, instruction
and data pointers, arbitrary raw 80-bit payloads, MXCSR flags/masks/rounding, and
vector payloads. x86 requires nonwaiting FNINIT, defined control-word fields
`(FCW & 0x0F3F) == 0x023F` (53-bit precision, nearest rounding, all six exception
masks), MXCSR 0x1F80, and preservation of physical 80-bit register cells. The
publisher's FLDCW operand is 0x023F; reserved bit 6 native readback is unknown
and is not asserted. Intel SDM revision 086, Vol. 2A, FLDCW pp. 3-416–3-417
defines C0–C3 as undefined: the independent x86 FSW check masks only those
bits (`0x4700`), requiring `(FSW & 0xB8FF) == 0` while retaining TOP, ES, B,
stack-fault and all exception-status checks. FXSAVE logical ST(i)
indices are remapped after TOP becomes 0. x64 requires only MXCSR reset and
preserves the complete x87 environment/payload and XMM0..15. ARM64 requires
FPCR/FPSR reset while preserving all V0..31 payloads and NZCV. Raw post-reset
snapshots precede scalar arithmetic. The C compiler is prohibited from using
FP/vector registers; assembly saves/restores all caller nonvolatile integer
registers and the original complete FP state. These are selected publisher-body
contracts, not a claim of equivalence to every Windows SDK/runtime version.

```sh
ruby tests/fixtures/user/windows/crt_bootstrap/build.rb
ruby tests/fixtures/user/windows/crt_bootstrap/verify_rebuild.rb
ruby tests/fixtures/user/windows/crt_bootstrap/baseline.rb /absolute/path/to/preserved/rax-user
```

`manifest.json` records every owned source, tool executable/version, producer
recipe, emitted PE, disassembly, exact IAT, and independent expected case. Link
timestamps are zero. The preserved CLI recorder requires exact input/tool
hashes, seed 1, a cleared guest environment, a 64 MiB arena (67,108,864 bytes),
`RAX_NO_JIT=1`, and a 30 s external watchdog per execution. Its expected
pre-feature classifications are 108 missing-export failures and 24 successful
controls (12 raw exits and 12 private ISA reset witnesses); no failure is
classified as a verified postcondition. Input PEs
are immutable in each isolated drive. `verify_rebuild.rb` recompiles both C and
assembly in new temporary directories and requires byte-identical manifests,
PEs, IATs, and instruction observations, recording `rebuild.json`. This producer
repeatability receipt is not a native oracle.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Selected desktop default-state publisher UCRT bodies are the implementation contract | Root's pinned SDK/publisher EAT and disassembly receipts | Policy and architecture-specific reset assertions | All three ABIs; extrema, ES/TOP/vector poison, non-NULL saved context | Different pinned publisher bodies or actual native execution contradict the selected profile | retained |
| A2 | Public FXSAVE/FXRSTOR and ARM64 MRS/MSR/pair accesses preserve the raw snapshot layouts used here | Explicit assembly and ISA encodings in independently observed produced PE | FP payload and environment comparisons | Arbitrary 80/128-bit payloads, TOP remapping, all vector registers | An independent ISA/native probe reports different snapshot representation | retained |

Bounded findings: high—ordinary compiler CRT startup remains a separate frontier,
and absence of native Windows recordings prevents a native-equivalence claim;
high—the preserved RAX CLI reports STATUS_ACCESS_VIOLATION for an otherwise
valid x86 absolute-address FLDCW (`D9 2D abs32`) in the private instrumentation
routine. Removing that instruction instead reaches the explicit precision
postcheck failure (exit 71), while loading the same CW through EAX
(`mov eax, offset CW; fldcw word ptr [eax]`, `D9 28`) passes the complete reset,
raw-payload, and scalar-arithmetic control. The exact emulator defect is unknown;
no ISA code is changed here. The final instrumentation uses the genuine
register-indirect form, not an exported `_fpreset` substitution;
medium—runtime global-state isolation variants and automatic hardware-signal
publication into the exposed exception-pointer cell remain outside this corpus;
low—the finite fixture payload is a correctness witness, not a performance test.
No proprietary publisher source or DLL bytes are copied into this fixture tree.
