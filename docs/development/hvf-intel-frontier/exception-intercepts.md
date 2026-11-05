# Preserve SDK exception intercepts during native Intel construction

[Run 42001141985](https://github.com/HexRaysSA/rax/actions/runs/42001141985)
passed 118 ordered native RAX cases and then rejected private capture with
`native Intel context: saved exception intercepts differ from policy`.
The earlier control-mask rejection no longer occurs. The signed build and
execution reports were retained by the same workflow job before and after
guest entry. This is a partial native result, not a successful 130-case run.

The [raw result](native-partial-42001141985.json),
[observations](native-partial-42001141985.jsonl), and
[stderr](native-partial-42001141985.stderr) identify the compiled source and
failure. The SDK's [initial field observation](../hvf-intel-sdk/hvf-intel-vmcs-41954251789.json)
reports exception bitmap `0x40000`, with the machine-check vector intercepted.
RAX's constructor subsequently wrote that bitmap to zero before freezing its
producer policy. Preserving the SDK default removes this unnecessary control
change. The failing native diagnostic does not retain the changed bitmap's
value, so identifying its exact post-entry difference remains an inference.

The [initializer](../../../src/backend/hvf/controls.rs) now leaves the exception
bitmap untouched while still validating all four required VMX capability banks
before its eight constructor writes. Later debugger-specific intercept changes
remain explicit. Private capture and restoration continue to require exact
producer policy, apart from their existing debugger-owned exception bits.
This correction does not permit an arbitrary changed intercept policy.

The host-independent regression supplies existing exception bitmaps including
`#MC`, debugger bits and all 32 vector bits, then executes the actual constructor
initialization path. It requires those values to remain intact. The original
initializer fails the new regression because it writes the exception bitmap.
The corrected complete `hvf_controls` target passes 11 tests with no failures,
ignored or filtered tests, including every capability and write-failure boundary.
The constructor still performs constant work and uses constant auxiliary space.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | Preserving the SDK's initial bitmap prevents its post-entry policy mismatch | Native capture correction | Compare the retained initial SDK observation and constructor writes; require a subsequent real RAX checkpoint to pass | Constructor retention confirmed; native correction unqualified |
| A2 | Required VMX controls and failure cleanup retain their contract | Constructor compatibility | Complete capability/initialization target, including every setter failure | Confirmed in all 11 tests |

High impact: corrected native private capture and continuation still require a
new run. The full state, SMP, A32-FP and HVF findings remain open. Medium impact:
the native runner is a hypervisor guest; bare-metal Intel behavior is unqualified.
