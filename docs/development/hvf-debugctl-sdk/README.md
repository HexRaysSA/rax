# SDK DEBUGCTL access and stepping observations

`tools/hvf/intel_debugctl_native.py` observes a fresh Intel Hypervisor.framework
VM for each of six cases. It links no RAX library. The purpose is to determine
whether guest DEBUGCTL access reaches a userspace exit and whether SDK entry
controls load BTF. An absent RAX MSR handler alone cannot answer those questions.

| Case | Guest or host setup | Observation frontier |
|---|---|---|
| read-msr | Guest RDMSR 0x1d9 | Delegated RDMSR, intercepted exception, or HLT |
| write-zero | Guest WRMSR 0x1d9, value 0 | Delegated WRMSR, intercepted exception, or HLT |
| write-btf | Guest WRMSR 0x1d9, value 2 | Same frontier, with DEBUGCTL readback |
| tf | Host DEBUGCTL=0, guest TF=1 | First exception after MOV or later exit |
| btf-default-entry | Host DEBUGCTL=2, guest TF=1 | Compare MOV and taken-JMP frontiers |
| btf-load-entry | Same, with VM-entry load-debug-controls bit 2 requested | SDK rejection or observed entry/exit |

The stepping sequence is `MOV R10, marker; JMP +0; HLT`. CODE is 0x10000;
the MOV ends at CODE+10 bytes and the taken JMP ends at CODE+12 bytes.
The MSR cases prepend RDMSR or WRMSR to `MOV R10, marker; HLT`.
The initial SDK exception bitmap is preserved and #DB/#GP interception is added.
All cases share the previously observed full-shadow RAM setup and constructor
operations. A main-function guard lets both probes compile the same setup.

The report retains raw stdout/stderr, source and executable SHA-256, SDK/OS/compiler
identity, core state, DR6, RDX, DEBUGCTL, pending debug, entry/exit controls,
exit-interruption information and qualification. Optional SDK reads retain their
status and a null value after failure. Configuration rejection is a complete
negative observation with no fabricated entry or exit. Each entry call is bounded
to 0.1 s, at most ten calls; each subprocess also has a 60 s timeout. Setup errors
fail the subprocess; completed observations must report successful resource
release. Temporary executable and signing files are removed by the wrapper.

```sh
python3 -B tools/hvf/intel_debugctl_native.py --output /tmp/hvf-debugctl-observation
python3 -B -m unittest discover -s tools/hvf -p 'test_*.py'
```

On Apple Silicon, use `--compile-only` to compile for Intel, sign and verify
without running a guest. The `native-intel-hvf-availability.yml` workflow executes
all six cases on its Intel runner and uploads them alongside the existing SDK
observations. A successful observation report does not assert ISA conformance,
hardware execution outside a nested host, or RAX guest execution. The separate
RAX native consumer remains the C-HVF execution gate.

| Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| The shared full-shadow setup can enter this SDK profile | Interpreting an exit as guest behavior | Record entry failure bit, SDK status and core state; compare the existing RAM control on the same runner | Retained pending native observations |
| DEBUGCTL access and BTF behavior may be SDK-managed | Whether RAX needs additional MSR dispatch or entry controls | Execute the three MSR and three stepping cases; inspect actual exits and control/readback fields | Unknown; no production change inferred |

High impact, non-blocking for collecting observations: BTF, LBR/BTS and data/I/O
breakpoint profiles still require production-path qualification. This probe
does not close A32-FP, C-STATE, C-SMP or C-HVF.

Architectural provenance: the retained December 2024 Intel SDM
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`, SHA-256
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`;
Vol.3B 19.4.1 identifies MSR 0x1d9 and BTF bit 1; 19.4.3 defines branch stepping
and BTF clearing on debug-exception generation; Vol.3C 28.3.2.1 defines loading
DEBUGCTL when the VM-entry load-debug-controls control is set. The observer
records those controls without assuming the SDK exposes the full hardware bank.
