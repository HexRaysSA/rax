# Native Intel SDK access observations

The unmodified [SDK result](hvf-intel-vmcs-41954251789.json) and
[host preflight](hvf-intel-availability-41954251789.json) record an untranslated
Intel Core i7-8700B process on macOS 15.7.9 (24G830), built with SDK 15.5.
The host reports nested virtualization. These observations qualify SDK calls
on that host; they do not establish guest execution or physical-machine coverage.
[Provenance](provenance.json) retains the run, source commit, and file hashes.

The actual RAX guest run 41948895261 stopped during construction: writing
VMCS_GUEST_LINK_POINTER=0xffffffffffffffff returned HV_BAD_ARGUMENT.
It completed zero guest cases. Subsequent SDK-only sweeps observed:

| Interface | Observation |
|---|---|
| 68 VMCS candidates | 64 readable and write-capability-query supported |
| LINK_POINTER, IA32_PAT, IA32_PERF_GLOBAL_CTRL, SMBASE | Read and write-capability queries return HV_BAD_ARGUMENT |
| Six native syscall/kernel-GS/TSC-AUX MSRs | Read, enable-native, same-value write, and readback succeed |
| IA32_PAT MSR | Read and enable-native return HV_BAD_ARGUMENT; no write attempted |
| IA32_DEBUGCTL MSR | Read, enable-native, same-value write, and readback succeed |
| IA32_PERF_GLOBAL_CTRL MSR | Read and same-value write/readback succeed; enable-native returns HV_UNSUPPORTED |

The corrected implementation excludes LINK_POINTER and IA32_PAT from its SDK
field bank, retains the other two fields as optional, and stores architectural
PAT in the existing EmulatorState field. Its SDK model rejects the same four
VMCS IDs. New CPU records use RAXHVI02; the documented fixed-PAT legacy migration
preserves the prior producer's architectural reset value.

| Assumption | Stress test and falsification probe | Status |
|---|---|---|
| The observed SDK access boundary applies to the tested native profile | Construct/capture/restore with those fields rejected; rerun actual native guests | SDK evidence confirmed; corrected native execution pending |
| PAT readback and checkpoint state can be retained independently of the private SDK slot | All legal byte types, reserved types/bits, privilege faults, private restoration, and native guest readback | SDK-owner and portable codec regressions passed on the recorded source |

High impact: TSC-deadline is advertised while its current MSR handler does not
represent an armed timer. The reserved-MSR dispatch now injects #GP(0), with
precise effects checked by SDK-model regressions and independent KVM controls.
The native run stopped at its first RAM-only control; those faults remain
unqualified through HVF. Physical cache-type behavior is also
outside PAT readback evidence. This component does not close A32-FP, C-STATE,
C-SMP, or C-HVF.

The [SDK-model qualification](sdk-model-qualification.json) records eight complete
Cargo integration binaries: 200 passed, zero failed, ignored, or filtered. The
new native guest consumer cross-compiled and passed signature verification, but
executed zero cases in this local qualification. That record is historical. Its later-qualification section retains the
202-test reserved-MSR update, the historical 59-test owner run, and both frozen
full roots with exact source boundaries. The portable codec gate passed; the
130-case native guest binary has built, signed and uploaded on Intel macOS.
Run 41978606771 failed its first RAM-only control without retaining the exit.
The enhanced diagnostic in run 41983036300 subsequently records failed entry
`0x80000021`, basic reason 33. The independent KVM setup control passes.
The [frontier diagnostic](../hvf-intel-frontier/README.md) retains both source
identities and outcomes.

The later [SDK constructor matrix](../hvf-intel-frontier/ram-entry-controls.md)
reproduces that failed-entry boundary and reaches HLT in five full-shadow
variants. The [public-import correction](../hvf-intel-frontier/control-shadow-import.md)
passes the complete 60-test owner binary, with no failures, ignored or filtered
tests. Its compiled source and the current pending native foundation match.
Actual RAX run 41992554080 has built, signed and retained the corrected 130-case
consumer; independent local artifact checks confirm its source fingerprint,
executable checksum and signature. Native guest execution remains pending.
