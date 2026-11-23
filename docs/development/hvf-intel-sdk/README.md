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

## CR0.NE backing and read shadow

The `cr0_ne` availability workflow input selects an SDK-only control. A
long-mode guest reaches a port marker, reads CR0, then clears and sets NE
with two MOV-to-CR0 instructions. The client checks the VM-exit reason,
qualification, operand and instruction address before publishing each
new shadow value. It checks the VMCS backing value, the guest's CR0 reads
after each transition, and the final HLT. The workflow archives the
signed Intel executable and the SDK readbacks.
[Intel SDM, Vol. 3C, §§25.8 and 26.6.6](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

| Assumption | Falsification probe |
| --- | --- |
| The programmed NE mask intercepts both changes against the current shadow. | Require two ordinary control-register exits at the assembled MOV addresses, with qualification zero for MOV to CR0 from RAX. |
| The SDK exposes the logical NE bit without changing VMX backing. | Require guest reads of one, zero and one, with the backing CR0 unchanged after both writes. |

The signed control tests register access. Full CR0 writes that also change
unmasked bits, native x87 error delivery, and coordinated checkpoint
continuation are separate validation cases.

The first hosted control reached its port marker and observed mask
`0x60000020`, including the SDK's CD and NW mask bits. Its exact-mask
check stopped the experiment before the first MOV to CR0. The second run
required NE in the mask and checked the unchanged values of all other
bits. The guest then read `0x80010033`, `0x80010013`, and
`0x80010033` and reached HLT at `0x10020`. Both MOV instructions
produced exit reason 28, qualification 0 and length 3. The VMCS CR0
field and the SDK register API both read `0x80010033` at each exit. An
architectural view of these controls must account for the read shadow.
[Initial Intel run](https://github.com/HexRaysSA/rax/actions/runs/45091163237/job/137420788647)
[Corrected Intel run](https://github.com/HexRaysSA/rax/actions/runs/45091686348/job/137422440650)

The corrected run used revision
`ed612cc59359f77d2d018517594033c72b64019d` in an untranslated Intel
macOS process inside a hypervisor guest. Artifact `14781528116`
matched SHA-256
`5fbb1e8a833686487679ab94ec0aed533494ad1f860c4fd31f79b49e6afdbc26`.
The downloaded executable passed strict signature verification with the
hypervisor entitlement and matched its reported source inputs. Production
RAX still rejects this CR0 exit. A full implementation also needs to
preserve the guest's x87 error-delivery mode when NE is clear.

The same workflow input also runs a fresh SDK VM for the x87 case. It
clears the guest CR0.NE shadow, keeps the VMX backing bit set, and
intercepts vector 16. An x87 divide with its exception unmasked leaves ZE
and ES set. The probe checks whether the next FWAIT produces a native
`#MF` exit at the original instruction address. A physical Intel Linux
control confirmed a divide-by-zero signal at FWAIT with ZE and ES set,
and normal FWAIT completion with the exception masked.
[Intel SDM, Vol. 1, §§8.7.1 and 8.7.2](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The hosted x87 case stopped at FWAIT at `0x10024` with VM-exit reason
0, interruption information `0x80000310` and x87 status `0xb084`.
The guest had read NE clear from CR0 while its VMX backing still had
NE set. Changing the shadow therefore leaves native `#MF` generation
active on this SDK. Legacy IRQ13 delivery needs separate handling.
[Hosted x87 control](https://github.com/HexRaysSA/rax/actions/runs/45092447779/job/137424827408)

The signed control repeated both NE transitions and the final HLT in a
separate VM in the same run. It used revision
`9963eb009fefcf20acd9d1d04b3b82b2d6ca2334` in an untranslated Intel
process inside a hypervisor guest. Artifact `14782365805` matched
SHA-256 `d76a68dc7ace563f32aa2ddebb31383f5714dacfcbc23a5d225488aeed299efb`.
The executable's signature, entitlement, architecture and three C
source digests were independently verified.
