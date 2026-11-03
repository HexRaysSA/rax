# Native PC PIT speaker-port ownership

PC initialization now creates the in-kernel PIT with `KVM_PIT_SPEAKER_DUMMY`.
The kernel then handles port0x61 together with channel2: gate writes, speaker-data
readback, OUT and refresh-clock status use the native PIT state. Previously the
kernel owned ports0x40..0x43 while the unrelated userspace system-control model
owned0x61; its OUT bit never reflected the native counter.

The existing generic `KvmVm::create_pit2()` configuration is preserved. Native PC
construction explicitly calls the crate-private speaker-wired constructor. A
separate actual native control requires the generic constructor to leave0x61
in userspace.

The native VMM regressions program channel2 mode0 with count16, enable its gate,
and read0x61 using byte, word and dword IN. The guest checks gate/data readback,
zero upper bits for the kernel stub, and eventual OUT, then writes a RAM marker
and requests ACPI shutdown. Its TSC wait is bounded by1000000000 cycles; no
fixed host duration or hard real-time latency is inferred from that cycle bound.

Against the unchanged complete library, all three widths produce0xbad00061 and
fail; all six prior discovery/startup controls pass. The first complete repair
passes all nine cases and all ten I/O cases. Adding the generic-constructor
control then exposes its configuration change:9 passed,1 failed. The final
implementation selects speaker ownership at PC initialization. Its complete
production library passes all ten native cases and all ten I/O cases. All17
canonical workspace, feature, lint, documentation, selected-unit and owning
gates pass; five documented examples remain ignored.

The final production CLI activates exactly1/2/4 CPUs with the same Linux
kernel and command line. Complete numeric activation lines are retained in
`linux-startup-native.json`; each guest then exits through its own console.
Linux still reports LAPIC timer verification failures, failed TSC calibration
and inconsistent die topology. CPU activation does not establish full OS boot
or correct clocks. `qualification.json` retains those open requirements,
complete native checkpoint/replay work and physical Intel validation.

The primary KVM API4.71 defines the speaker flag. The retained Linux6.8
`i8254.c` implements the linked gate/OUT/status behavior. This is the native
kernel device profile; physical PIT/audio equivalence is not established.
