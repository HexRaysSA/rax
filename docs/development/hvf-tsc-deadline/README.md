# TSC-deadline admission and expiry controls

The Intel HVF CPUID profile advertises TSC-deadline support, but its current
`IA32_TSC_DEADLINE` (MSR `0x6e0`) dispatch returns zero and discards writes.
This observer establishes independent execution controls for the pending fix;
it does not change that backend behavior or qualify macOS HVF.

The architectural source is the [Intel SDM](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf),
revision 086, December 2024, Volume 3A, section 12.5.4.1, printed pages
12-17/12-18 (one-based PDF pages 3491/3492). Its SHA-256 is
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`.
LVT timer bits 18:17 select one-shot (`00`), periodic (`01`), or deadline
(`10`); `11` is reserved. Deadline mode uses an unsigned 64-bit absolute TSC
value. Zero disarms it, and changing between deadline and other modes disarms
it. Initial-count writes are ignored and current-count reads return zero in
deadline mode. The kernel API's [section 4.46](linux-v6.8-kvm-api-cpuid.rst)
defines how to enable the guest feature on Linux 6.8; its
[provenance](linux-kvm-api-provenance.json) identifies the exact source.

Run on Linux x86-64 with an Intel CPU and an accessible `/dev/kvm`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/hvf/intel_tsc_deadline_kvm.py \
  --output /tmp/rax-deadline-observation-new
```

The wrapper refuses other hosts and an existing evidence directory. It requires
the existing KVM `ignore_msrs` policy to be disabled and does not modify that
policy. The program requires `KVM_CAP_TSC_DEADLINE_TIMER`. Each scenario creates
an independent VM with an in-kernel local APIC and exposes CPUID.1:ECX[24]. The actual
guest reads that CPUID leaf and executes CPL0 WRMSR/RDMSR and xAPIC MMIO with
MFENCE after LVT writes. IF remains zero to retain observable pending IRR bits.
Three intercepted port outputs expose successive observations; no claim is made
that the final pending port operation has retired. The host waits at least
20 ms between the first two observations. This interval is not a timer-latency
or precision measurement.

| Case | Configuration | Required or measured outcome |
|---|---|---|
| 0 | One-shot, write `UINT64_MAX` | MSR reads zero; write ignored |
| 1 | Periodic, write `UINT64_MAX` | MSR reads zero; write ignored |
| 2 | Deadline, write `UINT64_MAX` | Full 64-bit value remains readable |
| 3 | Deadline, write `UINT64_MAX`, then zero | Disarmed; MSR reads zero |
| 4 | Armed deadline, switch to one-shot | Disarmed; MSR reads zero |
| 5 | Armed deadline, switch to periodic | Disarmed; MSR reads zero |
| 6 | Armed deadline, write initial count | Deadline retained; current count zero |
| 7 | Armed deadline, change mask and vector | Deadline retained |
| 8 | Unmasked deadline, write one | Observed MSR zero, vector `0x51` in IRR |
| 9 | Masked deadline, write one | Observed MSR zero, no vector `0x51` in IRR |
| 10 | Masked deadline, write one, later unmask | Observed MSR zero; no pending vector appears |

Cases 0-7 have explicit architectural assertions. Cases 8-10 record the expiry
outcomes without turning this single KVM implementation into an architectural
definition. In particular, masked expiry is not inferred from an unmeasured
physical APIC. The sampled guest TSC exceeds one in every scenario, establishing
that the selected expiry value is already in the past.

The [complete observation](kvm-observation.json) came from an Intel Xeon
E5-1650 v3 running Ubuntu Linux 6.8.0-138. The
[qualification inventory](qualification.json) records 20 complete repetitions:
220 executed guest scenarios, 160 asserted controls, and 60 expiry observations.
All asserted controls passed, and each expiry case retained the same outcome
across the 20 runs. All temporary observer build directories were removed.
A macOS negative control refused before attempting guest execution. The initial
probe incorrectly required the CPUID bit from `KVM_GET_SUPPORTED_CPUID`; it
refused before guest entry. The corrected probe uses the documented capability
and explicit CPUID admission. That refusal is retained in the qualification
record and is not counted as an architectural failure.

The observer performs a fixed 11 scenarios with 65536 bytes of guest RAM per
live VM. Runtime and auxiliary storage are constant with respect to guest
inputs. Its execution timeout is a harness bound, not an architectural bound.

| Assumption | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| A1: the guest profile admits TSC-deadline instructions | Interpretation of MSR observations | Require KVM capability, in-kernel APIC, guest CPUID bit, and nonzero future-value roundtrip | Confirmed on this host |
| A2: mask/expiry behavior is stable on this KVM profile | Input to the HVF implementation design | Twenty independent repetitions; any differing MSR/IRR tuple falsifies stability | Confirmed for these 20 runs |
| A3: these KVM results predict native HVF behavior | Native implementation qualification | Execute corresponding guests through RAX on the Intel macOS runner | Unknown; not claimed |

High-impact remaining work: implement and qualify the advertised HVF deadline
facility, including private checkpoint state, mode transitions, per-CPU clock
ownership, halted-CPU wakeup, and coordinated interrupt delivery. This observer
does not close those requirements or the separate KVM private timer-phase gap.
