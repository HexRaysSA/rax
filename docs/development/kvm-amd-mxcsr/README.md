# AMD MXCSR mask admission in shared XSAVE state

The shared XSAVE validator now admits AMD's MXCSR.MM capability at bit 17.
Actual image and imported MXCSR values still have to fit the specific recorded
host mask. Bit 16 and bits 18 through 31 remain reserved. An Intel-style mask
continues to reject MM; this change does not manufacture an Intel capability.

The KVM producer reuses this portable validator. GitHub run
[41628940533](https://github.com/HexRaysSA/rax/actions/runs/41628940533) reports
`MXCSR_MASK=0x0002ffff` independently through the Rust intrinsic and inline
assembly, with XSAVE mask `0xe7` and maximum image size 2432 bytes. The former
`0xffff` upper bound rejected that valid profile before reading public CPU
state: 2 native tests passed and 12 failed. The observed agreement between both
FXSAVE paths excludes the suspected intrinsic discrepancy in that run.

AMD's primary *AMD64 Architecture Programmer's Manual*, Volume 1, revision
3.22, December 2017, section 4.2.2, printed page 115, defines MM and its mask bit.
The complete unmodified manual is retained in `references/`; provenance records
the university mirror, version, checksum, original notices and unsuccessful
attempts to retrieve newer vendor URLs. This is an existing AMD extension,
not a new Rust or processor requirement.

The regression uses the actual portable module and its entire test source,
linked against RAX's public register, snapshot, codec and error types. Before
the fix it compiles and executes 15 tests: 14 pass and the new AMD round-trip
case fails with the same admission error. After the fix all 15 pass. It covers
SSE in-use and initial-state projections, public-register and emulator-private
overlays, rejection under an Intel-style host mask, and reserved-bit controls.
The first harness attempt omitted the codec import and did not compile; it is
excluded from the red/green counts. `qualification.json` records that limit.
These type-seam runs are not native KVM/HVF guest execution. Production native
CI is separately confirmed by run41630404578: the same `0x0002ffff` mask
profile passes 15 portable tests, all 14 selected native public-state tests and
2 minimal native tests, with no failures or ignored cases in those selections.
The release build also succeeds. `github-success.log` retains the actual
counts and raw masks; this does not qualify complete unfiltered library or
physical Intel HVF behavior.

The existing KVM job also runs the complete portable XSAVE test module and
triggers on changes to its shared implementation/tests. Reproduce those checks
on a Linux x86-64 host with usable KVM:

```sh
cargo test --locked --features x86_64-suite --lib backend::intel_hvf_xsave::tests:: -- --test-threads=1
cargo test --locked --features x86_64-suite --lib backend::kvm::state_tests:: -- --include-ignored --test-threads=1
```

| ID | Assumption | Basis | Dependent result | Stress/falsification probe | Status |
|---|---|---|---|---|---|
| M1 | The host may advertise AMD MM in MXCSR_MASK | Native intrinsic and assembly both report `0x0002ffff`; AMD section 4.2.2 defines bit 17 | Admit the shared native layout | Reject bit 17 under a host mask lacking it; reject bits 16/18/31 under either profile | Confirmed by native observation and portable controls |
| M2 | The shared parser must retain the full supported MXCSR value | RAX stores MXCSR as u32; native images carry the complete field | Preserve MM through projection and overlays | Compare `0x00021f80` before/after standard XSAVE projection and both overlays, with SSE active and inactive | Portable whole-module tests pass; production native public-state suite also passes on the formerly rejected mask profile |

High impact: complete KVM private/shared/in-flight checkpointing, native VMM AP
startup and the original A32/HVF requirements remain open. Physical Intel HVF
execution is not established by Linux KVM or these portable tests. No C ABI,
checkpoint wire version or source-to-destination host-profile equality rule is
changed by this mask correction.
