# Native ARM64EC exception entry

The Windows 10.0.29704.1010 controls bind producer source, SDK header identity,
native scalar output and actual PE input hashes in `provenance-v1.json`.
`native-controls-v1.zip` retains the three executed inputs. The SDK version is
unknown; its exact header hash and consumed excerpts are retained. Build-command
roots are normalized as `{WORKTREE}`, `{MSVC_SPLAT}` and `{TOOLS}`.

The projected x64 NTDLL export `KiUserExceptionDispatcher` has RVA `0x328000`.
Its CHPE redirection selects ARM64EC entry RVA `0x30abe0`, whose code allocates
1744 B before the native ARM64 context. The plain ARM64 view exports a different
entry at RVA `0x1798f0`. These are finite observations, not constants in RAX's
entry-selection code. RAX resolves the selected projected export and its exact
owned redirection, checks instruction class, alignment, bounds and executable
mapping, then enters with a native ARM64 frame. Ordinary guest calls retain
their existing canonical-byte redirection guard.

The compatibility kernel exposes XSTATE enabled/volatile mask `0x7` and an
832 B save area. Feature 0 occupies 160 B at offset 0; feature 1 occupies 256 B
at offset 160; feature 2 occupies 256 B at offset 576. The 320 B extended payload
contains its 64 B header and 256 B upper-YMM bank. The selected kernel profile
publishes this shared configuration before RTL initialization. Installed RTL
owns its extended-context allocations. Other kernel profiles retain their
existing construction path.

All eight native LOW/HIGH/FULL floating selections set/get successfully, with
zero mismatches and natural process exit 0. The captured 32 pairs of 64-bit
vector halves and FPCR/FPSR values per selection are regression inputs. The SDK
assigns ARM64 LOW `0x40` and HIGH `0x80`; LOW includes FPCR/FPSR, HIGH does not.
ARM64 XSTATE/SVE uses `0x20`, independently of AMD64 XSTATE `0x40`.

The original SDK/CRT-free x64 fault fixture uses its existing vectored handler,
checks that exception address equals context PC, selects its continuation and
exits 0. Candidate v12 first completed naturally in 28.3 s with unchanged fixture
SHA-256 `6a249f7cd38a631635719959e6295be9104154b1f61d284e7de3fbb2b8729483`.
The installed runtime translated its private fault to application PC
`0x140001034`, re-raised with native context flags `0x4000cf`, and continued at
`0x14000103f`. The permanent native regression includes x64 on ARM64, preserving
its original 60 s and 2^26-attempt limits. Later qualification belongs to the
exact source frame and image receipts, not this historical first success.

Raw `NtRaiseException` retains the complete supplied native context. Raw ARM64
`NtContinue` validates logical register groups and the native debug bank before
mutation; unselected state remains intact. Public logical AMD64 XSTATE and ARM64
SVE remain rejected because this API does not capture those images.

| Assumption | Stress test and falsification probe | Status |
| --- | --- | --- |
| A plain ARM64 same-named export is the compatibility kernel entry. | Compare native/projected exports and exact CHPE mappings; run the original fault fixture. | Falsified. |
| Empty shared XSTATE metadata suffices for installed RTL. | Observe native configuration and extended-feature lookup on the original fault path. | Falsified by null lookup; measured configuration required. |
| Native contexts can pass through a legacy AMD64 projection without loss. | Include debug/partial flags, native-only registers and both vector banks; compare complete supplied images. | Falsified by native `0x4000cf` rejection; native image retained. |

High impact: other Windows kernels remain unmeasured for this compatibility
profile. Existing explicit profile admission is retained. Broader instruction
breakpoint/data-watchpoint integration remains separate. These observations do
not qualify unrelated full-process frontiers or inherited failing tests.

Shared Windows-personality Rust code compiles on Windows, macOS and Linux;
native installed-DLL execution requires Windows. Plugin/UI, mesh, persistence,
permissions, public C ABI layouts, feature defaults and packaging consume no
changed interface. C API compilation and actual Assist archive consumers remain
separate qualification gates. Metadata selection is O(log R + log C) for R
redirections and C code ranges; context/frame work and storage are bounded by
fixed architecture layouts, at most 1472 B for these native frames.
