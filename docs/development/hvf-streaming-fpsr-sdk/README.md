# Current public-SDK streaming FPSR counterexample

The direct public-SDK control still reproduces streaming FPSR loss on macOS
27.2 build 26B5112a, SDK 27.2, Apple M4 Max. It executes no RAX code and uses
no private SDK calls. This is an unresolved native state requirement.

The [probe source](reentry-control.cpp) creates a fresh VM/vCPU for each
streaming/getter combination, executes scalar MRS/MSR FPSR instructions, and
exits through an unmapped scalar store. All 20 expected exit PCs and exception
classes are verified in the [current observation record](current-host-reproduction.json).
The binary is ad-hoc signed with the Hypervisor entitlement and its signature
is verified before execution. The temporary binary and entitlement file are
removed after the run.

| Mode | After guest writes FPSR=1 | Next ordinary entry | Later host writes 2/4 |
|---|---|---|---|
| Non-streaming | Guest reads 1 | Guest reads 1 | Guest reads 2/4 |
| Streaming | Guest reads 1 in the same entry | Guest reads 0x0800009f | Guest reads 0x0800009f |

Omitting the pre-entry getter does not repair the streaming case. A same-mode
SME setter followed by an FPSR setter also fails to preserve the requested
flags through the next entry. No RAX checkpoint operation is involved.

The SDK's `hv_vcpu_set_sme_state` documentation describes flags changing on
streaming-mode transitions. The control above additionally observes loss on
ordinary re-entry without an intervening SME setter. The exact kernel cause
and a transparent production repair remain unknown. Rewriting FPSR once at
restore does not satisfy the required ordinary-entry behavior.

[Provenance](provenance.json) records the installed SDK header path/hash and
the original and formatted probe source hashes. The SDK header is retained
locally under this documentation directory as a primary reference; the probe
build uses the installed SDK header.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| F1 | Each entry reaches the intended scalar status read/write and fault | Exact PC and exception checks; streaming/getter off/on, guest assignment and host assignments | Confirmed for all 20 entries |
| F2 | The failure exceeds RAX checkpoint publication | Direct public-SDK source; ordinary re-entry without any RAX call | Confirmed on this host |

High-impact consequence: complete native AArch64 state preservation remains
unproven. This observation does not remove advertised SME support, replace a
native-state repair, or close C-STATE. Other host/SDK combinations remain
unqualified by this control.
