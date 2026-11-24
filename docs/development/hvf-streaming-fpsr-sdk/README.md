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

Two further direct public-SDK controls were rebuilt, signed, verified and run
from the retained formatted sources. Their [280-entry record](controls-v2/qualified-controls.json)
contains counterexamples to two possible repairs. These observations execute
no RAX code and establish no production repair.

| Control | Entries | Non-streaming status mismatches | Streaming-requested status mismatches |
|---|---|---|---|
| Four host-thread FPSR seeds, getter off/on, five guest boundaries | 80 | 0 of40 | 32 of40 |
| Five public Z/P access orders, ZA off/on, getter off/on, FPSR written last | 200 | 0 of100 | 80 of100 |

The [host-seeding probe](controls-v2/host-fpsr-control.cpp) restores its original
host-thread FPSR immediately after each entry. Every observed host before/after
value equals its seed; the streaming-requested guest mismatch remains. This
falsifies host FPSR contamination as the explanation in this control.

The [public vector-state probe](controls-v2/vector-order-control.cpp) compares
no access, Z0 read, Z0 read/write, P0 read/write and both read/write sequences.
It sizes buffers from the public maximum streaming-vector-length query and
writes FPSR after the vector operations. Each of the ten access-order/ZA
partitions retains eight mismatches. The guest's own FPSR write still reads
back correctly within that entry. Neither public vector access nor FPSR-last
ordering repairs the observed next-entry loss.

All280 expected fault PCs and scalar data-abort exception classes were verified.
The probes advance past the deliberately unmapped store after each observation.
The public SME setters and Z/P calls return success; these additional probes do
not independently sample guest SVCR or vector contents. Other host/SDK versions
remain unqualified. Formatted source, executable and header hashes, exact
commands, original-source transformation, raw records and assumptions F3/F4
are retained beside the source. Sources and raw records are unchanged after
qualification; temporary executables use the same owned build cache as the
current I/O work and are removed when that cache becomes idle.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| F3 | Host-thread FPSR contamination explains the guest loss | Four seeds, before/after reads, immediate original-state restoration | Falsified on this host;32 streaming-requested mismatches remain |
| F4 | Public Z/P access with FPSR written last repairs the guest loss | Five access orders, ZA off/on and getter off/on | Falsified on this host;80 streaming-requested mismatches remain |

The high-impact C-STATE requirement remains open. The medium-impact limit is
one host/SDK combination and unsampled guest mode/vector contents. No adjacent
low-impact change is required.

## macOS 27.3 runtime replay

The unchanged public-SDK reentry control reproduced the counterexample on
Apple M4 Max with macOS 27.3 build 26C5035r and SDK 27.2. All 20 rows matched
the macOS 27.2 observation record, including the exit PC, syndrome, and guest
FPSR. All ten non-streaming entries returned the expected value. Eight of ten
streaming entries returned `0x0800009f` in place of the expected value.

The replay built with `clang++ -std=c++17 -Wall -Wextra -Werror` and linked
Hypervisor.framework. Signature verification succeeded for the executable
signed with the Hypervisor entitlement. The installed header SHA-256 matched
the original provenance. Stdout SHA-256 is
`35926003adb4c613a4db4fb8594bf105ee94f80ae9ecb8a16b5c739db7a4dcc8`.
The owned executable was removed. A transparent native repair remains unknown.

The signed RAX native checkpoint module at
`2a09163d518440deefe4860aeb7c50dda9dd674d` reported 28 passed and one failed
on the same host. The first serial invocation reported 23 cases in 720 s.
The six unreported cases ran with the same signed executable and all passed.
The single failure was reproduced separately with that executable. Both
non-streaming modes passed before the streaming case read `0x0800009f`
where the test expected `1`. The streaming ZA-enabled mode was outside the
completed path. The checkpoint cases that passed include one-, two-, and
four-vCPU continuation, pending input and output, and rollback after a late
SDK GIC rejection. The test executable SHA-256 is
`0c3b3d43a49e165fb06d2e3ef3873c8246f780475b77a55fdc64ce5f86777c6c`.

## Guest-initiated streaming entry

The public-SDK [mode-entry probe](streaming-mode-entry.cpp) compares a
non-streaming vCPU, an SDK streaming-mode setter and a guest `SMSTART SM`.
Each mode runs with and without the SDK SME state getter. The guest reads
SVCR every time. All 18 entries reached the expected PC and data abort
at IPA `0x09000000`. Both streaming entry methods produced guest SVCR=1
with ZA disabled for all their entries.

| Mode | Same entry after guest writes FPSR=1 | Reentry without status write | Reentry after host writes FPSR=4 |
|---|---|---|---|
| Non-streaming | `0x1` | `0x1` | `0x4` |
| Host SDK setter | `0x1` | `0x0800009f` | `0x0800009f` |
| Guest `SMSTART SM` | `0x1` | `0x0800009f` | `0x0800009f` |

| ID | Assumption | Falsification probe | Result |
|---|---|---|---|
| F5 | The loss requires the host SDK SME mode setter. | Execute guest `SMSTART SM` before writing FPSR, verify guest SVCR, then reenter. | Falsified on the tested host. All eight later streaming reads differ from the expected values. |
| F6 | Reading SME state through the SDK causes the loss. | Omit the SDK mode getter while still reading guest SVCR. | Falsified on the tested host. The getter does not change any guest result. |

Two signed runs produced byte-identical [stdout](streaming-mode-entry.stdout)
on Apple M4 Max with macOS 27.3 build 26C5035r and SDK 27.2. The signed
executable passed strict verification before either run. Stdout SHA-256 is
`83f91f6935d96098aab2858796398e212cb8ce277e12f2937e4c3b5ba8eb07`.
From the repository root:

```sh
probe_dir=$(mktemp -d)
xcrun clang++ -std=c++17 -Wall -Wextra -Werror \
  docs/development/hvf-streaming-fpsr-sdk/streaming-mode-entry.cpp \
  -framework Hypervisor -o "$probe_dir/streaming-mode-entry" &&
codesign --sign - --entitlements rax.entitlements --timestamp=none \
  "$probe_dir/streaming-mode-entry" &&
codesign --verify --strict "$probe_dir/streaming-mode-entry" &&
"$probe_dir/streaming-mode-entry"
probe_status=$?
rm -f "$probe_dir/streaming-mode-entry"
rmdir "$probe_dir"
test "$probe_status" -eq 0
```

The failure affects ordinary native vCPU reentry even when the guest alone
enables streaming mode. A transparent production repair and the underlying
kernel mechanism remain unknown. This probe covers one host/SDK pair and
tests ZA disabled. C-STATE remains open.
