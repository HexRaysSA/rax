# Independent physical Raw8 helper reference

This OWNCOORD draft implements seven physical helpers in independently authored C++
PER-BIT state, compared with the actual current Python Core SPAN implementation and
fresh verified Machine execution. It is not a backend, source issuer or runtime
adapter. All shared source and LLVM checkout files remain read-only.

Native request grammar is schema.json plus its executable canonical-byte constraint:
compact sorted-key ASCII JSON, unsigned integer tokens,32KiB/depth32/origins128,
Raw8/64, model memory64octets. Duplicate/escaped keys and floating spellings reject.
Seven operations: from_int8/freeze8/observe8/split_code64/join_code64/load8/store8.
The mask argument is a plain physical overlay utility, not a new SMIR atomic/volatile
or source bitfield ABI. Code join.raw is the concatenated preimage diagnostic; typed
state/origin/range is separate. Native labels never construct real Core pointers or
permits. raw_results accepts only raw-shaped fromInt/freeze/split/load results.

ReferenceSession preserves actual original B/max-attempts/native-path bindings and
immutable same-session refs/events. Failed attempts spend quota, not event serials
or guest writes. Constructor prepays finite captured-size+1 UNBUFFERED guard scans;
actual canonical resource failures retain the same object, with drift primary and
original resource as cause. Bounds cover application/FileIO positions, not kernel
cache read-ahead, CPU/RSS or host allocator guarantees. Memory outputs are functional
model images, never writes to actual Core memory.

Build (draft needs explicit absolute foundation; installed known layout derives it):

    SMIR_RAW8_REFERENCE_PROJECT=/path/to/current/rax3 python3 -B build.py \
      --llvm /path/to/pinned/llvm-project --output /tmp/raw8-native
    SMIR_RAW8_REFERENCE_PROJECT=/path/to/current/rax3 \
      RAW8_REFERENCE_BINARY=/tmp/raw8-native/raw8-reference \
      RAW8_REFERENCE_RECEIPT=/tmp/raw8-native/build-receipt.json \
      RAW8_REFERENCE_ARTIFACTS=/tmp/raw8-tests \
      PYTHONPYCACHEPREFIX=/tmp/raw8-fresh-cache python3 -B tests.py

Repeat in a new artifact/cache directory with PYTHONOPTIMIZE=1 and python3 -O -B.
No missing native tool is counted as a pass/skip success. cli.py drives a fresh
actual Machine profile with explicit --binary/--receipt/--profile. relocation.py
copies CURRENT dirty portable foundation (including untracked work), builds a fresh
native oracle from that installed-layout path with spaces, and runs actual bind42
normal/O with no draftoverride. No HEAD-only worktree or receipt transplant.

The real Machine owns address_of, eight typed calls/store/load/return, ordered join
and actual code_bind/call42. Native results are independent comparisons at actual
frontiers, never frame-value injection/permit/validator stubs. Foreign equalbits,
mixed/reordered/numeric/originless fragments and stale generation reject at their
actual later binding frontier. Original roots stay retained; storage-holder lifetime
reclamation is not implemented. Full-function tests are physical/reference evidence,
not source ABI2/body/init eligibility.

helper-image.ll compares all7 structural signatures against the actual pinned LLVM
parser/verifier/O1 with actual OptNoneInstrumentation. It is syntax/retention only,
not native opaque-R execution or semantic admission. Root-assigned public profile/
IDs and actual LLVM extraction/emission remain absent.

Assumptions/falsification probes are assumptions.json. HIGH required original source/
body/type/init/private events, semantic extractor and five wider/DataPtr/vararg/coro/
source-init compiler gaps remain incomplete; MEDIUM final source/namespace/guard/cost
qualification and integrator review pending; LOW no guest native/JIT/parallel/fullhost
or performance proof. Compiler freeze remains false. No universal C++ byte-law or
binary foreign C++ compatibility is inferred from these finite physical witnesses.
