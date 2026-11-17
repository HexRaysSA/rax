# Genuine CodeAddress byte relay reference

This corpus exercises the actual Python execution verifier, interpreter and
private runtime code registry. The positive program obtains its CodeAddress
from an actual verified `address_of`, splits it into eight ordered Raw8 values,
passes each through an actual generic typed helper call, stores and loads each
through guarded guest memory, returns each through that helper's actual SSA
continuation, and reconstructs the address from the eight-byte memory buffer.
Actual `code_bind` then produces a permit for an ordinary source-plan call to
the original verified identity function, which returns 42. The separate helper
return reconstruction has the same numeric bits. Per-fragment observations
include bit offsets, poison/undef masks and identity comparison with the actual
issued target and authority; diagnostics do not serialize private capabilities.

`cases.json` contains ten complete encoded modules and a separately verified
foreign producer module, with exact octet lengths and SHA-256 hashes. Every
execution witness decodes the exact fixture, constructs an original RootContext,
verifies its complete ABI and body, attaches its actual source-registry context
to an actual CodeRegistry and steps the verified Machine. No private origin,
source fact, address lane, permit or source-entry result is constructed by this
fixture helper. Fixture-local IDs do not allocate shared registry IDs.

| Case | Observed relation required by the test |
|---|---|
| relay | Eight helper entries/returns, eight stores/nine loads, same target and authority, one permit/entry, result 42. |
| mixed-foreign-equal-bits | One byte from a second genuine registry; equal bits, invalid reconstructed address, no permit/entry. |
| foreign-equal-bits | All bytes from a second genuine registry; equal bits, semantic `RT_CODE_REFERENCE`, no permit/entry. |
| reordered-zero-bytes | Swap two zero-valued byte fragments; unchanged bits, lost ordered origin, `code_address_invalid`. |
| numeric-byte-roundtrip | One byte passes through actual Int8 casts; unchanged bits, lost origin, `code_address_invalid`. |
| numeric-vector-roundtrip | Loaded bytes pass through an actual Int8 vector; unchanged bits, lost origins, `code_address_invalid`. |
| originless-zero-byte | Replace one zero byte by an equal literal; `code_address_invalid`. |
| stale-generation | Actually retire the owner and register the original source again at a later generation; old packet gives `code_address_stale`. |
| readonly-buffer | First actual helper store gives `memory_permission`; no binding. |
| short-buffer | Eighth actual helper store gives `memory_bounds`; seven helper returns, no binding. |

The original caller's address root remains live throughout the relay. The
foreign producer is paused with its genuine address root live. The retirement
control observes `busy_active` while that original activation remains retained;
it establishes stale-generation rejection, not completed code reclamation.
The witness does not establish independent lifetime retention by Raw8-only
storage, storage-holder implementation, external importer behavior, source
ABI revision 2, LLVM emission/external-state transport, native execution or
parallel execution. The generic helper has no source ABI plan; the final
indirect call has the actual original ordinary source plan. These are distinct
relations, and generic helper success does not admit a source-language call.

From the repository root, use a fresh, absent cache prefix for each command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/relay-check-normal python3.15 -B tools/smir-format/execution/code_address_bytes/generate.py --check
PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/relay-test-normal python3.15 -B tools/smir-format/execution/test_candidate_code_address_bytes.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/relay-test-optimized python3.15 -B -O tools/smir-format/execution/test_candidate_code_address_bytes.py
```

The generator authors only this new corpus. `--check` compares exact authored
bytes without writing. Each actual registry witness runs in an isolated child
with its parent's optimization mode; this preserves existing codec namespace
isolation. Normal and optimized runs each contain nine test methods covering
all ten execution profiles. Generation is O(P*N) time/space for P profiles and
N bounded encoded-module size. Witness execution is bounded by 1,000 actual
single-step iterations per profile; actual source-registry validation costs
remain those of the called reference implementations, not a new performance
or canonical-budget complexity claim.

Assumption register:

- BR1: authority originates exclusively in actual admission and `address_of`.
  Probe: real equal-bit foreign-registry and originless-byte rejection; inspect
  helper code for private-fact/opaque-origin construction or bypasses.
- BR2: generic Raw8 parameters, SSA returns and guarded memory preserve complete
  ordered fragments. Probe: per-byte parameter/return bits, masks and genuine
  target/authority comparisons; swap equal zero bytes and use numeric casts.
- BR3: binding uses the original complete source plan and current generation.
  Probe: complete RootContext ABI/body verification, actual retirement/new
  generation, zero permits/entries for every rejected case, unchanged original
  snapshots before and after execution.
- BR4: original caller and foreign roots remain retained. Probe: pause positions
  and actual retirement `busy_active`; after-root-release/storage-holder lifetime
  is explicitly outside this witness and must be tested separately.

High-impact remaining boundary: LLVM external-state transport must reproduce
these relations rather than infer authority from equal machine bits. Medium:
raw-only storage lifetime and parallel publication are separate implementation
work. Low: this reference package changes neither public wire grammar nor
existing lifted-ISA behavior. The bounded package has executable positive and
negative evidence; the platform compiler/runtime freeze gates remain open.
