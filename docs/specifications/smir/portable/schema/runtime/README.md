# Runtime candidate schemas

`candidate.json` is generated from the runtime owner's `schema_build.py` and
contains exact ordered record declarations. It supplies executable profile-0.2
payload roots, not a complete verifier or executable admission token.

| Section | Root |
|---|---|
| 2 | runtime_symbols |
| 4 | runtime_data |
| 5 | runtime_relocations |
| 6 | runtime_imports |
| 7 | runtime_tls |
| 9 | runtime_capabilities |

Every root starts with payload_revision:u32=1. Section2 identity follows that u32;
canonical content hashing zeroes only its 32 bytes at offsets4..36. All ten
sections are required and independently verified together by the integrator.
Private deployment/live-state roots are state protocols, not extra module sections
or durable/public snapshot restore interfaces.

Section 5 contains payload_revision, relocations, constant_initializers. Its
constant records identify a positive-access actual layout, restricted verified
function and whole-segment selection association. Both GEP steps and the final
relocation carry explicit check_base; no missing-field default is encoded.
The 177-helper catalog includes journal_begin's journal_captures metadata template:
actual SELF program formals expand in declared order to a fixed portable function.
None is missing metadata; [] is an admitted zero-formal environment.

Live state includes partial_objects after lifetimes. Completed certificates save
captures/counts and explicit child owners. Claims use full thread/activation/
generation/instance tuples. Journal seeds discriminate object versus partial;
partial records distinguish historical completed from current live children.
Only actual process registries and private issued handles can authorize these
facts. A structurally valid serialized record never reconstructs authority.

The shared codec uses LE u8/u16/u32/u64 and signed equivalents; bool is one byte
0/1. UTF-8/hex/byte strings have u32 byte count, strict UTF-8 where specified;
digest32 is exactly32 B. Token has u8 count1..63 with the common token alphabet.
Vectors have u32 element count. Options are tag0 None or tag1 followed by value;
in JSON witnesses tag1 is `{some:value}`. Nested option presence is preserved.
Variants use the common discriminator/string-tag grammar. Ordered fields have no
implicit padding, omitted fields or host-native layout. Unknown fields/tags,
duplicate keys/IDs where prohibited, noncanonical booleans and trailing bytes
reject. Reference materialization limits are resource failures, not ABI limits.

Entity refs are module:self or dependency slot plus table-specific u32 ID. The
consuming field/helper catalog defines the namespace; the same number in another
table does not resolve it. Consumer declaration IDs map explicitly to provider
exports and then private IDs. File assertions, body digests and callbacks do not
self-certify actual roots. Runtime validation joins source/execution/physical/
function/import/export relationships, mandatory grants, exact registered requirement
versions, TLS hooks and admitted native facts. Selection precedes code/data tokens.

`helpers-v1.json` gives complete internal helper templates, allowed contracts,
options, ABI/target namespaces, effects/guards/leases, completion and frontier
policies. Digest is SHA256(`SMIR-HELPERS-V1\0` + sorted compact ASCII JSON of the
ENTIRE catalog, no newline/exclusions). `services-v1.json` uses analogous
`SMIR-SERVICES-V1\0` and defines59 services plus exact structures/buffer constraints.
`errno-v1.json` contains primary-header-derived personality conversion maps.
`runtime_host_descriptor` hashes canonical bytes under `SMIR-HOST-V1\0`; only
independent host registration installs its callback.

The mirrored execution live-value/origin/progress and ABI cleanup-state records
must exactly match those owners' current schemas. Shape admission alone cannot
validate values, source construction, native descriptors or a whole executable.
Reference tools require independently admitted graph/registry facts. No raw live
image is externally resumable: runtime-issued private handoff ownership is required.

Legacy `*.schema.json`, catalog.json and source-manifest.json are retained local
runtime-draft-v1 JSON protocol evidence. Their earlier 64 B jmp cookie/atomic width/
selection limits do not define profile0.2. Candidate fixtures are isolated under
`conformance/runtime/candidate`; the legacy87 corpus remains independently checked.
