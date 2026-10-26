# Configured NVMe and AHCI images

Image flags attach the existing x86 PCI NVMe or AHCI controller to a bounded raw
image. An image path enables the optional PCI family by default. An explicit
`pci_devices=false` in TOML conflicts with images unless CLI `--pci-devices`
overrides it. Images on other guest architectures are rejected before execution.

```sh
rax --kernel bzImage --backend emulator --nvme-image disk.raw
rax --kernel bzImage --ahci-image disk.raw --ahci-image-mode read-only
rax --kernel bzImage --nvme-image disk.raw --nvme-image-mode read-write \
  --nvme-image-limit 8GiB
```

| Property | CLI | TOML | Default |
|---|---|---|---|
| NVMe source | `--nvme-image PATH` | `storage.nvme.path` | Absent |
| AHCI source | `--ahci-image PATH` | `storage.ahci.path` | Absent |
| NVMe mode | `--nvme-image-mode MODE` | `storage.nvme.mode` | COW |
| AHCI mode | `--ahci-image-mode MODE` | `storage.ahci.mode` | COW |
| NVMe limit | `--nvme-image-limit SIZE` | `storage.nvme.max_bytes` | 4 GiB |
| AHCI limit | `--ahci-image-limit SIZE` | `storage.ahci.max_bytes` | 4 GiB |

| Mode | CLI value | TOML value | Host effect |
|---|---|---|---|
| Read-only | `read-only` | `read_only` | Guest modifications fail |
| Persistent | `read-write` | `read_write` | Successful writes synchronize the opened file |
| COW | `copy-on-write` | `copy_on_write` | Writes remain in the loaded instance |

Each field resolves CLI, then TOML, then default. A CLI mode or limit can override
a file-supplied path. A mode/limit without any path is an error. Unknown storage
fields are rejected. Paths in TOML resolve relative to the configuration file's
directory; CLI paths resolve from the process directory.

```toml
[storage.nvme]
path = "images/system.raw"
mode = "copy_on_write"
max_bytes = "8GiB"

[storage.ahci]
path = "images/data.raw"
mode = "read_only"
max_bytes = "4GiB"
```

Source capture canonicalizes the path and checks a nonempty regular file with a
512-byte-aligned length within its configured limit. It hashes bytes incrementally
with pinned SHA-256 under a shared file lock. The resolved record contains source
length, digest, access mode and byte budget. Runtime attachment opens the selected
medium, then hashes the loaded bytes and compares both size and content before
exposing a controller. Same-size replacement is detected. Persistent attachment
also retains its exclusive file lock. Arbitrary host writers that ignore advisory
locks remain outside the file-consistency contract.

The runtime's actual PCI bridge constructs the requested image-backed controller
and shares the VM's guest-RAM DMA mapping. Distinct NVMe/AHCI paths stay distinct;
absent attachments retain the original empty-controller behavior. File aliases
that conflict with a persistent attachment fail before guest execution. Source
hashing takes O(n) input work and 64 KiB scratch; runtime image loading remains
O(n) resident storage. Total resident data includes RAM and all loaded images.

## Checkpoint boundary

Configuration schema 2 in the tagged version-8 container records attachment
metadata. The decoder separately supports the prior schema 1 and original
untagged version-8 layout; it never guesses appended fields. Old schema-1 files
default to no images, while preserving their PCI flag. Old untagged files retain
the original absent-PCI default. Image lengths/budgets/topology are validated
before compressed RAM allocation.

This change records source identity, not guest-modified media or controller
queues. Runtime checkpoint capture and restore for attached images are rejected
until that state is captured. Reopening a COW source after a checkpoint would
lose modifications. Configuration metadata persistence is tested independently;
it is not presented as full image-backed VM restoration. CLI image overrides
are resolved on the checkpoint path and cannot be silently ignored.

## Evidence and assumptions

Twenty public configuration tests cover default behavior, fieldwise precedence,
TOML path resolution, strict nested fields, PCI admission, malformed files/budgets,
mode binding, SHA-256 identity, same-size replacement, binary metadata, the actual
old schema-1 fixture and checkpoint rejection. Three tests in the actual `rax`
binary check CLI parsing; both core and scheduled CI select that complete
binary alongside the 23 backend/device owners (554 local macOS tests total). Three library runtime tests send commands through the
actual PCI bridge and guest-RAM DMA mapping, proving distinct source reads,
persistent writes and rejection of source replacement/conflicting attachment.
These runtime tests do not execute a guest CPU or prove Linux boot.

The independent checkpoint oracle parses ten published schema-2 files, six image
identity records and the captured schema-1 file. Python hashes the actual source
images; separate system zstd checks all 40,960 represented RAM bytes. The previous
unsupported-schema test now probes schema 3, with schema 2 explicitly exercised.
The original failed checkpoint-CLI-override test is retained in the evidence:
it exposed missing automatic PCI enablement, which the implementation corrects.

| ID | Assumption and dependent result | Stress/falsification probe | Status |
|---|---|---|---|
| C1 | Input precedence is fieldwise CLI > TOML > default. | Path/mode/budget overrides, absent paths and unknown keys. A silently ignored explicit field fails. | Tested locally. |
| C2 | SHA-256 and length identify the captured byte content. | Fixed independent digest, same-size replacement, changed size and independent parser/hash comparison. Digest equality is the identity test; no mathematical collision exclusion is claimed. | Tested locally. |
| C3 | Shared/exclusive locks coordinate cooperating image users. | Source replacement between capture and attachment; conflicting aliases through the actual runtime. Noncooperating host writers remain outside exclusion guarantees. | Bounded local evidence. |
| C4 | PCI images require an x86 PCI topology. | Disabled PCI, CLI enablement, checkpoint CLI image override and non-x86 rejection. The initial override failure is retained. | Corrected and tested. |
| C5 | Prior config schema 1 has a fixed field sequence. | Actual original-writer fixture, original kernel absent, preserved PCI=true and empty images. Config-only payload length is never used to infer schema. | Tested; full gates required. |
| C6 | Image paths alone cannot restore COW/device state. | Explicit capture/restore and checkpoint-config guards; future complete media/queue/state integration. Any successful incomplete image-backed restore falsifies this boundary. | Integration remains open. |
| C7 | PCI/DMA evidence is distinct from guest execution. | Full owning/library/CLI inventories, then separate boot/native-host gates. No PCI helper result is claimed as CPU or native-hypervisor evidence. | Scope explicit. |

High impact: complete device/media checkpoints, replay suppression, Linux storage
boot and native interrupt delivery remain integration requirements. Medium impact:
configured virtio transport on non-PCI platforms, arbitrary noncooperating host
writes and aggregate image/RAM admission remain separate. Low impact: COW is fully
resident, and TOML paths now have an explicit directory-relative rule.

Commit gates require complete native/translated owners and library inventories,
all binary parser tests, C API compatibility, build, Clippy, formatting, CI
selection and independent storage/checkpoint records against frozen sources.
Partial library filters are iteration/preflight evidence only.
