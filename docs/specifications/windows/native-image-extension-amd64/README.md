# Independent AMD64 image-extension availability

`run-v1.py` records `NtQueryVirtualMemory` class 14 for independently owned
NTDLL image sections on native AMD64 Windows. It observes both `KnownDlls`
and `KnownDlls32`, and sections created from the matching installed files.
Ordinary mapping, explicit image-machine mapping, and explicit machine mapping
with the image-rebase flag are separate observations.

Each mapped view records valid types 0 and 1, invalid type 2, nonzero reserved
flags, and a 23 B short output. Complete 24 B before/after buffers, NTSTATUS,
and native `SIZE_T` ReturnLength are retained. The probe records up to eight
metadata-only tail regions, each bounded to 4 MiB, without dereferencing or
executing the mapped image. All maps and handles are released. Input hashes and
the process handle count must match before and after the campaign.

The existing Windows 2022 and Windows 2025 observation jobs run the producer;
it adds no CI jobs. `target/native-image-extension-amd64-v1.json` is created
exclusively so an observation cannot overwrite a completed or active run.
Unsupported map/query statuses are retained as observations, not converted to
successful absent-extension results. This campaign does not change runtime
behavior or establish full process-emulation completion.

Assumption A1 is retained: the observed build-26100 `STATUS_NOT_SUPPORTED`
may depend on selected image architecture or mapping mode. Compare exact
per-profile statuses and tail ownership on both native kernels to falsify it.
The availability decision remains unknown until those observations complete.

High-impact boundary: the existing guest class-14 absence semantics were
measured on native ARM64 kernels. Independent AMD64 availability and fault
precedence are separate evidence requirements; this observation does not
silently extend the ARM64 contract to every AMD64 kernel.
