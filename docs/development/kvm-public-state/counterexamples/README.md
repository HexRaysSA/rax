# Frozen native PAE counterexample

`pae-overlay.rs` creates the actual public RAX KVM adapter, seeds a native PAE
cache through SREGS2 and changes only public CR8. The physical table is zero,
while the cached first pointer is 0x3001. The native observations are in
`red-v5.json` and `green-v6.json`; both use the identical probe source hash.
The prior adapter replaces the cache with zeros and the probe exits 101.
The SREGS2 adapter retains 0x3001 and exits 0.

The four files under `prior-non-test-kvm/` are frozen prior implementation
inputs, not current production modules. Their bytes match the source hashes
recorded before the original native run. See `manifest.json` for that proof,
the tracked source revision, compiler and feature profile.

To reproduce the red case, export the tracked revision named in the manifest
into a separate temporary directory, then overlay those four files at
`src/backend/kvm/`. Build the **non-test library** with the recorded features
and locked dependencies. The archived mod.rs has cfg(test) declarations whose
files are not needed by this non-test build. Compile `pae-overlay.rs` against
that library and its libc/kvm_bindings dependencies using the rustc arguments
recorded in red-v5.json, substituting the new temporary paths. Running it needs
Linux x86-64 and usable /dev/kvm. For green, use the current implementation
without the four prior files. The native CI job also runs the committed
public-state regressions directly.

The original standalone probe and prior modules retain their executed bytes,
including formatting. These fixtures qualify this PAE regression; they do not
qualify MP preservation, complete private/shared/in-flight checkpoint records,
SMP startup or any native Intel macOS path.
