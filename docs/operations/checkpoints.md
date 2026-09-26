[← Documentation home](../../README.md)

# Checkpoints and restore

`rax` exposes two restore concepts:

- **whole-machine checkpoint** through `--checkpoint`, using a self-contained `.rxc` image;
- **legacy restore** through `--resume`, restoring state into a machine rebuilt from current launch inputs.

They have different contracts and should not share documentation examples without explaining the distinction.

These restore paths belong to the machine application. `rax-user` does not
expose `.rxc` checkpoints or these CLI triggers; guest ptrace register/memory
access is not a serialized Linux-process checkpoint format.

## Whole-machine `.rxc` checkpoint

The documented whole-machine format contains enough state to reconstruct a live machine without a separate kernel or TOML file:

- embedded validated configuration;
- architecture/vCPU state;
- zstd-compressed guest RAM;
- serialized state for every instantiated device participating in the format;
- timing anchor/runtime state required by the VM;
- format/version metadata needed by the loader.

Restore:

```sh
./target/release/rax --checkpoint checkpoint.rxc
```

No `--kernel` or `--config` is required for the ordinary self-contained path.

## Legacy `--resume`

```sh
./target/release/rax \
    --kernel linux/vmlinux \
    --initrd initrd.cpio.gz \
    --resume old-state-file
```

This mode reconstructs the machine from the supplied current configuration and then loads legacy state. It is more sensitive to image, address-map, device, and version mismatches. Prefer `.rxc` whole-machine checkpoints for new workflows.

## Snapshot triggers

### Interactive console

On a TTY:

```text
Ctrl-A s
```

writes through the configured manual snapshot output path.

### Signal

Sending `SIGUSR1` requests a checkpoint on supported Unix paths. Signal handling should request the operation safely rather than serializing arbitrary complex state directly in the signal handler.

### Periodic instruction count

```sh
--snapshot-interval 10000000
```

requests a checkpoint every N software-retired instructions. `0` disables interval snapshots.

### Exact instruction counts

```sh
--snapshot-at 1000000,5000000,10000000
```

requests snapshots at the listed software instruction counts.

These triggers are tied to the software execution count. They are not a portable hardware-retirement counter for KVM/HVF.

## Output controls

### Manual output

```sh
--snapshot-out checkpoint.rxc
```

sets the path used by manual triggers such as `Ctrl-A s` and `SIGUSR1`. The documented default is `checkpoint.rxc`.

### Automatic output directory

```sh
--snapshot-dir snapshots
```

sets the directory for interval/exact-count snapshots. Automatic names should carry enough count/context to avoid overwriting distinct captures.

Create the directory and ensure the process has sufficient disk space and permissions. RAM compression reduces size but a sequence of snapshots can still be large.

## Configuration precedence on restore

For ordinary launch:

```text
CLI > TOML > detection > built-in defaults
```

For whole-machine checkpoint restore:

```text
checkpoint embedded configuration > permitted explicit CLI overrides
```

An override must not silently create an incompatible machine. Output/logging controls are safer overrides than architecture, memory map, device set, or image identity.

## Atomicity and safe points

A correct checkpoint must represent a coherent point between architecturally visible operations. The runtime must not serialize:

- half-committed instruction state;
- a Hexagon packet before packet-end commit;
- native-region state before registers/flags are synchronized;
- a device transaction whose queue and interrupt state disagree;
- RAM while a concurrent writer mutates it without coordination.

The VM control path should bring the vCPU and devices to a safe point, synchronize native state, then serialize.

## Device state obligations

Every wired device that can affect the guest after restore needs a serialization contract. Examples include:

- register state;
- interrupt line level and pending state;
- DMA position;
- command queues and descriptors;
- storage-controller link/command state;
- UART FIFOs;
- timer deadlines relative to the timing anchor;
- PCI configuration/BAR state;
- firmware/CMOS mutable state.

If an active device cannot be restored, the checkpoint should fail clearly or declare the configuration unsupported. Silently resetting one device turns a whole-machine checkpoint into a partial state dump.

## Native/JIT state

Compiled host code should normally be treated as a cache, not durable checkpoint state. Restore can reconstruct architectural state and invalidate/rebuild native-region caches. Persisting raw host pointers or executable mappings across process/host changes would be unsafe.

Before save, any native execution must synchronize guest registers, flags, and pending exits back into the canonical vCPU state.

## Timing

A timing anchor allows relative timer/deadline reconstruction. Exact wall-clock continuation across hosts is not generally possible or desirable. Documentation should distinguish:

- guest RTC/calendar state;
- virtual monotonic time;
- instruction count;
- host wall time;
- timer deadlines and pending interrupts.

## Compatibility

Checkpoint compatibility can be broken by:

- format changes;
- architecture-state schema changes;
- device state changes;
- address-map changes;
- different endianness or word-size assumptions;
- removal/renaming of enum variants;
- incompatible compression/version dependencies.

The loader should version the format and reject unsupported inputs with a precise error. Unless the project publishes a compatibility promise, assume checkpoints are most reliable with the same `rax` commit and host architecture.

## Validation workflow

For each supported machine:

1. Boot a deterministic workload.
2. Mutate CPU, RAM, and device state.
3. Save at a known marker.
4. Continue and record a deterministic suffix.
5. Restore in a new process.
6. Confirm the same suffix and final state.
7. Repeat while optional devices are active.
8. Corrupt/truncate the file and verify clean rejection.
9. Test version mismatch behavior.
10. Confirm terminal/log output controls do not alter embedded machine identity.

## Failure diagnosis

### File rejected

Record the exact error, checkpoint header/version, `rax` commit that created it, current commit, host architecture, and whether the file was truncated or transferred through a tool that changed it.

### Guest resumes but diverges

Suspect unsaved device/timer/native state. Compare a trace immediately before save and after restore with JIT disabled. Check pending interrupts, UART queues, DMA, and timer anchors.

### Restore asks for a kernel

Confirm that `--checkpoint`, not legacy `--resume`, was used and that the file is a whole-machine `.rxc` image.

### Automatic snapshots absent

Confirm the software backend is retiring instructions, the interval/list was parsed, the output directory exists, and the process can write there.

## Artifact handling

A checkpoint can contain guest secrets, kernel memory, credentials, decrypted data, and device buffers. Do not publish it casually. Compressing or naming it `.rxc` does not sanitize it.
