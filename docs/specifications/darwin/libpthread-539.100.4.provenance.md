[← Documentation home](../../../README.md)

# libpthread 539.100.4 sources provenance

- Canonical title: libpthread source tree, selected files
- Issuing organization: Apple Inc. (Apple Open Source)
- Revision: tag `libpthread-539.100.4`
- Source URL: https://github.com/apple-oss-distributions/libpthread (tag
  `libpthread-539.100.4`); the files were extracted from the tag's archive
  `https://github.com/apple-oss-distributions/libpthread/archive/refs/tags/libpthread-539.100.4.tar.gz`
  (archive SHA-256
  `c815492b81044b1cf8d53b124a9ac9503697439e96325daac982adad934d7cd4`)
- Retrieved: 27 September 2026
- Integrity: `libpthread-539.100.4.sha256` lists the SHA-256 of every
  imported file, relative to `libpthread-539.100.4/`.
- License: every imported file carries the Apple Public Source License 2.0
  header; the archive has no top-level license file, and the license text
  is the APSL 2.0 in `xnu-12377.121.6/APPLE_LICENSE`. The files are
  reference material for an independent implementation; no RAX source is
  derived from their text.

Paths under `libpthread-539.100.4/` mirror the libpthread tree. Do not
reformat or edit the files.

## Use in RAX

| Area | Files |
|---|---|
| The kernel side of `bsdthread_register` (registration data, features, the main thread's QoS, the stack hint), `bsdthread_create` (start state, TSD base, QoS, suspended start), and `bsdthread_terminate` | `kern/kern_support.c`, `kern/kern_internal.h` |
| psynch: the kernel wait queues of mutexes, condition variables, and read-write locks, the sequence words, preposts, and interrupted wakeups (`ECVCLEARED`, `ECVPREPOST`) | `kern/kern_synch.c`, `kern/synch_internal.h`, `kern/kern_internal.h` |
| The user side the kernel serves: thread start and exit, joins through the exit-gate ulock, cancellation after `EINTR`, the default mutex policy, and the psynch callers | `src/pthread.c`, `src/pthread_cancelable.c`, `src/pthread_mutex.c`, `src/pthread_cond.c`, `src/pthread_rwlock.c`, `src/types_internal.h` |
| Thread QoS encodings | `private/pthread/qos_private.h` |
