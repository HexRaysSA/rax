[← Documentation home](../../../README.md)

# libdispatch 1542.100.32 sources provenance

- Canonical title: libdispatch source tree, selected files
- Issuing organization: Apple Inc. (Apple Open Source)
- Revision: tag `libdispatch-1542.100.32`
- Source URL: https://github.com/apple-oss-distributions/libdispatch (tag
  `libdispatch-1542.100.32`); the files were extracted from the tag's
  archive
  `https://github.com/apple-oss-distributions/libdispatch/archive/refs/tags/libdispatch-1542.100.32.tar.gz`
  (archive SHA-256
  `b251152f46d2cc16b87be85d32880144b44aadab62eb0712c31b27ca86556718`)
- Retrieved: 27 September 2026
- Integrity: `libdispatch-1542.100.32.sha256` lists the SHA-256 of every
  imported file, relative to `libdispatch-1542.100.32/`.
- License: `LICENSE` (the Apache License, version 2.0), the tree's license
  text; the imported sources carry Apple's Apache 2.0 header. The files
  are reference material for an independent implementation; no RAX source
  is derived from their text.

Paths under `libdispatch-1542.100.32/` mirror the libdispatch tree. Do not
reformat or edit the files.

## Use in RAX

| Area | Files |
|---|---|
| How libdispatch drives the kernel: workqueue setup and the feature checks that select workloops (`_dispatch_root_queues_init_once`, `DISPATCH_USE_KEVENT_WORKLOOP`, `DISPATCH_USE_MGR_THREAD`), which queues are workloops (`_dispatch_base_lane_is_wlh`), and the kevent, kevent-worker, and workloop-worker entry points | `src/queue.c`, `src/internal.h` |
| The kevents it sends: the manager's `EVFILT_USER` poke, `kevent_qos` on the workqueue kqueue and `kevent_id` on workloops, the workloop thread-request, synchronous-wait, wake, ownership, and sync IPC events, and the errors it accepts (`ENOENT`, `ESTALE`, `EINTR`) | `src/event/event_kevent.c` |
