# VIRTIO primary reference

- Title: Virtual I/O Device (VIRTIO) Version 1.2
- Issuer: OASIS Open, Virtual I/O Device (VIRTIO) Technical Committee
- Revision: Committee Specification 01
- Publication date: 2022-07-01
- Source: https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.pdf
- Canonical revision: https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.pdf
- Retrieval date: 2026-10-24
- SHA-256: `42c7d2b9da95b4763e5416e18eab08d9a5d715dd98390cb5fb727205c15f5e45`
- Size: 1,213,207 bytes
- Scope: Split virtqueues, indirect descriptors, MMIO negotiation and reset, block request framing, discard and write-zeroes contracts.
- Notices: The PDF is retained without modification, including its original OASIS copyright, licensing and patent notices.
- Repository purpose: Primary reference retained for reproducible field and ordering verification under AGENTS.md section 10.4.

## QEMU explanatory implementation

- Title: QEMU virtio core implementation (`hw/virtio/virtio.c`)
- Issuer: QEMU Project
- Revision: Git tag `v11.1.0`
- Publication date: unknown; the fixed tag identifies the retrieved revision.
- Source: https://raw.githubusercontent.com/qemu/qemu/v11.1.0/hw/virtio/virtio.c
- Retrieval date: 2026-10-24
- Local copy: `qemu-v11.1.0-virtio.c`
- SHA-256: `7bd4565e13e674c7970049e9cf88ac53f776c537048e642011cd2d46a28c9126`
- Size: 142,190 bytes
- Notices: Unmodified file, including its IBM copyright and GNU GPL version 2 notice.
- Scope: Explains the implementation's initial-descriptor indirect selection. This source revision is separate from the executed Homebrew QEMU binary; it is not proof of that binary's source identity.
