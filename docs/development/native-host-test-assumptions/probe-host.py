#!/usr/bin/env python3
"""Observe host-owned socket capacity and netlink framing without global changes."""
import json
import platform
import socket
import struct


def socket_capacity(requested=None):
    sender, receiver = socket.socketpair()
    try:
        if requested is not None:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, requested)
        sender.setblocking(False)
        queued = 0
        limit = 128 * 1024 * 1024
        while queued < limit:
            try:
                queued += sender.send(bytes(65536))
            except BlockingIOError:
                break
        return {
            "requested_send_bytes": requested,
            "actual_send_bytes": sender.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
            "actual_receive_bytes": receiver.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
            "queued_bytes": queued,
            "capacity_reached": queued < limit,
        }
    finally:
        sender.close()
        receiver.close()


def netlink():
    if not hasattr(socket, "AF_NETLINK"):
        return {"available": False}
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    try:
        membership = {}
        for group in [0, 1, 33, 36, 37, 39, 40, 0xFFFFFFFF]:
            try:
                sock.setsockopt(270, 1, struct.pack("I", group))
                membership[group] = 0
            except OSError as error:
                membership[group] = error.errno
        # Match the RAX fixture's one-byte legacy RTM_GETADDR payload.
        sock.settimeout(5)
        sock.bind((0, 0))
        sock.sendto(struct.pack("=IHHII", 17, 22, 0x301, 1, 0) + bytes([10, 0, 0, 0]), (0, 0))
        datagrams = []
        while True:
            raw = sock.recv(32768)
            offset = 0
            messages = []
            while len(raw) - offset >= 16:
                length, kind, flags, seq, pid = struct.unpack_from("=IHHII", raw, offset)
                if length < 16 or offset + length > len(raw):
                    raise RuntimeError("malformed native netlink datagram")
                messages.append({"length": length, "kind": kind, "flags": flags, "seq": seq})
                offset += (length + 3) & ~3
            datagrams.append(messages)
            if any(message["kind"] == 2 for message in messages):
                raise RuntimeError("native netlink returned NLMSG_ERROR")
            if any(message["kind"] == 3 for message in messages):
                break
        return {"available": True, "membership_errno": membership, "ipv6_datagrams": datagrams}
    finally:
        sock.close()


def main():
    print(json.dumps({
        "host": platform.uname()._asdict(),
        "default_socket": socket_capacity(),
        "bounded_socket": socket_capacity(4096),
        "netlink": netlink(),
        "scope": "Owned sockets only; no sysctl, interface, route or process changes.",
    }, indent=2))


if __name__ == "__main__":
    main()
