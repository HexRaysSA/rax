# Security policy

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** action when available:
https://github.com/HexRaysSA/rax/security/advisories/new

If private reporting is unavailable, contact Hex-Rays through its
[published security-report mailbox](https://hex-rays.com/bug-bounty),
**bugbounty@hex-rays.com**, with a subject beginning `RAX security report`.
Avoid public issues for an undisclosed vulnerability or confidential payload.

Include the RAX commit/version, host OS and architecture, guest ISA, enabled
features/backend, build command, minimal reproducer, expected and observed
behavior, and security impact. Identify whether JIT, MMIO/devices, checkpoint
loading, the C API or the debugger is involved. Attach only material you may
share; request a suitable private transfer channel for large or restricted data.

## Triage and disclosure

Maintainers reproduce reports, identify affected configurations, and coordinate
fixes and disclosure with the reporter. A report should distinguish guest
architectural faults from host memory corruption, information disclosure or
host resource exhaustion. Maintainers and the reporter agree on disclosure
timing for each report.

## Maintenance scope

Security fixes target the current development branch. Older tags have no
separate maintenance or backport commitment. Include the affected release even
if the reproducer also works on the current branch.

RAX is experimental emulator/VMM software. Running untrusted guests requires
host-level process isolation and resource limits appropriate to the deployment.
Keep debugger endpoints on trusted networks.
