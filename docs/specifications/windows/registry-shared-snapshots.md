# Shared physical registry snapshots

The installed Windows runtime selects fixed startup subjects before execution.
`Local Settings`, machine `OLE`, and the `System` Command Processor subtree
use one physical subject for the native and WoW32 logical views. Machine and
user Software Command Processor subjects retain their independent capture path.

Microsoft documents shared registry keys and inheritance of the parent key's
redirection behavior in [Registry Keys Affected by WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys).
The table identifies user Classes and machine OLE as shared on Windows 7 and
later; no redirected exception is listed below Local Settings or OLE. The
System subtree inherits the machine root's shared behavior. The Local Settings
creator-hive alias is validated against the captured SID and primary hive.

The original implementation traversed a shared subject independently for each
view, then rejected any difference in values, grants, descendants, or child
FILETIMEs. A live Local Settings mutation between those traversals could abort
process startup before an installed DLL entry was executed.

The corrected acquisition opens both view roots and validates their canonical
physical identity and access profile. It closes the second root before
traversing descendants, captures the physical subtree once, and constructs both
immutable view projections from that record. Each projection retains its own
view tags and is charged to the existing aggregate budgets. Redirected subjects
continue to be captured independently.

Only native not-found errors become absent records. Both absent views must
retain the same not-found class. Permission, resource, and other native errors
remain errors. A root identity or grant disagreement is rejected before the
subtree is exposed; an identity or grant change during traversal is also
rejected. Existing injected-tree equality checks remain in force.

Acquisition retains per-node bounded stability checks and closes each parent
handle before opening descendants. It does not promise an atomic transaction
across the entire live registry subtree. No host handle, arbitrary guest path,
or live host callback is retained in the guest registry.

For N captured nodes and B captured metadata/value bytes, cloning and building
the two projections take O(N + B) time and space, with two logical views. The
native traversal occurs once for each declared shared subject.
