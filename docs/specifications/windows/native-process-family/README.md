# Windows guest process creation

This implementation admits a native64 image on a configured guest drive. It
maps the executable and startup libraries into a separate guest address space.
The caller receives process and primary-thread handles from its own object
table. The root and child processes share one cooperative scheduler. Each
scheduler turn polls one process and executes at most its configured instruction
slice. The root result ends the emulator session. The scheduler retains a child
until it exits or the session ends. Process and thread handles retain exit
records after the child address space has been released.

The initial implementation covers same-architecture ARM64 and AMD64 children,
ordinary console startup without inherited object-table entries, normalized
process parameters, and the image-name, client-ID, image-information, and
ARM64 CHPE creation attributes. The embedded closed-filesystem policy rejects
filesystem-based child creation before reading the requested image. Cross-ISA
creation, explicit object attributes, nonempty handle inheritance, and
image-specific execution options remain unsupported. The startup path does not
invoke host process creation, wait, thread resume, or cross-process memory APIs.

On Windows 11 ARM64 build 29708, a native run of installed `cmd.exe` creating
another installed `cmd.exe` supplied an 88-byte `PS_CREATE_INFO` input with
state 0, creation flags `0x204`, thread flags 1, and a 136-byte attribute list.
Its successful output returned state 6 and parameter flags `0x6001`. The new
process handle subsequently received process information class 60 and class 0
queries, a private-memory allocation, two memory writes, a primary-thread
resume, and a wait.
The CDB control observed the normal installed executable under the current user.
The recorded values exclude host pointers, identifiers, and environment data.

The native service test exercises the full modeled guest lifecycle with an
owned executable fixture on both guest architectures. It checks suspended
creation, independent client IDs and address spaces, a counted command line,
raw UTF-16 environment bytes, access-checked allocation and writes in the
child address space, resume, signal, and exit status. Allocations require
`PROCESS_VM_OPERATION` on a handle to a direct guest child.

Installed `cmd.exe` on Windows build 29708 next opens the AppCertDlls registry
key. The native control returned `STATUS_OBJECT_NAME_NOT_FOUND` for absolute
and relative names in the default, 32-bit and 64-bit registry views. The
installed-library snapshot now records this absence after a read-only open
confirms it. A configured or unreadable host key stays outside the snapshot.
The same nested shell comparison next reaches the CSR request carried by
`NtAlpcSendWaitReceivePort`. On ARM64 build 29708 in session 1, the selected
guest CSR peer handles the child-start request for a suspended direct child.
It checks that the captured strings lie in its shared view and that the
process and primary-thread handles identify that child. For an executable
with a simple embedded application manifest, it copies the assembly identity
into the captured response. The native controls observed
`Microsoft.Windows.FileSystem.CMD` and `Microsoft.Windows.Filesystem.Where` in
the replies for the two installed images. The exchange uses guest-owned
memory and does not contact the host CSR server.

On ARM64 build 29708.1003 in session 0, installed `cmd.exe` launches
an installed child by absolute path or by executable basename. Native
and guest stdout, stderr, and exit status match for both forms and for
a child that exits with status 23.

The manifest parser accepts bounded UTF-8 and BOM-marked UTF-16 input with a
single Win32 assembly identity and no assembly dependencies. Full side-by-side
activation and other CSR child-start profiles remain outside this model.

The native ARM64 caller queries the case-sensitive
`Kernel-OneCore-DeviceFamilyID` name through `NtQueryLicenseValue` before
allocating child memory. The emulator answers this read from the selected
installed Windows policy snapshot. A four-byte destination receives the
captured DWORD. A shorter destination reports the required four bytes and
leaves the data buffer untouched. Other policy names are outside this service's
model.

In the installed-library comparison on that Windows build, `cmd.exe` ran
a second installed `cmd.exe` and both paths returned exit code 0, identical
standard output and empty standard error. The emulator selected the DLLs from
the installed system directory without a separate sysroot.

The private ABI definitions are in [the pinned PHNT process declarations](../native-console-owner/phnt-ntpsapi.h)
and [the pinned PHNT process-parameter declarations](../native-process-parameters/phnt-ntrtl.h).
Public behavior is documented in [Process Handles and Identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)
and [Suspending Thread Execution](https://learn.microsoft.com/en-us/windows/win32/procthread/suspending-thread-execution).
