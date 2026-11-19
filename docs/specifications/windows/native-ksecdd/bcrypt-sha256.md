# Installed bcrypt SHA-256 provider configuration

On Windows 10.0.29708.1003 ARM64, the installed ARM64 `certutil -hashfile`
path sends two synchronous buffered `NtDeviceIoControlFile` requests on a
`\\Device\\KsecDD` file. Both calls use control code `0x390400` and null
completion event, APC routine, and APC context arguments.

| Request | Input | Output capacity | Reported bytes |
| --- | ---: | ---: | ---: |
| Provider event registration | 104 bytes | 8 bytes | 0 bytes |
| SHA-256 provider resolution | 64 bytes | 384 bytes | 224 bytes |

Both native returns were `STATUS_SUCCESS`. The registration's last eight
bytes carry the handle returned by `NtCreateEvent` for an initially
unsignaled auto-reset event with access `0x1f0003`. The SHA-256 reply uses
relative offsets. It resolves one hash provider, Microsoft Primitive
Provider, and its user-mode image, `bcryptprimitives.dll`. The
[native observation](bcrypt-sha256-arm64.json) binds two ordinary-user runs
of installed certutil to the installed binaries and local fixture. The runs
agreed on both message layouts after removing their process-specific event
handles and excluding the unassigned four-byte span at offset `0x34` from
comparison.

The emulated service selects this ARM64 profile and these two message
shapes. It processes the buffers and retains the notification event in the
guest's file object. Duplicate handles share that object. The static guest
provider configuration has no changes to notify, and the last release of
the file object releases its event reference. The guest response encodes the
observed relative fields and initializes all padding to zero.

The observation establishes the stock caller's call and return shapes.
Replacement registrations, provider changes, other algorithms or guest
architectures, and kernel-level timing, aliasing and fault ordering require
separate observations.

- [NtDeviceIoControlFile](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile)
- [BCryptResolveProviders](https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptresolveproviders)
- [CRYPT_PROVIDER_REF](https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-crypt_provider_ref)
