# Selected SRP device absence

On Windows 10.0.26200 ARM64, installed `cmd.exe /d /c ver` requests
`\Device\SrpDevice` through `NtOpenFile`. The request specifies
`FILE_READ_DATA`, all three sharing dispositions, no open options, and
`OBJ_CASE_INSENSITIVE`. The matching native control returned
`STATUS_OBJECT_NAME_NOT_FOUND` (`0xC0000034`), issued no handle and left
both fields of the I/O status block untouched. Three read-only controls also
observed absence. [Guest request and native controls](arm64-26200-open.json)
[Windows observer](https://github.com/HexRaysSA/rax/actions/runs/44738107844)

Runtime selection checks the fixed request twice on the qualified native
kernel. Both calls must produce the observed status with no handle and an
unchanged I/O status block. An acquired native handle is closed immediately.
The common emulator serves the captured result for the matching ARM64 open.
The guest never supplies host arguments or receives a native handle. The
capture performs no device reads, writes or control operations.
[Native file-open contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenfile)

| Assumption | Dependent result | Stress test and falsification | Status |
| --- | --- | --- | --- |
| The exact device open reports stable absence when selecting this runtime | One fixed guest request can return the native failure status | Repeat the fixed host query with untouched output sentinels. A returned handle, different status, or modified output disables the capture. Replay checks host machine, kernel build, guest architecture, request flags and access. | Confirmed for the recorded native runner and checked on selection |
| The selected snapshot describes the launch context | The read result is fixed for the lifetime of that guest | A new launch takes a new measurement. Live changes after selection are outside the snapshot contract. | Retained |

A present SRP device or a request outside the measured profile remains an
explicit unsupported operation. This command's observed progression qualifies
one open boundary and leaves software restriction policy decisions and device
controls outside this profile.
