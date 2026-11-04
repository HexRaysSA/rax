/* Repeated valid-buffer reads of private regular files, never fault injection.
 */
#define entry scalar_control_entry
#include "scalars-v1.c"
#undef entry
static void complete_read(Resource *r, HANDLE event, IoStatus *io, void *buffer,
                          unsigned length, LARGE_INTEGER *offset,
                          LONG *initial) {
  *initial =
      read_file(r->h, event, NULL, NULL, io, buffer, length, offset, NULL);
  if (*initial == 0x103 && WaitForSingleObject(event, 5000) != WAIT_OBJECT_0) {
    CancelIoEx(r->h, NULL);
    WaitForSingleObject(event, 5000);
    ExitProcess(50);
  }
}
void entry(void) {
  control_sink = GetStdHandle(STD_OUTPUT_HANDLE);
  HMODULE m = GetModuleHandleW(L"ntdll.dll");
  read_file = (ReadFn)(uintptr_t)GetProcAddress(m, "NtReadFile");
  query_file =
      (InformationFn)(uintptr_t)GetProcAddress(m, "NtQueryInformationFile");
  if (!read_file || !query_file)
    ExitProcess(51);
  control_print("{\"schema\":\"rax-native-file-read-transitions-v1\",\"pointer_"
                "bytes\":%zu,\"read_leaf\":",
                sizeof(void *));
  hex((const void *)(uintptr_t)read_file, 64);
  control_text("}\n");
  for (unsigned role = 0; role < 5; ++role) {
    Resource r = acquire(role);
    release(&r);
  }
  DWORD before, after;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    ExitProcess(52);
  unsigned rows = 0;
  const unsigned sizes[] = {0, 1, 0, 4, 4, 16, 1, 0};
  const int64_t positions[] = {-2, 0, 2, 8, 9, 7, -2, 9};
  for (unsigned role = 0; role < 5; ++role)
    for (unsigned sequence = 0; sequence < 3; ++sequence) {
      Resource r = acquire(role);
      HANDLE event = CreateEventW(NULL, TRUE, TRUE, NULL);
      if (!event)
        ExitProcess(53);
      if (sequence && role != 2) {
        unsigned char warm[1];
        DWORD n;
        LARGE_INTEGER at;
        at.QuadPart = 0;
        if (sequence == 2 && role != 3) {
          if (!ReadFile(r.h, warm, 1, &n, NULL) || n != 1)
            ExitProcess(54);
        } else {
          IoStatus io;
          LONG status;
          memset(&io, 0xa5, sizeof io);
          complete_read(&r, event, &io, warm, 1, &at, &status);
          if ((status != 0 && status != 0x103) || io.result.status != 0 ||
              io.information != 1)
            ExitProcess(55);
        }
        set_position(r.h, 2);
      }
      for (unsigned step = 0; step < 8; ++step) {
        __declspec(align(16)) unsigned char buffer[32];
        IoStatus io;
        LARGE_INTEGER offset;
        offset.QuadPart = positions[step];
        LONG initial;
        memset(buffer, 0xa5, sizeof buffer);
        memset(&io, 0xa5, sizeof io);
        SetEvent(event);
        SetLastError(0x6a1b2c3d);
        complete_read(&r, event, &io, buffer, sizes[step],
                      (step == 0 || step == 6) ? NULL : &offset, &initial);
        DWORD error = GetLastError();
        control_print("{\"role\":\"%s\",\"sequence\":%u,\"step\":%u,\"length\":"
                      "%u,\"initial_status\":%lu,\"last_error\":%lu,\"io\":",
                      roles[role], sequence, step, sizes[step],
                      (unsigned long)(ULONG)initial, (unsigned long)error);
        hex(&io, sizeof io);
        control_text(",\"buffer\":");
        hex(buffer, sizeof buffer);
        control_text(",\"position\":");
        position(r.h);
        control_text("}\n");
        ++rows;
      }
      if (!CloseHandle(event))
        ExitProcess(56);
      release(&r);
    }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    ExitProcess(57);
  control_print("{\"handles_before\":%lu,\"handles_after\":%lu,\"rows\":%u}\n",
                (unsigned long)before, (unsigned long)after, rows);
  control_flush();
  ExitProcess(0);
}
