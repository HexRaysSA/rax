// Own-process/own-child mode inheritance, without changing the invoking process.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Set = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG);
static Query query;
static Set set;

static ULONG raw() {
  ULONG mode = 0xa5a5a5a5, returned = 0xa5a5a5a5;
  LONG status = query(GetCurrentProcess(), 12, &mode, 4, &returned);
  if (status || returned != 4) ExitProcess(10);
  return mode;
}

static DWORD WINAPI thread(void *) {
  printf("kind=thread raw=%08lX public=%08X thread-mode=%08lX\n",
         raw(), GetErrorMode(), GetThreadErrorMode());
  return 0;
}

int main(int argc, char **) {
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  query = reinterpret_cast<Query>(GetProcAddress(nt, "NtQueryInformationProcess"));
  set = reinterpret_cast<Set>(GetProcAddress(nt, "NtSetInformationProcess"));
  if (!query || !set) return 2;
  if (argc > 1) {
    printf("kind=child raw=%08lX public=%08X thread-mode=%08lX\n",
           raw(), GetErrorMode(), GetThreadErrorMode());
    return 0;
  }
  ULONG original = raw();
  unsigned child_count = 0, closed = 0;
  wchar_t image[32768];
  if (!GetModuleFileNameW(nullptr, image, 32768)) return 3;
  const ULONG values[] = {0, 1, 4, 0x8007, 0xffffffff};
  for (ULONG value : values) {
    LONG changed = set(GetCurrentProcess(), 12, &value, 4);
    printf("kind=parent raw=%08lX requested=%08lX status=%08lX public=%08X\n",
           raw(), value, changed, GetErrorMode());
    HANDLE worker = CreateThread(nullptr, 0, thread, nullptr, 0, nullptr);
    if (!worker) return 4;
    if (WaitForSingleObject(worker, INFINITE) != WAIT_OBJECT_0) return 5;
    if (CloseHandle(worker)) ++closed;
    for (unsigned defaults = 0; defaults < 2; ++defaults) {
      SECURITY_ATTRIBUTES attributes = {sizeof(attributes), nullptr, TRUE};
      HANDLE reader, writer;
      if (!CreatePipe(&reader, &writer, &attributes, 0)) return 6;
      if (!SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0)) return 7;
      wchar_t command[32768];
      if (swprintf_s(command, 32768, L"\"%ls\" --child", image) < 0) return 8;
      STARTUPINFOW startup = {};
      startup.cb = sizeof(startup);
      startup.dwFlags = STARTF_USESTDHANDLES;
      startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
      startup.hStdOutput = startup.hStdError = writer;
      PROCESS_INFORMATION process = {};
      DWORD flags = CREATE_NO_WINDOW | (defaults ? CREATE_DEFAULT_ERROR_MODE : 0);
      if (!CreateProcessW(image, command, nullptr, nullptr, TRUE, flags, nullptr,
                          nullptr, &startup, &process)) return 9;
      if (CloseHandle(writer)) ++closed;
      printf("kind=inherit parent=%08lX default=%u child-pid=%lu flags=%08lX ",
             value, defaults, process.dwProcessId, flags);
      char buffer[1024]; DWORD bytes;
      while (ReadFile(reader, buffer, sizeof(buffer), &bytes, nullptr) && bytes)
        fwrite(buffer, 1, bytes, stdout);
      if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0)
        return 11;
      DWORD code = 0xa5a5a5a5;
      if (!GetExitCodeProcess(process.hProcess, &code)) return 12;
      printf("kind=child-terminal pid=%lu exit=%lu\n", process.dwProcessId, code);
      if (code != 0) return 13;
      if (CloseHandle(reader)) ++closed;
      if (CloseHandle(process.hThread)) ++closed;
      if (CloseHandle(process.hProcess)) ++closed;
      ++child_count;
    }
  }
  LONG restored = set(GetCurrentProcess(), 12, &original, 4);
  printf("summary children=%u closed=%u initial=%08lX final=%08lX restore=%08lX\n",
         child_count, closed, original, raw(), restored);
  return child_count == 10 && closed == 45 && raw() == original ? 0 : 14;
}
