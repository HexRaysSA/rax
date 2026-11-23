#define wmain observe_csr_startup
#include "../native-wow64-csr-amd64/startup-v1.cpp"
#undef wmain
#include <psapi.h>
#include <string_view>

struct Profile {
  USHORT native_machine;
  ULONG leaf;
  ULONG parent_return;
  ULONG thunk;
  bool output_in_esi;
};

constexpr Profile server_2022{IMAGE_FILE_MACHINE_AMD64, 0x155090, 0x12bde7,
                              0x18cc30, false};
constexpr Profile server_2025{IMAGE_FILE_MACHINE_AMD64, 0x16b660, 0x132c91,
                              0x1d28a0, true};
constexpr Profile client_arm64{IMAGE_FILE_MACHINE_ARM64, 0x176450, 0x16e1ed,
                               0x1e7fe0, true};
constexpr ULONG payload_bytes = 1660;
constexpr ULONG ret_offset = 12;

static bool is_x86_kernelbase(HANDLE process, uintptr_t base) {
  std::array<wchar_t, 1024> path{};
  const DWORD chars = K32GetMappedFileNameW(
      process, reinterpret_cast<void *>(base), path.data(), DWORD(path.size()));
  constexpr std::wstring_view suffix = L"\\SysWOW64\\KernelBase.dll";
  if (chars < suffix.size() || chars >= path.size() ||
      _wcsicmp(path.data() + chars - suffix.size(), suffix.data()) != 0)
    return false;
  IMAGE_DOS_HEADER dos{};
  read_exact(process, base, &dos, sizeof(dos));
  if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
      dos.e_lfanew > 4096)
    fail("kernelbase-dos");
  IMAGE_NT_HEADERS32 nt{};
  read_exact(process, base + static_cast<ULONG>(dos.e_lfanew), &nt, sizeof(nt));
  if (nt.Signature != IMAGE_NT_SIGNATURE ||
      nt.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
      nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    fail("kernelbase-pe32");
  return true;
}

static void print_payload(const char *phase, HANDLE process, ULONG address) {
  std::array<BYTE, payload_bytes> data{};
  read_exact(process, address, data.data(), data.size());
  std::printf("NLS_%s payload=", phase);
  for (const BYTE byte : data)
    std::printf("%02x", unsigned(byte));
  std::putchar('\n');
}

int wmain(int argc, wchar_t **argv) {
  if (argc != 3)
    return 2;
  const std::wstring_view build = argv[2];
  const Profile *profile = nullptr;
  if (build == L"20348")
    profile = &server_2022;
  else if (build == L"26100")
    profile = &server_2025;
  else if (build == L"26200")
    profile = &client_arm64;
  if (!profile)
    return 2;

  setvbuf(stdout, nullptr, _IONBF, 0);
  std::array<wchar_t, MAX_PATH> windows{};
  const UINT chars = GetWindowsDirectoryW(windows.data(), UINT(windows.size()));
  if (!chars || chars >= windows.size() ||
      _wcsicmp((std::wstring(windows.data()) + L"\\SysWOW64\\cmd.exe").c_str(),
               argv[1]) != 0)
    fail("stock-x86-cmd-path");
  HANDLE debug_object = nullptr;
  PROCESS_INFORMATION child =
      create_pure(argv[1], &debug_object, L" /d /c ver");
  if (!DebugSetProcessKillOnExit(FALSE))
    fail("disable-debugger-kill-on-exit");
  USHORT guest_machine = 0, native_machine = 0;
  DWORD child_session = 0, own_session = 0;
  if (!IsWow64Process2(child.hProcess, &guest_machine, &native_machine) ||
      guest_machine != IMAGE_FILE_MACHINE_I386 ||
      native_machine != profile->native_machine ||
      !ProcessIdToSessionId(child.dwProcessId, &child_session) ||
      !ProcessIdToSessionId(GetCurrentProcessId(), &own_session) ||
      child_session != own_session)
    fail("owned-x86-child-identity");
  std::printf("PROFILE guest=%04X machine=%04x session=%lu\n",
              unsigned(guest_machine), unsigned(native_machine), child_session);

  uintptr_t module = 0, entry = 0;
  ULONG data = 0, entry_sp = 0, exit_code = 0;
  bool pending = false, observed = false, exited = false;
  const ULONGLONG deadline = GetTickCount64() + 90000;
  while (!exited && GetTickCount64() < deadline) {
    DEBUG_EVENT event{};
    if (!WaitForDebugEvent(&event, 1000)) {
      if (GetLastError() == ERROR_SEM_TIMEOUT)
        continue;
      fail("debug-event");
    }

    DWORD disposition = DBG_CONTINUE;
    switch (event.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT:
      if (event.u.CreateProcessInfo.hFile)
        CloseHandle(event.u.CreateProcessInfo.hFile);
      break;
    case CREATE_THREAD_DEBUG_EVENT:
      if (event.u.CreateThread.hThread)
        CloseHandle(event.u.CreateThread.hThread);
      break;
    case LOAD_DLL_DEBUG_EVENT: {
      const uintptr_t base =
          reinterpret_cast<uintptr_t>(event.u.LoadDll.lpBaseOfDll);
      if (event.u.LoadDll.hFile)
        CloseHandle(event.u.LoadDll.hFile);
      if (entry || base > UINT32_MAX ||
          !is_x86_kernelbase(child.hProcess, base))
        break;
      module = base;
      entry = module + profile->leaf;
      if (entry > UINT32_MAX)
        fail("kernelbase-entry");
      std::array<BYTE, 15> leaf{};
      read_exact(child.hProcess, entry, leaf.data(), leaf.size());
      const ULONG thunk = static_cast<ULONG>(module) + profile->thunk;
      std::array<BYTE, 15> expected{0xb8, 0x0b, 0x30, 0,    0,    0xba, 0, 0,
                                    0,    0,    0xff, 0xd2, 0xc2, 8,    0};
      std::memcpy(expected.data() + 6, &thunk, sizeof(thunk));
      if (leaf != expected)
        fail("kernelbase-relocated-x86-leaf");
      std::array<BYTE, 5> call{};
      const uintptr_t caller = module + profile->parent_return;
      read_exact(child.hProcess, caller - call.size(), call.data(),
                 call.size());
      std::int32_t offset = 0;
      std::memcpy(&offset, call.data() + 1, sizeof(offset));
      if (call[0] != 0xe8 ||
          std::int64_t(caller) + offset != std::int64_t(entry))
        fail("kernelbase-caller-displacement");
      patch(child.hProcess, entry, 0xcc);
      std::printf("NLS_LEAF module=%08lX leaf=%08lX thunk=%08lX parent=%08lX\n",
                  ULONG(module), profile->leaf, profile->thunk,
                  profile->parent_return);
      break;
    }
    case EXCEPTION_DEBUG_EVENT: {
      const ULONG exception = event.u.Exception.ExceptionRecord.ExceptionCode;
      const uintptr_t hit = reinterpret_cast<uintptr_t>(
          event.u.Exception.ExceptionRecord.ExceptionAddress);
      const bool breakpoint =
          exception == EXCEPTION_BREAKPOINT || exception == 0x4000001f;
      if (!breakpoint) {
        disposition = DBG_EXCEPTION_NOT_HANDLED;
        break;
      }
      if (!entry || observed || hit != (pending ? entry + ret_offset : entry))
        break;
      if (event.dwThreadId != child.dwThreadId)
        fail("unexpected-child-thread");
      WOW64_CONTEXT context{};
      context.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER;
      if (!Wow64GetThreadContext(child.hThread, &context))
        fail("child-context");

      if (!pending) {
        std::array<ULONG, 3> stack{};
        read_exact(child.hProcess, context.Esp, stack.data(), sizeof(stack));
        data = stack[1];
        entry_sp = context.Esp;
        MEMORY_BASIC_INFORMATION destination{};
        if (!VirtualQueryEx(child.hProcess,
                            reinterpret_cast<void *>(uintptr_t(data)),
                            &destination, sizeof(destination)))
          fail("output-mapping");
        const auto region =
            reinterpret_cast<uintptr_t>(destination.BaseAddress);
        const auto allocation =
            reinterpret_cast<uintptr_t>(destination.AllocationBase);
        std::printf("NLS_ENTRY sp=%08lX caller=%08lX data=%08lX size=%lu "
                    "edi=%08lX esi=%08lX type=%08lX protect=%08lX "
                    "state=%08lX allocation_offset=%08lX region_offset=%08lX\n",
                    entry_sp, stack[0], data, stack[2], context.Edi,
                    context.Esi, destination.Type, destination.Protect,
                    destination.State, ULONG(data - allocation),
                    ULONG(data - region));
        if (stack[0] != module + profile->parent_return ||
            stack[2] != payload_bytes ||
            std::uint64_t(context.Edi) + 12 != data ||
            (profile->output_in_esi && context.Esi != data) ||
            destination.State != MEM_COMMIT || region > data ||
            std::uint64_t(data - region) + payload_bytes >
                destination.RegionSize)
          fail("leaf-request-geometry");
        print_payload("BEFORE", child.hProcess, data);
        patch(child.hProcess, entry, 0xb8);
        patch(child.hProcess, entry + ret_offset, 0xcc);
        context.Eip = ULONG(entry);
        pending = true;
      } else {
        std::printf("NLS_RETURN status=%08lX sp=%08lX\n", context.Eax,
                    context.Esp);
        print_payload("AFTER", child.hProcess, data);
        patch(child.hProcess, entry + ret_offset, 0xc2);
        context.Eip = ULONG(entry + ret_offset);
        if (context.Eax != 0 || context.Esp != entry_sp)
          fail("leaf-return-geometry");
        pending = false;
        observed = true;
      }
      if (!Wow64SetThreadContext(child.hThread, &context))
        fail("restore-child-context");
      break;
    }
    case EXIT_PROCESS_DEBUG_EVENT:
      exit_code = event.u.ExitProcess.dwExitCode;
      exited = true;
      break;
    }
    if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition))
      fail("continue-child");
  }

  CloseHandle(child.hThread);
  CloseHandle(child.hProcess);
  CloseHandle(debug_object);
  std::printf("NLS_DONE observed=%u pending=%u exited=%u exit=%lu\n",
              unsigned(observed), unsigned(pending), unsigned(exited),
              exit_code);
  return observed && !pending && exited && exit_code == 0 ? 0 : 22;
}
