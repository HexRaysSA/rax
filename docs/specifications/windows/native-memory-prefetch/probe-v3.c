#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  PVOID address;
  SIZE_T bytes;
} RANGE;
typedef NTSTATUS(NTAPI *SetFn)(HANDLE, ULONG, SIZE_T, RANGE *, PVOID, ULONG);

static DWORD protection(void *p) {
  MEMORY_BASIC_INFORMATION info;
  return VirtualQuery(p, &info, sizeof(info)) ? info.Protect : 0;
}

static unsigned resident(unsigned char *target, ULONG_PTR values[4]) {
  PSAPI_WORKING_SET_EX_INFORMATION entries[4] = {0};
  unsigned mask = 0;
  for (unsigned i = 0; i < 4; ++i)
    entries[i].VirtualAddress = target + i * 4096;
  if (!QueryWorkingSetEx(GetCurrentProcess(), entries, sizeof(entries)))
    exit(93);
  for (unsigned i = 0; i < 4; ++i) {
    values[i] = entries[i].VirtualAttributes.Flags;
    if (entries[i].VirtualAttributes.Valid)
      mask |= 1u << i;
  }
  return mask;
}

/* A snapshot never probes an unreadable/guarded page and cannot consume a
 * guard. */
static void snapshot(unsigned char *p, unsigned char out[32], unsigned *mask) {
  *mask = 0;
  memset(out, 0, 32);
  for (unsigned i = 0; i < 32; ++i) {
    DWORD protect = protection(p + i);
    if (protect && !(protect & (PAGE_GUARD | PAGE_NOACCESS))) {
      out[i] = p[i];
      *mask |= 1u << i;
    }
  }
}

static void hex(const unsigned char *bytes) {
  putchar('"');
  for (unsigned i = 0; i < 32; ++i)
    printf("%02x", bytes[i]);
  putchar('"');
}

int main(int argc, char **argv) {
  unsigned id = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 0) : 0;
  if (id >= 206)
    return 89;
  SetFn set = (SetFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                    "NtSetInformationVirtualMemory");
  unsigned char *controls =
      VirtualAlloc(NULL, 32768, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  unsigned char *target =
      VirtualAlloc(NULL, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!set || !controls || !target)
    return 90;
  /* Only controls are written: the four target pages begin untouched. */
  memset(controls, 0xcc, 32768);
  RANGE *ranges = (RANGE *)(controls + 128);
  ULONG *information = (ULONG *)(controls + 8192 + 128);
  RANGE pair[2] = {{target, 4096}, {target + 4096, 4096}};
  HANDLE process = GetCurrentProcess(), owned = NULL;
  ULONG class_id = 0, length = 4, flags = 0;
  SIZE_T count = 1;
  DWORD old;
  memcpy(ranges, pair, sizeof(pair));
  *information = 0;

  if (id == 1)
    flags = 1;
  if (id >= 2 && id < 34)
    flags = (ULONG)1 << (id - 2);
  if (id == 34)
    flags = 0xffffffff;
  if (id == 35)
    flags = 3;
  if (id >= 36 && id <= 41) {
    const ULONG lengths[] = {0, 1, 3, 5, 8, 0xffffffff};
    length = lengths[id - 36];
  }
  if (id == 44 || id == 45)
    information = (ULONG *)((unsigned char *)information + id - 43);
  if (id == 49)
    flags = 1;
  if (id == 50 || id == 51)
    information = (ULONG *)(controls + 16384 - (id == 50 ? 3 : 4));
  if (id == 54 || id == 55)
    ranges = (RANGE *)((unsigned char *)ranges + (id == 54 ? 1 : 4));
  if (id == 60 || id == 61)
    ranges = (RANGE *)(controls + 4096 -
                       (id == 60 ? sizeof(RANGE) - 1 : sizeof(RANGE)));
  if (id == 62)
    count = 0;
  if (id >= 63 && id <= 65) {
    count = 2;
    if (id == 64)
      pair[1].address = (PVOID)1;
    if (id == 65)
      pair[0].address = (PVOID)1;
  }
  if ((id >= 70 && id <= 78) || (id >= 193 && id <= 201)) {
    unsigned rights_index = id >= 193 ? id - 193 : id - 70;
    if (id >= 193)
      flags = 1;
    const DWORD rights[] = {0,
                            PROCESS_VM_OPERATION,
                            PROCESS_VM_READ,
                            PROCESS_VM_OPERATION | PROCESS_VM_READ,
                            PROCESS_QUERY_INFORMATION,
                            PROCESS_QUERY_LIMITED_INFORMATION,
                            PROCESS_QUERY_INFORMATION |
                                PROCESS_QUERY_LIMITED_INFORMATION,
                            SYNCHRONIZE,
                            PROCESS_ALL_ACCESS};
    if (rights_index == 0) {
      if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                           GetCurrentProcess(), &owned, 0, FALSE, 0))
        return 91;
    } else {
      owned = OpenProcess(rights[rights_index], FALSE, GetCurrentProcessId());
    }
    if (!owned)
      return 91;
    process = owned;
  }
  if (id == 192)
    flags = 1;
  if (id >= 202 && id <= 204) {
    count = 2;
    flags = 1;
    if (id == 202)
      pair[1].address = (PVOID)1;
    if (id == 203)
      pair[0].address = (PVOID)1;
  }
  if (id == 205) {
    flags = 1;
    pair[0].bytes = 16384;
  }
  unsigned target_case = id >= 100 && id < 120 ? id - 21 : id;
  if (id >= 100 && id < 120)
    flags = 1;
  switch (target_case) {
  case 79:
    pair[0].address = NULL;
    break;
  case 80:
    pair[0].address = (PVOID)1;
    break;
  case 81:
    pair[0].address = target + 1;
    break;
  case 82:
    pair[0].address = target + 4095;
    break;
  case 83:
    pair[0].bytes = 0;
    break;
  case 84:
    pair[0].bytes = 1;
    break;
  case 85:
    pair[0].bytes = 4095;
    break;
  case 86:
    pair[0].bytes = 4097;
    break;
  case 87:
    pair[0].bytes = ~(SIZE_T)0;
    break;
  case 88:
    pair[0].address = (PVOID) ~(ULONG_PTR)0;
    break;
  case 89:
    pair[0].address = (PVOID)(~(ULONG_PTR)0 - 2047);
    pair[0].bytes = 8192;
    break;
  case 90:
    pair[0].address = (PVOID)((ULONG_PTR)1 << (sizeof(void *) * 8 - 1));
    break;
  case 91:
    if (!VirtualFree(target, 16384, MEM_DECOMMIT))
      return 92;
    break;
  case 92:
    if (!VirtualFree(target, 4096, MEM_DECOMMIT))
      return 92;
    break;
  case 93:
    if (!VirtualFree(target, 0, MEM_RELEASE))
      return 92;
    break;
  case 94:
    if (!VirtualProtect(target, 4096, PAGE_NOACCESS, &old))
      return 92;
    break;
  case 95:
    if (!VirtualProtect(target, 4096, PAGE_READWRITE | PAGE_GUARD, &old))
      return 92;
    break;
  case 96:
    if (!VirtualProtect(target, 4096, PAGE_READONLY, &old))
      return 92;
    break;
  case 97:
    if (!VirtualProtect(target, 4096, PAGE_EXECUTE, &old))
      return 92;
    break;
  case 98:
    if (!VirtualProtect(target, 4096, PAGE_EXECUTE_READ, &old))
      return 92;
    break;
  case 192:
  case 99:
    if (!VirtualProtect(target, 4096, PAGE_READONLY | PAGE_GUARD, &old))
      return 92;
    break;
  }

  if (id >= 120 && id < 132) {
    switch (id) {
    case 120:
      count = 0;
      information = NULL;
      break;
    case 121:
      count = 0;
      ranges = NULL;
      break;
    case 122:
      count = 0;
      length = 0;
      break;
    case 123:
      count = 0;
      process = NULL;
      break;
    case 124:
      process = NULL;
      length = 0;
      break;
    case 125:
      process = NULL;
      information = NULL;
      break;
    case 126:
      process = NULL;
      ranges = NULL;
      break;
    case 127:
      length = 0;
      information = NULL;
      break;
    case 128:
      length = 0;
      ranges = NULL;
      break;
    case 129:
      information = NULL;
      ranges = NULL;
      break;
    case 130:
      flags = 2;
      ranges = NULL;
      break;
    case 131:
      flags = 2;
      process = NULL;
      break;
    }
  }
  if (id >= 132 && id < 140) {
    SIZE_T counts[] = {(SIZE_T)0x7fffffff, (SIZE_T)0x80000000,
                       (SIZE_T)0xffffffff, ~(SIZE_T)0};
    count = counts[(id - 132) % 4];
    ranges = (RANGE *)1;
    if (id >= 136)
      length = 0;
  }
  if (id >= 140 && id < 148) {
    class_id = (id & 1) ? 0xffffffff : 8;
    if (id == 142 || id == 143)
      length = 0;
    if (id == 144 || id == 145)
      information = NULL;
    if (id == 146 || id == 147)
      ranges = NULL;
  }
  if (id >= 148 && id < 156)
    information = (ULONG *)(controls + 16384 - (id - 148));
  if (id >= 156 && id < 180)
    ranges = (RANGE *)(controls + 4096 - (id - 156));
  if (id >= 180 && id < 192) {
    switch (id) {
    case 180:
      process = NULL;
      break;
    case 181:
      count = 0;
      break;
    case 182:
      length = 0;
      break;
    case 183:
      flags = 2;
      break;
    case 184:
      information = NULL;
      break;
    case 185:
      ranges = NULL;
      break;
    case 186:
      process = NULL;
      break;
    case 187:
      count = 0;
      break;
    case 188:
      length = 0;
      break;
    case 189:
      flags = 2;
      break;
    case 190:
      information = NULL;
      break;
    case 191:
      ranges = NULL;
      break;
    }
  }
  /* Materialize valid input copies before changing page protections. */
  if (information && (ULONG_PTR)information >= (ULONG_PTR)controls &&
      (ULONG_PTR)information < (ULONG_PTR)controls + 32764)
    memcpy(information, &flags, 4);
  if (ranges && (ULONG_PTR)ranges >= (ULONG_PTR)controls &&
      (ULONG_PTR)ranges < (ULONG_PTR)controls + 32768 - sizeof(pair))
    memcpy(ranges, pair, sizeof(pair));
  switch (id) {
  case 42:
    information = NULL;
    break;
  case 43:
    information = (ULONG *)1;
    break;
  case 46:
    VirtualProtect(controls + 8192, 4096, PAGE_READONLY, &old);
    break;
  case 47:
    VirtualProtect(controls + 8192, 4096, PAGE_NOACCESS, &old);
    break;
  case 48:
    VirtualProtect(controls + 8192, 4096, PAGE_READWRITE | PAGE_GUARD, &old);
    break;
  case 49:
    VirtualProtect(controls + 8192, 4096, PAGE_READONLY | PAGE_GUARD, &old);
    break;
  case 52:
    ranges = NULL;
    break;
  case 53:
    ranges = (RANGE *)1;
    break;
  case 56:
    VirtualProtect(controls, 4096, PAGE_READONLY, &old);
    break;
  case 57:
    VirtualProtect(controls, 4096, PAGE_NOACCESS, &old);
    break;
  case 58:
    VirtualProtect(controls, 4096, PAGE_READWRITE | PAGE_GUARD, &old);
    break;
  case 59:
    VirtualProtect(controls, 4096, PAGE_READONLY | PAGE_GUARD, &old);
    break;
  case 66:
    process = NULL;
    break;
  case 67:
    process = (HANDLE)0x1234;
    break;
  case 68:
    process = (HANDLE)(LONG_PTR)-2;
    break;
  case 69:
    owned = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!owned)
      return 91;
    process = owned;
    break;
  }
  if (id == 50 || id == 51 || (id >= 148 && id < 156))
    VirtualProtect(controls + 16384, 4096, PAGE_NOACCESS, &old);
  if (id == 60 || id == 61 || (id >= 156 && id < 180))
    VirtualProtect(controls + 4096, 4096, PAGE_NOACCESS, &old);
  if (id >= 180 && id < 186)
    VirtualProtect(controls, 4096, PAGE_READWRITE | PAGE_GUARD, &old);
  if (id >= 186 && id < 192)
    VirtualProtect(controls + 8192, 4096, PAGE_READWRITE | PAGE_GUARD, &old);

  ULONG_PTR before[4], after[4];
  unsigned before_mask = resident(target, before), after_mask;
  DWORD protections[3] = {protection(controls), protection(controls + 8192),
                          protection(target)};
  DWORD status = 0xdeadbeef, exception = 0;
  SetLastError(0x12345678);
  __try {
    status = (DWORD)set(process, class_id, count, ranges, information, length);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    exception = GetExceptionCode();
  }
  DWORD error = GetLastError();
  after_mask = resident(target, after);
  unsigned char range_bytes[32], info_bytes[32];
  unsigned range_mask, info_mask;
  snapshot(controls + 128, range_bytes, &range_mask);
  snapshot(controls + 8192 + 128, info_bytes, &info_mask);
  printf("{\"id\":%u,\"pointer_bytes\":%u,\"process\":%llu,\"class\":%lu,"
         "\"count\":%llu,\"ranges\":%llu,\"information\":%llu,\"length\":%lu,"
         "\"flags\":%lu,\"controls\":%llu,\"target\":%llu,\"range_address\":%"
         "llu,\"range_bytes\":%llu,\"status\":%lu,\"exception\":%lu,\"last_"
         "error\":%lu,\"before_valid\":%u,\"after_valid\":%u,\"protect_"
         "before\":[%lu,%lu,%lu],\"protect_after\":[%lu,%lu,%lu],\"ws_before\":"
         "[%llu,%llu,%llu,%llu],\"ws_after\":[%llu,%llu,%llu,%llu],\"range_"
         "snapshot_mask\":%u,\"range_snapshot\":",
         id, (unsigned)sizeof(void *), (unsigned long long)(ULONG_PTR)process,
         class_id, (unsigned long long)count,
         (unsigned long long)(ULONG_PTR)ranges,
         (unsigned long long)(ULONG_PTR)information, length, flags,
         (unsigned long long)(ULONG_PTR)controls,
         (unsigned long long)(ULONG_PTR)target,
         (unsigned long long)(ULONG_PTR)pair[0].address,
         (unsigned long long)pair[0].bytes, status, exception, error,
         before_mask, after_mask, protections[0], protections[1],
         protections[2], protection(controls), protection(controls + 8192),
         protection(target), (unsigned long long)before[0],
         (unsigned long long)before[1], (unsigned long long)before[2],
         (unsigned long long)before[3], (unsigned long long)after[0],
         (unsigned long long)after[1], (unsigned long long)after[2],
         (unsigned long long)after[3], range_mask);
  hex(range_bytes);
  printf(",\"info_snapshot_mask\":%u,\"info_snapshot\":", info_mask);
  hex(info_bytes);
  puts("}");
  if (owned)
    CloseHandle(owned);
  return 0;
}
