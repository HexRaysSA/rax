#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#if defined(_M_IX86)
extern "C" {
extern const unsigned char __safe_se_handler_table[];
extern const unsigned char __safe_se_handler_count;
struct ProbeLoadConfiguration {
  DWORD size, timestamp;
  WORD major, minor;
  DWORD zero[13];
  const void *handlers;
  DWORD count;
};
static_assert(sizeof(ProbeLoadConfiguration)==72);
static_assert(offsetof(ProbeLoadConfiguration,handlers)==offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32,SEHandlerTable));
extern const ProbeLoadConfiguration _load_config_used = {
  sizeof(ProbeLoadConfiguration),0,0,0,{0},__safe_se_handler_table,
  static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(&__safe_se_handler_count))
};
}
#endif
