// Source/IR shape only; no ISO legality or portable byte-origin claim.
using F = int (*)(int);
static_assert(sizeof(F) == 8 && __is_trivially_copyable(F));

extern "C" __attribute__((noinline)) unsigned char relay(unsigned char value) {
  return value;
}
extern "C" unsigned char external_relay(unsigned char);

int copy_via_local(F original, int value) {
  F copied = nullptr;
  auto from = reinterpret_cast<const unsigned char *>(&original);
  auto to = reinterpret_cast<unsigned char *>(&copied);
  for (unsigned i = 0; i < sizeof(F); ++i)
    to[i] = relay(from[i]);
  return copied(value);
}

int copy_via_external(F original, int value) {
  F copied = nullptr;
  auto from = reinterpret_cast<const unsigned char *>(&original);
  auto to = reinterpret_cast<unsigned char *>(&copied);
  for (unsigned i = 0; i < sizeof(F); ++i)
    to[i] = external_relay(from[i]);
  return copied(value);
}
