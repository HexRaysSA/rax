// Compiler source-cell oracle fixture. No execution or lifetime claim.
struct V { int value; };
struct L : virtual V { int left; };
struct R : virtual V { int right; };
struct D : L, R { int own; };
struct N1 : V {};
struct N2 : V {};
struct Copies : N1, N2 {};
struct Nested { D member; D grid[2][3]; D second; };
struct EmptyA {};
struct EmptyB {};
struct EqualBases : EmptyA, EmptyB { int value; };
struct EqualMembers {
  [[no_unique_address]] EmptyA first;
  [[no_unique_address]] EmptyB second;
  int value;
};
union Choice { D first; D second; int value; };
struct Huge { V cells[1000000000ULL]; };
struct Singleton { D cells[1]; };
struct Bits { unsigned field : 3; unsigned : 0; int ordinary; };
struct PrefixHolder { D member; };
struct PrefixOwner : virtual PrefixHolder {};
