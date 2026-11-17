using Throwing = int(*)(int);
using NoThrow = int(*)(int) noexcept;
static_assert(__is_convertible_to(NoThrow, Throwing));
static_assert(!__is_convertible_to(Throwing, NoThrow));
int no_throw(int) noexcept;
int may_throw(int);
Throwing weakened = &no_throw;
NoThrow exact = &no_throw;
#ifdef RAX_REJECT_NOEXCEPT_STRENGTHENING
NoThrow rejected = &may_throw;
#endif
