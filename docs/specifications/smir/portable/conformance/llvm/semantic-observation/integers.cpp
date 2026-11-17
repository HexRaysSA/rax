unsigned __int128 widen() { return static_cast<unsigned __int128>(0xffffffffffffffffULL); }
long negative() { return -2147483649L; }
unsigned wrap() { return 0xffffffffu; }
int cast(long v) { int x=static_cast<int>(v); return (x+1)*2; }
