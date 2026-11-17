int same(int);
long same(long);
int same(int x) { return x; }
long same(long x) { return x; }
int shadows() { int a = 1; { int a = 2; if (a) return a; } return same(a); }
