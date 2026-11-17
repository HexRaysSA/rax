/* Explicit strict FP IR witness, no libm headers. */
#pragma STDC FENV_ACCESS ON
float strict_add(float x, float y) { return x+y; }
double strict_convert(long long x) { return (double)x; }
int strict_compare(double x, double y) { return x < y; }
