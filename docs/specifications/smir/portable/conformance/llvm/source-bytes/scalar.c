typedef unsigned char char8_t;
typedef unsigned char uint8_t;
typedef signed char int8_t;
char plain;
signed char signed_byte;
unsigned char unsigned_byte;
char8_t char8_alias;
uint8_t uint8_alias;
int8_t int8_alias;
_Bool flag;
unsigned _BitInt(1) b1;
unsigned _BitInt(8) b8;
unsigned _BitInt(9) b9;
signed _BitInt(17) b17;
unsigned _BitInt(65) b65;
_Atomic(unsigned char) atomic_byte;
void function(int n) { char variable_array[n]; (void)variable_array; }
