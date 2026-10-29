#include <stdint.h>
#include <stdio.h>
typedef struct { uint64_t x[4],nzcv,pc,v[4],fpcr,fpsr; } State;
extern void oracle_add_x(State*);
extern void oracle_add_w(State*);
extern void oracle_subs_x(State*);
extern void oracle_adds_x(State*);
extern void oracle_eor_x(State*);
extern void oracle_and_x(State*);
extern void oracle_orr_x(State*);
extern void oracle_nop(State*);
extern void oracle_b(State*);
extern void oracle_b_eq(State*);
extern void oracle_b_ne(State*);
extern void oracle_cbz(State*);
extern void oracle_cbnz(State*);
extern void oracle_fadd_s(State*);
extern void oracle_fadd_d(State*);
extern void oracle_fmul_d(State*);
typedef void(*Oracle)(State*);
int main(void){
Oracle functions[]={oracle_add_x,oracle_add_w,oracle_subs_x,oracle_adds_x,oracle_eor_x,oracle_and_x,oracle_orr_x,oracle_nop,oracle_b,oracle_b_eq,oracle_b_ne,oracle_cbz,oracle_cbnz,oracle_fadd_s,oracle_fadd_d,oracle_fmul_d};
uint32_t words[]={0x91000400,0x11000400,0xf1000400,0xab010000,0xca010000,0x8a010000,0xaa010000,0xd503201f,0x14000002,0x54000040,0x54000041,0xb4000040,0xb5000040,0x1e212800,0x1e612800,0x1e610800};
const uint64_t values[]={0,1,0x7fffffffffffffffULL,0x8000000000000000ULL,0xffffffffffffffffULL,0xaaaa5555aaaa5555ULL};
puts("[");
int first=1;
for(unsigned kind=0;kind<sizeof(functions)/sizeof(functions[0]);kind++) for(unsigned i=0;i<6;i++) for(unsigned flags=0;flags<16;flags++){
State s={.x={values[i],values[(i+1)%6],0x123456789abcdef0ULL,0xfedcba9876543210ULL},.nzcv=(uint64_t)flags<<28,.pc=0x100,.v={0x3ff8000000000000ULL,0x1122334455667788ULL,0xbfe0000000000000ULL,0x8877665544332211ULL}};
State initial=s;
for(unsigned iteration=0;iteration<128;iteration++) functions[kind](&s);
if(!first) puts(","); first=0;
printf("{\"word\":%u,\"sample\":%u,\"flags\":%u,\"initial_x\":[%llu,%llu,%llu,%llu],\"x\":[%llu,%llu,%llu,%llu],\"nzcv\":%llu,\"pc\":%llu,\"v\":[%llu,%llu,%llu,%llu],\"fpcr\":%llu,\"fpsr\":%llu}",words[kind],i,flags,initial.x[0],initial.x[1],initial.x[2],initial.x[3],s.x[0],s.x[1],s.x[2],s.x[3],s.nzcv,s.pc,s.v[0],s.v[1],s.v[2],s.v[3],s.fpcr,s.fpsr);
}
puts("\n]"); return 0;}
