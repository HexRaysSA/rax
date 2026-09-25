/*
 * RAROG -- a name-bound licence gate (keygen-me), full-screen TUI edition.
 * Single translation unit, no external libraries (POSIX: termios/ioctl/ANSI).
 * Builds:
 *   cc -O2 -o rarog rarog.c                 # the challenge (TUI validator)
 *   cc -O2 -DRAROG_FORGE -o rarog_forge rarog.c   # reference keygen
 * When stdin is not a TTY the validator drops to a plain line mode
 * (read "NAME:SIGIL" from stdin) so it stays scriptable.
 *
 * Decoded sigil (12 bytes, 24 runes):
 *   [0..3]A  [4..7]N  [8]mac  [9]flags(hi6 checked | lo2 = tier^cloak)  [10,11]crc16
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <poll.h>
#include <sys/ioctl.h>

#define R_ROUNDS  16u
#define RS        0x9A17C0DEu
#define MAGIC_X   0xF12EB19Du
#define MAGIC_Y   0x2A606C63u
#define TIER_STEP 0x51A3E7D1u
static const char RUNE[16] = { 'G','H','J','K','L','M','N','P','Q','R','S','T','V','W','X','Z' };

/* ==== obfuscated blobs ==== */
static const unsigned char b_tui_tag[] = { 0xc9, 0xe7, 0xaf, 0x5e, 0x4f, 0xa8, 0x53, 0xf1, 0x00, 0x4b, 0xb1, 0xcd, 0x24, 0x0a, 0x71, 0xa1, 0x85, 0xa2, 0xed, 0x66, 0x0f, 0x55, 0xdf, 0xb7, 0x9d, 0x68, 0xe5, 0x6f, 0x33, 0x40, 0xf9, 0x38 };
static const uint16_t b_tui_tag_s = 0x1f31u; /* n=32 */
static const unsigned char b_tui_ward[] = { 0x35, 0x1e, 0x41, 0xd0, 0x2d, 0x0e, 0x19, 0x12, 0xbf, 0x3e, 0xe0, 0x17, 0x1c, 0xb5, 0xf3, 0x37, 0x74 };
static const uint16_t b_tui_ward_s = 0x4b7cu; /* n=17 */
static const unsigned char b_tui_grant[] = { 0x54, 0x69, 0xe9, 0xa5, 0xd7, 0x57, 0xee, 0xa1, 0x89, 0x95, 0x32, 0x00, 0xb9, 0xa4, 0xc4, 0x32, 0xfc, 0x2b, 0x4e, 0xe1, 0x89, 0xff, 0x10, 0x55, 0x1f, 0x97, 0x36, 0x45, 0x6a, 0x0d, 0x85, 0xcd, 0x50, 0xa0 };
static const uint16_t b_tui_grant_s = 0x77c3u; /* n=34 */
static const unsigned char b_tui_near[] = { 0x2c, 0x9f, 0xd3, 0x52, 0x6a, 0xae, 0x3d, 0x58, 0x42, 0x6c, 0x6e, 0x7f, 0x01, 0x66, 0xb4, 0x95, 0x04, 0xa7, 0x47, 0x5c, 0xcd, 0x6b, 0x71, 0xfb, 0x9a, 0x16, 0x21, 0xcd, 0xab, 0xf4, 0x8c, 0x1a, 0x82, 0x0e, 0xcf, 0x63, 0xfa, 0xfc, 0x44, 0x03, 0x64, 0x1d, 0xb3, 0x96, 0x7d, 0x26, 0xc6 };
static const uint16_t b_tui_near_s = 0x5d2au; /* n=47 */
static const unsigned char b_tui_shape[] = { 0x72, 0x84, 0x5f, 0x5e, 0x36, 0x5b, 0x9b, 0xb0, 0x39, 0x7e, 0x9b, 0x9e, 0x8b, 0x15, 0x55, 0x92, 0xc1, 0xe3, 0x6f, 0xfc, 0x5c, 0x60, 0x80, 0x94, 0x52, 0x02, 0x86, 0xd0, 0x51, 0x17, 0xdf, 0x31, 0x01, 0x23, 0xb5, 0x63, 0x3e, 0x38, 0xd2, 0xfd, 0xe9, 0x48, 0x28, 0xea };
static const uint16_t b_tui_shape_s = 0x38b1u; /* n=44 */
static const unsigned char b_tui_trap[] = { 0x76, 0x6b, 0x04, 0xf9, 0xda, 0x39, 0xbb, 0xf4, 0x8c, 0x7d, 0xaf, 0xd6, 0xaf, 0xe8, 0xb3, 0x87, 0xf5, 0x16, 0x40, 0xf0, 0xa5, 0xbb, 0x52, 0x6f, 0xfb, 0xa4, 0x8e, 0x8c, 0x75, 0x72, 0xc5, 0x4b, 0xf4, 0xdb, 0xd6, 0x16, 0x6d, 0x74, 0x70, 0xc3, 0x57, 0xec, 0xfa, 0x35, 0xc0, 0x8a, 0x05, 0x29, 0xce, 0x3b, 0xa7, 0xd7, 0x62, 0x23, 0xd4, 0xd9, 0x5a, 0x77, 0xcd, 0x75 };
static const uint16_t b_tui_trap_s = 0x6f9du; /* n=60 */
static const unsigned char b_t0[] = { 0x35, 0x82, 0x23, 0x12, 0xb6 };
static const uint16_t b_t0_s = 0x1122u; /* n=5 */
static const unsigned char b_t1[] = { 0x23, 0xf7, 0x06, 0x09, 0xc9 };
static const uint16_t b_t1_s = 0x3344u; /* n=5 */
static const unsigned char b_t2[] = { 0x42, 0x7d, 0x98, 0x3e, 0x52 };
static const uint16_t b_t2_s = 0x5566u; /* n=5 */
static const unsigned char b_t3[] = { 0xd0, 0x15, 0x44, 0xf4, 0xd1, 0xb4, 0xf9 };
static const uint16_t b_t3_s = 0x7788u; /* n=7 */
static const unsigned char b_kg_hdr[] = { 0xa4, 0x3c, 0xf7, 0x55, 0xe9, 0xde, 0x44, 0x3b, 0x1e, 0xed, 0x7d, 0xe8, 0xb7, 0x76, 0xe0, 0x32, 0x12, 0x6f, 0xa0, 0xc0, 0x33, 0x8f, 0xdd, 0x61, 0xcf, 0x0a, 0xb7, 0xd4, 0xd2, 0x55, 0x58, 0x39, 0x48, 0xa4, 0x89, 0x3e, 0xb8 };
static const uint16_t b_kg_hdr_s = 0xa1b2u; /* n=37 */
static const unsigned char b_kg_key[] = { 0x93, 0x02, 0x7e, 0xd5, 0x9d, 0x4d, 0x82, 0xfd, 0x20, 0x40 };
static const uint16_t b_kg_key_s = 0xa3b4u; /* n=10 */
static const unsigned char b_kg_usage[] = { 0xae, 0x3c, 0x76, 0x36, 0x62, 0x1d, 0x4f, 0xf3, 0x19, 0x90, 0x8d, 0x88, 0xda, 0x54, 0x68, 0xb0, 0x3b, 0xc2, 0xaa, 0x72, 0x19, 0x30, 0xb1, 0x5c, 0x67, 0xa6, 0xdf, 0x32, 0x6d, 0xa2, 0xd0, 0x6e, 0x23, 0x86, 0x3c, 0x99, 0x15, 0x0b, 0x88, 0xee, 0xba, 0x20, 0xe6, 0x8d, 0xaf, 0x54, 0xeb, 0xd2, 0xaf, 0x5f, 0x86, 0xc0, 0x15, 0xd2, 0x2f, 0x47, 0x00, 0xdb, 0xd7, 0xf3, 0x7b, 0xa0, 0xe3, 0x73 };
static const uint16_t b_kg_usage_s = 0xa5b6u; /* n=64 */
static const unsigned char b_kg_tier[] = { 0xd0, 0x6f, 0x44, 0xa3, 0x39, 0x39, 0x5f, 0xa8, 0x44, 0xf3, 0xf6, 0x95, 0xeb, 0xb7 };
static const uint16_t b_kg_tier_s = 0xa7b8u; /* n=14 */

static size_t reveal(const unsigned char *e, size_t n, uint16_t seed, char *out, size_t cap) {
    if (n >= cap) n = cap - 1;
    memcpy(out, e, n);
    uint16_t s = seed ? seed : 0xACE1u;
    for (size_t i = 0; i < n; ++i) {
        unsigned ks = 0;
        for (int b = 0; b < 8; ++b) { unsigned lsb = s & 1u; s >>= 1; if (lsb) s ^= 0xB400u; ks = (ks<<1)|lsb; }
        out[i] ^= (unsigned char)(ks ^ (unsigned char)(i * 0x2fu + (seed & 0xffu)));
    }
    out[n] = 0; return n;
}
#define REVEAL(name, buf) reveal(b_##name, sizeof(b_##name), b_##name##_s, (buf), sizeof(buf))
static void tier_reveal(unsigned t, char *out, size_t cap) {
    const unsigned char *e; size_t n; uint16_t s;
    switch (t & 3u) {
        case 0u: e=b_t0; n=sizeof b_t0; s=b_t0_s; break;
        case 1u: e=b_t1; n=sizeof b_t1; s=b_t1_s; break;
        case 2u: e=b_t2; n=sizeof b_t2; s=b_t2_s; break;
        default: e=b_t3; n=sizeof b_t3; s=b_t3_s; break;
    }
    reveal(e, n, s, out, cap);
}
#if defined(RAROG_FORGE)
static void say(const unsigned char *e, size_t n, uint16_t seed, FILE *q) {
    unsigned char buf[256]; if (n > sizeof buf) n = sizeof buf; memcpy(buf, e, n);
    uint16_t s = seed ? seed : 0xACE1u;
    for (size_t i = 0; i < n; ++i) { unsigned ks=0; for(int b=0;b<8;b++){unsigned lsb=s&1u;s>>=1;if(lsb)s^=0xB400u;ks=(ks<<1)|lsb;} buf[i]^=(unsigned char)(ks^(unsigned char)(i*0x2fu+(seed&0xffu))); }
    fwrite(buf, 1u, n, q);
}
#define SAY(name, q) say(b_##name, sizeof(b_##name), b_##name##_s, (q))
#endif

/* ==== core primitives (unchanged) ==== */
static uint32_t rotl32(uint32_t x, unsigned r){ r&=31u; return (x<<r)|(x>>((32u-r)&31u)); }
static uint32_t rotr32(uint32_t x, unsigned r){ r&=31u; return (x>>r)|(x<<((32u-r)&31u)); }
static void speck(uint32_t *x, uint32_t *y, uint32_t k){ uint32_t a=*x,b=*y; a=(rotr32(a,8)+b); a^=k; b=rotl32(b,3)^a; *x=a; *y=b; }
static void schedule(unsigned tier, uint32_t k[R_ROUNDS]){ k[0]=RS; for(unsigned i=1;i<R_ROUNDS;++i){ uint32_t t=k[i-1]^(i*0x9E3779B9u+tier*0x85EBCA6Bu); k[i]=rotl32(t,5)+0x27D4EB2Du; } }
static uint32_t fnv1a(const unsigned char *p, size_t n){ uint32_t h=0x811c9dc5u; for(size_t i=0;i<n;++i){h^=p[i];h*=0x01000193u;} return h; }
static uint16_t crc16(const unsigned char *p, size_t n){ uint16_t c=0xFFFFu; for(size_t i=0;i<n;++i){ c^=(uint16_t)p[i]<<8; for(int b=0;b<8;b++) c=(c&0x8000u)?(uint16_t)((c<<1)^0x1021u):(uint16_t)(c<<1);} return c; }
static void norm(const char *s, size_t len, unsigned char *out, size_t *on){ size_t j=0; for(size_t i=0;i<len;++i){ unsigned c=(unsigned char)s[i]; if(c=='-'||c=='_'||c==' ')continue; if(c>='A'&&c<='Z')c+=32u; out[j++]=(unsigned char)c;} *on=j; }

static void derive(const char *name, size_t nlen, unsigned tier, unsigned char sig[12]) {
    unsigned char nb[256]; size_t nn=0; if(nlen>sizeof nb)nlen=sizeof nb; norm(name,nlen,nb,&nn);
    uint32_t oh=fnv1a(nb,nn);
    uint32_t ks[R_ROUNDS]; schedule(tier,ks);
    uint32_t x=oh^MAGIC_X, y=MAGIC_Y+tier*TIER_STEP;
    for(unsigned r=0;r<R_ROUNDS;++r) speck(&x,&y,ks[r]);
    uint32_t A=x,N=y;
    unsigned cloak=((A>>5)^(N>>11)^(A*N))&3u;
    sig[0]=(unsigned char)A; sig[1]=(unsigned char)(A>>8); sig[2]=(unsigned char)(A>>16); sig[3]=(unsigned char)(A>>24);
    sig[4]=(unsigned char)N; sig[5]=(unsigned char)(N>>8); sig[6]=(unsigned char)(N>>16); sig[7]=(unsigned char)(N>>24);
    unsigned char mb[9]; memcpy(mb,sig,8); mb[8]=(unsigned char)tier; uint32_t m=fnv1a(mb,9);
    sig[8]=(unsigned char)((m^(m>>8)^(m>>16)^(m>>24))&0xffu);
    sig[9]=(unsigned char)(((m>>3)&0xFCu)|((tier^cloak)&3u));
    uint16_t tag=crc16(sig,10); sig[10]=(unsigned char)tag; sig[11]=(unsigned char)(tag>>8);
}

static int rune_val(unsigned c){ if(c>='a'&&c<='z')c-=32u; for(int i=0;i<16;++i) if((unsigned char)RUNE[i]==c) return i; return -1; }
static int decode_sigil(const char *s, unsigned char out[12]){
    unsigned nib[24]; unsigned k=0;
    for(size_t i=0;s[i];++i){ unsigned c=(unsigned char)s[i]; if(c=='-'||c==' '||c=='\t'||c=='\r'||c=='\n')continue; int v=rune_val(c); if(v<0)return -1; if(k>=24u)return -1; nib[k++]=(unsigned)v; }
    if(k!=24u)return -1; for(unsigned i=0;i<12u;++i) out[i]=(unsigned char)((nib[2*i]<<4)|nib[2*i+1]); return 0;
}
#if defined(RAROG_FORGE)
static void encode_sigil(const unsigned char in[12], char out[28]){ unsigned j=0; for(unsigned i=0;i<12u;++i){ if(i&&(i%3u)==0u)out[j++]='-'; out[j++]=RUNE[(in[i]>>4)&0xfu]; out[j++]=RUNE[in[i]&0xfu]; } out[j]=0; }
#endif

/* ==== analysis-only distractions (never affect the live verdict) ==== */
static int opq(uint32_t x){ return (int)((x*x+x)&1u); }  /* x*x+x always even -> always 0 */
static const unsigned char SB[256] = {
 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };
static uint32_t sbnoise(uint32_t x){ unsigned char v=SB[x&0xffu]; return (uint32_t)(v^v); } /* == 0 */
static unsigned rarog_shadow(const unsigned char sig[12], const char *name, size_t nlen){
    unsigned char probe[12]; derive(name,nlen,(unsigned)(sig[9]&3u),probe);
    uint32_t acc=fnv1a(probe,12)^fnv1a(sig,12); acc+=sbnoise(acc);
    return (acc==0x1CEDF00Du)?(1u|(2u<<1)):0u;
}

/* ==== real verdict: bit0=granted, bit1=well-shaped, bits2-3=tier ==== */
static unsigned verify(const char *name, size_t nlen, const char *sigil){
    unsigned char sig[12]; if(decode_sigil(sigil,sig)!=0) return 0u;
    unsigned shaped=2u;
    uint32_t A=(uint32_t)sig[0]|((uint32_t)sig[1]<<8)|((uint32_t)sig[2]<<16)|((uint32_t)sig[3]<<24);
    uint32_t N=(uint32_t)sig[4]|((uint32_t)sig[5]<<8)|((uint32_t)sig[6]<<16)|((uint32_t)sig[7]<<24);
    unsigned cloak=((A>>5)^(N>>11)^(A*N))&3u;
    unsigned tier=((unsigned)sig[9]&3u)^cloak;
    if(opq(A^N)) return rarog_shadow(sig,name,nlen)|shaped;   /* dead path */
    unsigned char want[12]; derive(name,nlen,tier,want);
    int ok=(memcmp(want,sig,12)==0);
    return (ok?1u:0u)|shaped|((tier&3u)<<2);
}

#if defined(RAROG_FORGE)
static unsigned tier_of(const char *s){ char u[16]; size_t i=0; for(;s[i]&&i<sizeof(u)-1;++i){unsigned c=(unsigned char)s[i]; if(c>='a'&&c<='z')c-=32; u[i]=(char)c;} u[i]=0;
    if(!strcmp(u,"SPARK"))return 0u; if(!strcmp(u,"EMBER"))return 1u; if(!strcmp(u,"BLAZE"))return 2u; if(!strcmp(u,"INFERNO"))return 3u; return 4u; }
int main(int argc,char**argv){
    if(argc<2){SAY(kg_usage,stdout);return 1;}
    unsigned char pn[64]; size_t pl; norm(argv[1],strlen(argv[1]),pn,&pl);
    if(fnv1a(pn,pl)!=0x6c7ac5d9u) return 1;
    if(argc<4){SAY(kg_usage,stdout);return 1;}
    unsigned t=tier_of(argv[2]); if(t>3u){SAY(kg_tier,stdout);return 1;}
    char name[256]; size_t p=0;
    for(int a=3;a<argc&&p<sizeof(name)-1;++a){ if(a>3&&p<sizeof(name)-1)name[p++]=' '; for(size_t i=0;argv[a][i]&&p<sizeof(name)-1;++i)name[p++]=argv[a][i]; }
    name[p]=0;
    unsigned char sig[12]; char runes[28]; derive(name,p,t,sig); encode_sigil(sig,runes);
    SAY(kg_hdr,stdout); tier_reveal(t, (char[16]){0}, 16); /* keep symbol used */
    { char tw[16]; tier_reveal(t,tw,sizeof tw); fwrite(tw,1,strlen(tw),stdout); }
    SAY(kg_key,stdout); fwrite(runes,1u,strlen(runes),stdout); fputc('\n',stdout);
    return 0;
}
#else
/* ================= TUI frontend ================= */
static char SPACES[1024];
static char FB[1u<<18]; static size_t FBn;
static struct termios g_orig; static int g_raw = 0;
static volatile sig_atomic_t g_winch = 1;

/* app state */
static char g_name[64] = {0};
static char g_sigil[64] = {0};
static int  g_focus = 0;          /* 0 = name, 1 = sigil */
static int  g_kind  = 0;          /* 0 none 1 grant 2 near 3 shape 4 trap */
static char g_gv1[96] = {0};
static char g_gvt[16] = {0};

static void af(const char *fmt, ...){
    if(FBn>=sizeof FB) return;
    va_list ap; va_start(ap,fmt);
    int k=vsnprintf(FB+FBn,sizeof FB-FBn,fmt,ap); va_end(ap);
    if(k>0) FBn+=(size_t)k; if(FBn>sizeof FB) FBn=sizeof FB;
}
static void flush_fb(void){ if(FBn){ ssize_t w=write(STDOUT_FILENO,FB,FBn); (void)w; FBn=0; } }
static void FG(int r,int g,int b){ af("\x1b[38;2;%d;%d;%dm",r,g,b); }
static void BG(int r,int g,int b){ af("\x1b[48;2;%d;%d;%dm",r,g,b); }
static void CUP(int y,int x){ af("\x1b[%d;%dH",y,x); }
static void SPn(int n){ if(n<0)n=0; if(n>(int)sizeof SPACES-1)n=(int)sizeof SPACES-1; af("%.*s",n,SPACES); }

static void grad(double t,int*R,int*G,int*B){
    double s0[3]={255,180,80}, s1[3]={255,110,50}, s2[3]={200,55,42}, *a,*b,u;
    if(t<0.5){a=s0;b=s1;u=t/0.5;} else {a=s1;b=s2;u=(t-0.5)/0.5;}
    *R=(int)(a[0]+(b[0]-a[0])*u); *G=(int)(a[1]+(b[1]-a[1])*u); *B=(int)(a[2]+(b[2]-a[2])*u);
}
static void ctext(int y,int ox,int cardW,int r,int g,int b,const char*s,int cols){
    int Wi=cardW-2, pad=(Wi-cols)/2; if(pad<0)pad=0;
    CUP(y,ox+1+pad); BG(28,20,18); FG(r,g,b); af("%s",s);
}
static void ltext(int y,int x,int r,int g,int b,const char*s){ CUP(y,x); BG(28,20,18); FG(r,g,b); af("%s",s); }

static void draw_well(int y,int ox,int cardW,int focused,const char*val){
    int Wi=cardW-2, Fx=ox+4, Fw=Wi-6;
    int wr,wg,wb; if(focused){wr=58;wg=40;wb=32;} else {wr=42;wg=30;wb=26;}
    CUP(y,Fx-1); BG(wr,wg,wb); if(focused)FG(255,150,70);else FG(120,100,88); af("\u27e8");
    CUP(y,Fx);   BG(wr,wg,wb); SPn(Fw);
    int len=(int)strlen(val), dl=len; const char*disp=val;
    if(len>Fw-1){ disp=val+(len-(Fw-1)); dl=Fw-1; }
    CUP(y,Fx); BG(wr,wg,wb); FG(235,225,205); af("%.*s",dl,disp);
    if(focused){ CUP(y,Fx+dl); BG(wr,wg,wb); FG(255,160,80); af("\u258f"); }
    CUP(y,Fx+Fw); BG(wr,wg,wb); if(focused)FG(255,150,70);else FG(120,100,88); af("\u27e9");
}

static void get_size(int*W,int*H){
    struct winsize ws;
    if(ioctl(STDOUT_FILENO,TIOCGWINSZ,&ws)==0 && ws.ws_col>0){ *W=ws.ws_col; *H=ws.ws_row; }
    else { *W=80; *H=24; }
}

static void redraw(void){
    int W,H; get_size(&W,&H); FBn=0;
    if(W<50||H<21){
        BG(18,13,12); for(int r=1;r<=H;r++){CUP(r,1);SPn(W);}
        const char*m="terminal too small - resize to at least 50 x 21";
        CUP(H/2, (W-(int)strlen(m))/2>0?(W-(int)strlen(m))/2:1); FG(230,150,120); af("%s",m);
        af("\x1b[0m"); flush_fb(); return;
    }
    int cardW=W-6; if(cardW>66)cardW=66; if(cardW<48)cardW=48;
    int cardH=19, ox=(W-cardW)/2, oy=(H-cardH)/2; if(ox<1)ox=1; if(oy<1)oy=1;

    BG(18,13,12); for(int r=1;r<=H;r++){CUP(r,1);SPn(W);}            /* backdrop */
    BG(9,6,6);   for(int i=0;i<cardH;i++){CUP(oy+1+i,ox+2);SPn(cardW);}  /* shadow */

    for(int row=0;row<cardH;row++){                                  /* card + border */
        int y=oy+row; double t=(double)row/(double)(cardH-1); int br,bg,bb; grad(t,&br,&bg,&bb);
        if(row==0){ CUP(y,ox); BG(28,20,18); FG(br,bg,bb); af("\u256d"); for(int k=0;k<cardW-2;k++)af("\u2500"); af("\u256e"); }
        else if(row==cardH-1){ CUP(y,ox); BG(28,20,18); FG(br,bg,bb); af("\u2570"); for(int k=0;k<cardW-2;k++)af("\u2500"); af("\u256f"); }
        else { CUP(y,ox); BG(28,20,18); FG(br,bg,bb); af("\u2502"); BG(28,20,18); SPn(cardW-2); FG(br,bg,bb); af("\u2502"); }
    }

    int Wi=cardW-2;
    /* flame bar (per-char gradient, hot in the middle) */
    { const char*fl[11]={"\u2581","\u2582","\u2583","\u2585","\u2586","\u2587","\u2586","\u2585","\u2583","\u2582","\u2581"};
      int pad=(Wi-11)/2; CUP(oy+2,ox+1+pad); BG(28,20,18);
      for(int i=0;i<11;i++){ double d=(double)i/10.0*2.0-1.0; if(d<0)d=-d; double hot=1.0-d;
        int r=(int)(150+ (255-150)*hot), g=(int)(50+ (215-50)*hot), b=(int)(30+ (110-30)*hot);
        FG(r,g,b); af("%s",fl[i]); } }
    ctext(oy+3,  ox,cardW, 255,214,150, "\u2726   R A R O G   \u2726", 17);
    { char b[64]; REVEAL(tui_tag,b); ctext(oy+4,ox,cardW, 152,132,112, b, (int)strlen(b)); }
    { char w[64],line[96]; REVEAL(tui_ward,w); snprintf(line,sizeof line,"\u27e1 %s \u27e1",w);
      ctext(oy+6,ox,cardW, 255,172,92, line, (int)strlen(w)+4); }

    ltext(oy+8, ox+4, 150,130,112, "NAME");
    draw_well(oy+9, ox,cardW, g_focus==0, g_name);
    ltext(oy+10,ox+4, 150,130,112, "SIGIL");
    draw_well(oy+11,ox,cardW, g_focus==1, g_sigil);

    /* live shape hint */
    { unsigned rc=0; int bad=0; for(const char*p=g_sigil;*p;++p){ unsigned c=(unsigned char)*p; if(c=='-'||c==' ')continue; if(rune_val(c)<0)bad=1; else rc++; }
      char h[48]; int r,g,b;
      if(bad){ snprintf(h,sizeof h,"unknown rune present"); r=232;g=140;b=140; }
      else if(rc==0){ snprintf(h,sizeof h,"awaiting your sigil"); r=150;g=130;b=110; }
      else if(rc==24){ snprintf(h,sizeof h,"well-formed  (12/12 bytes)"); r=150;g=220;b=150; }
      else { snprintf(h,sizeof h,"%u/24 runes", rc); r=200;g=180;b=120; }
      ltext(oy+12, ox+4, r,g,b, h); }

    /* verdict */
    if(g_kind==1){ ctext(oy+14,ox,cardW, 130,240,150, g_gv1, (int)strlen(g_gv1));
                   ctext(oy+15,ox,cardW, 255,214,120, g_gvt, (int)strlen(g_gvt)); }
    else if(g_kind==2){ ctext(oy+14,ox,cardW, 255,196,80, g_gv1, (int)strlen(g_gv1)); }
    else if(g_kind==3){ ctext(oy+14,ox,cardW, 255,110,110, g_gv1, (int)strlen(g_gv1)); }
    else if(g_kind==4){ ctext(oy+14,ox,cardW, 255,120,90, g_gv1, (int)strlen(g_gv1)); }

    ctext(oy+17,ox,cardW, 112,96,86, "Tab: switch    Enter: offer    Esc: leave", 41);
    af("\x1b[0m"); flush_fb();
}

static void cleanup(void){
    if(g_raw){ tcsetattr(STDIN_FILENO,TCSAFLUSH,&g_orig); g_raw=0; }
    ssize_t w=write(STDOUT_FILENO,"\x1b[0m\x1b[?25h\x1b[?1049l",18); (void)w;
}
static void on_sig(int s){ (void)s; cleanup(); _exit(0); }
static void on_winch(int s){ (void)s; g_winch=1; }

static void submit(void){
    if(strstr(g_sigil,"INFERNO.KEEPER.OVERRIDE")){ g_kind=4; REVEAL(tui_trap,g_gv1); return; }
    unsigned v=verify(g_name,strlen(g_name),g_sigil);
    if(v&1u){ g_kind=1; REVEAL(tui_grant,g_gv1); tier_reveal((v>>2)&3u,g_gvt,sizeof g_gvt); }
    else if(v&2u){ g_kind=2; REVEAL(tui_near,g_gv1); }
    else { g_kind=3; REVEAL(tui_shape,g_gv1); }
}

static int line_mode(void){
    char line[256]; if(!fgets(line,sizeof line,stdin)){ puts("nothing offered"); return 1; }
    size_t L=strlen(line); while(L&&(line[L-1]=='\n'||line[L-1]=='\r'))line[--L]=0;
    char b[96];
    if(strstr(line,"INFERNO.KEEPER.OVERRIDE")){ REVEAL(tui_trap,b); puts(b); return 1; }
    char*c=strchr(line,':'); if(!c){ REVEAL(tui_shape,b); puts(b); return 1; }
    *c=0; unsigned v=verify(line,strlen(line),c+1);
    if(v&1u){ char t[16]; REVEAL(tui_grant,b); tier_reveal((v>>2)&3u,t,sizeof t); printf("%s %s\n",b,t); return 0; }
    if(v&2u){ REVEAL(tui_near,b); puts(b); return 1; }
    REVEAL(tui_shape,b); puts(b); return 1;
}

static void field_append(char*buf,size_t cap,int c){ size_t n=strlen(buf); if(n+1<cap && n<40){ buf[n]=(char)c; buf[n+1]=0; } }
static void field_back(char*buf){ size_t n=strlen(buf); if(n) buf[n-1]=0; }

int main(void){
    memset(SPACES,' ',sizeof SPACES);
    if(!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) return line_mode();

    if(tcgetattr(STDIN_FILENO,&g_orig)!=0) return line_mode();
    struct termios raw=g_orig; raw.c_lflag &= ~(unsigned)(ICANON|ECHO); raw.c_cc[VMIN]=1; raw.c_cc[VTIME]=0;
    if(tcsetattr(STDIN_FILENO,TCSAFLUSH,&raw)!=0) return line_mode();
    g_raw=1; atexit(cleanup);
    signal(SIGINT,on_sig); signal(SIGTERM,on_sig); signal(SIGWINCH,on_winch);
    { ssize_t w=write(STDOUT_FILENO,"\x1b[?1049h\x1b[?25l",13); (void)w; }

    for(;;){
        if(g_winch){ g_winch=0; redraw(); }
        struct pollfd pf={ STDIN_FILENO, POLLIN, 0 };
        int pr=poll(&pf,1,-1);
        if(pr<0){ if(g_winch) continue; break; }
        if(!(pf.revents&POLLIN)) continue;
        unsigned char c; if(read(STDIN_FILENO,&c,1)!=1) break;

        if(c==27){                                   /* ESC or CSI seq */
            struct pollfd p2={ STDIN_FILENO, POLLIN, 0 };
            if(poll(&p2,1,30)>0){ unsigned char a; if(read(STDIN_FILENO,&a,1)==1 && a=='['){ unsigned char b; if(read(STDIN_FILENO,&b,1)==1){ if(b=='A'||b=='B') g_focus^=1; } } }
            else break;                              /* lone ESC -> quit */
        } else if(c=='\t'){ g_focus^=1; }
        else if(c=='\n'||c=='\r'){ submit(); }
        else if(c==127||c==8){ field_back(g_focus?g_sigil:g_name); g_kind=0; }
        else if(c>=32&&c<127){ field_append(g_focus?g_sigil:g_name, 64, c); g_kind=0; }
        redraw();
    }
    cleanup();
    return 0;
}
#endif
