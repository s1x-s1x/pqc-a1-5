/* SM3 compression and padding from the published GB/T 32905 definition. */
#include "sm3.h"
#include "secure_zero.h"
#include <string.h>
static uint32_t rot(uint32_t x, unsigned n) { n &= 31; return n ? (x << n) | (x >> (32-n)) : x; }
static uint32_t rd(const uint8_t *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static void wr(uint8_t *p, uint32_t x) { p[0]=x>>24; p[1]=x>>16; p[2]=x>>8; p[3]=x; }
static void compress(a15_sm3 *s, const uint8_t *p) {
    uint32_t w[68], a=s->h[0], b=s->h[1], c=s->h[2], d=s->h[3];
    uint32_t e=s->h[4], f=s->h[5], g=s->h[6], h=s->h[7];
    for(unsigned j=0;j<16;j++) w[j]=rd(p+4*j);
    for(unsigned j=16;j<68;j++) {
        uint32_t x=w[j-16]^w[j-9]^rot(w[j-3],15);
        w[j]=x^rot(x,15)^rot(x,23)^rot(w[j-13],7)^w[j-6];
    }
    for(unsigned j=0;j<64;j++) {
        uint32_t ar=rot(a,12), ss1=rot(ar+e+rot(j<16?0x79cc4519u:0x7a879d8au,j),7);
        uint32_t ff=j<16?a^b^c:(a&b)|(a&c)|(b&c);
        uint32_t gg=j<16?e^f^g:(e&f)|(~e&g);
        uint32_t t1=ff+d+(ss1^ar)+(w[j]^w[j+4]);
        uint32_t t2=gg+h+ss1+w[j];
        d=c; c=rot(b,9); b=a; a=t1;
        h=g; g=rot(f,19); f=e; e=t2^rot(t2,9)^rot(t2,17);
    }
    s->h[0]^=a; s->h[1]^=b; s->h[2]^=c; s->h[3]^=d;
    s->h[4]^=e; s->h[5]^=f; s->h[6]^=g; s->h[7]^=h;
    a15_secure_zero(w,sizeof w);
}
void a15_sm3_init(a15_sm3 *s) {
    static const uint32_t iv[8]={0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e};
    memcpy(s->h,iv,sizeof iv); s->bytes=0; s->used=0;
}
void a15_sm3_compress_block(uint32_t state[8],const uint8_t block[64]) {
    a15_sm3 s;memcpy(s.h,state,sizeof s.h);compress(&s,block);memcpy(state,s.h,sizeof s.h);a15_secure_zero(&s,sizeof s);
}
void a15_sm3_update(a15_sm3 *s, const void *vp, size_t n) {
    const uint8_t *p=vp; s->bytes+=n;
    while(n) { size_t z=64-s->used; if(z>n) z=n; memcpy(s->buf+s->used,p,z); s->used+=z; p+=z; n-=z;
        if(s->used==64) { compress(s,s->buf); s->used=0; } }
}
void a15_sm3_final(a15_sm3 *s, uint8_t out[32]) {
    uint64_t bits=s->bytes*8; s->buf[s->used++]=0x80;
    if(s->used>56) { memset(s->buf+s->used,0,64-s->used); compress(s,s->buf); s->used=0; }
    memset(s->buf+s->used,0,56-s->used);
    for(unsigned i=0;i<8;i++) s->buf[63-i]=(uint8_t)(bits>>(8*i));
    compress(s,s->buf); for(unsigned i=0;i<8;i++) wr(out+4*i,s->h[i]);
}
