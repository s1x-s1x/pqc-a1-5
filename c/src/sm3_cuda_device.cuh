/* CUDA/host-compilable arithmetic shared with a private CPU algorithm harness.
 * The host harness never advertises a CUDA backend or substitutes for GPU QA. */
#ifndef A15_SM3_CUDA_DEVICE_CUH
#define A15_SM3_CUDA_DEVICE_CUH
#include <stdint.h>
#include <stddef.h>
#ifdef SLH_TEST_BUILD
#ifndef SLH_TEST_FAULT_POINT
#define SLH_TEST_FAULT_POINT 0
#endif
#endif
#ifdef __CUDACC__
#define A15_DEVICE __device__ __forceinline__
#else
#define A15_DEVICE inline
#endif
struct a15_cuda_job {
 uint32_t seed[8];uint8_t skseed[16],adrs[32];uint32_t start;
#ifdef SLH_TEST_BUILD
 unsigned fault_site;uint32_t fault_index;
#endif
};
A15_DEVICE uint32_t cuda_rot(uint32_t x,unsigned n){n&=31;return n?(x<<n)|(x>>(32-n)):x;}
A15_DEVICE uint32_t cuda_read32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
A15_DEVICE void cuda_put32(uint8_t *p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
A15_DEVICE void cuda_sm3_compress(uint32_t s[8],const uint8_t b[64]){
 uint32_t w[68];for(unsigned j=0;j<16;j++)w[j]=cuda_read32(b+4*j);
 for(unsigned j=16;j<68;j++){uint32_t x=w[j-16]^w[j-9]^cuda_rot(w[j-3],15);w[j]=x^cuda_rot(x,15)^cuda_rot(x,23)^cuda_rot(w[j-13],7)^w[j-6];}
 uint32_t a=s[0],b0=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
 for(unsigned j=0;j<64;j++){
  uint32_t ar=cuda_rot(a,12),ss1=cuda_rot(ar+e+cuda_rot(j<16?0x79cc4519u:0x7a879d8au,j),7);
  uint32_t ff=j<16?a^b0^c:(a&b0)|(a&c)|(b0&c),gg=j<16?e^f^g:(e&f)|(~e&g);
  uint32_t t1=ff+d+(ss1^ar)+(w[j]^w[j+4]),t2=gg+h+ss1+w[j];
  d=c;c=cuda_rot(b0,9);b0=a;a=t1;h=g;g=cuda_rot(f,19);f=e;e=t2^cuda_rot(t2,9)^cuda_rot(t2,17);
 }
 s[0]^=a;s[1]^=b0;s[2]^=c;s[3]^=d;s[4]^=e;s[5]^=f;s[6]^=g;s[7]^=h;
}
A15_DEVICE void cuda_sm3_hash(const uint8_t *input,size_t length,uint8_t out[32]){
 uint32_t s[8]={0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e};
 size_t whole=length/64;for(size_t j=0;j<whole;j++)cuda_sm3_compress(s,input+64*j);
 uint8_t b[64]={0};unsigned tail=(unsigned)(length%64);for(unsigned j=0;j<tail;j++)b[j]=input[whole*64+j];b[tail]=0x80;
 if(tail>=56){cuda_sm3_compress(s,b);for(unsigned j=0;j<64;j++)b[j]=0;}
 uint64_t bits=(uint64_t)length*8;for(unsigned j=0;j<8;j++)b[63-j]=(uint8_t)(bits>>(8*j));cuda_sm3_compress(s,b);
 for(unsigned j=0;j<8;j++)cuda_put32(out+4*j,s[j]);
}
/* PRF/F/H have exactly one padded block after the cached PK.seed block. */
A15_DEVICE void cuda_thash(const uint32_t seed[8],const uint8_t adrs[32],const uint8_t *input,unsigned length,uint8_t out[16]){
 uint32_t s[8];for(unsigned j=0;j<8;j++)s[j]=seed[j];uint8_t b[64]={0};b[0]=adrs[3];
 for(unsigned j=0;j<8;j++)b[1+j]=adrs[8+j];for(unsigned j=0;j<13;j++)b[9+j]=adrs[19+j];
 for(unsigned j=0;j<length;j++)b[22+j]=input[j];b[22+length]=0x80;uint64_t bits=(64+22+length)*8;
 for(unsigned j=0;j<8;j++)b[63-j]=(uint8_t)(bits>>(8*j));cuda_sm3_compress(s,b);for(unsigned j=0;j<4;j++)cuda_put32(out+4*j,s[j]);
}
A15_DEVICE void cuda_fors_leaf(const a15_cuda_job &job,uint32_t relative,uint8_t out[16]){
 uint8_t address[32];for(unsigned j=0;j<32;j++)address[j]=job.adrs[j];uint32_t index=job.start+relative;
 cuda_put32(address+16,6);cuda_put32(address+24,0);cuda_put32(address+28,index);cuda_thash(job.seed,address,job.skseed,16,out);
#ifdef SLH_TEST_BUILD
 if(SLH_TEST_FAULT_POINT==2&&job.fault_site==2&&job.fault_index==index)out[0]^=1;
#endif
 cuda_put32(address+16,3);cuda_thash(job.seed,address,out,16,out);
#ifdef SLH_TEST_BUILD
 if(SLH_TEST_FAULT_POINT==5&&job.fault_site==5&&job.fault_index==index)out[0]^=1;
#endif
}
A15_DEVICE void cuda_fors_parent(const a15_cuda_job &job,unsigned height,uint32_t relative,const uint8_t *nodes,uint8_t out[16]){
 uint8_t address[32];for(unsigned j=0;j<32;j++)address[j]=job.adrs[j];cuda_put32(address+16,3);
 cuda_put32(address+24,height);cuda_put32(address+28,(job.start>>height)+relative);cuda_thash(job.seed,address,nodes+relative*32,32,out);
}
#endif
