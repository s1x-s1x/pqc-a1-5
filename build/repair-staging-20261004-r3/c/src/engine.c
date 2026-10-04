/* Copyright (c) The slhdsa-c project authors and A1-5 contributors.
 * SPDX-License-Identifier: MIT
 * FIPS 205 algorithm skeleton adapted from slh-dsa/slhdsa-c,
 * commit 2b111e076a3bf0b6041651cf8746acf5ade56cc7 (MIT option).
 * Changes: native SM3, explicit parallel treehash, cache, and checked ABI. */
#include "slhdsa_sm3.h"
#include "sm3.h"
#include "sm3x8.h"
#include "sm3_cuda.h"
#include "secure_zero.h"
#include "sha2_api.h"
#include "sha3_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/random.h>
#include <omp.h>
#include <stdatomic.h>
#include <errno.h>
#include <sys/stat.h>

#define N 16
#define MAX_LEN 68
#define MAX_HEIGHT 24
#define NO_TARGET UINT32_MAX
#if (defined(A15_TEST_CANDIDATE_OBSERVER) || defined(A15_TEST_CACHE_PREALLOC) || defined(SLH_TEST_REVERSE_TASKS)) && !defined(SLH_TEST_BUILD)
#error Private repair hooks require a standalone SLH_TEST_BUILD
#endif
/* Faults are compiled only into standalone test executables. The two-macro
 * gate prevents accidentally enabling a fault by adding only a point flag to
 * a release build. No setter, environment switch, or ABI entry point exists. */
#if defined(SLH_TEST_FAULT_POINT) && !defined(SLH_TEST_BUILD)
#error SLH_TEST_FAULT_POINT requires SLH_TEST_BUILD
#endif
#if defined(SLH_RELEASE_BUILD) && defined(SLH_TEST_BUILD)
#error Release library must not include SLH_TEST_BUILD
#endif
#ifdef SLH_TEST_BUILD
#ifndef SLH_TEST_FAULT_POINT
#define SLH_TEST_FAULT_POINT 0
#endif
#if SLH_TEST_FAULT_POINT < 0 || SLH_TEST_FAULT_POINT > 5
#error Invalid SLH_TEST_FAULT_POINT
#endif
#define TEST_SITE(w,point,index) do { (w).test_site=(point);(w).test_index=(index); } while (0)
#define TEST_FAULT(w,point,index,output) do { if (SLH_TEST_FAULT_POINT==(point)&&(w)->test_site==(point)&&(w)->test_index==(index)) (output)[0]^=1; } while (0)
#else
#define TEST_SITE(w,point,index) ((void)0)
#define TEST_FAULT(w,point,index,output) ((void)0)
#endif
typedef struct { int pid, sm3; unsigned h,d,hp,a,k,lgw,len,m; } param;
static const param parameters[] = {
 {1,1,63,7,9,12,14,4,35,30}, {2,1,66,22,3,6,33,4,35,34},
 {3,1,22,1,22,24,6,2,68,21}, {101,0,63,7,9,12,14,4,35,30},
 {102,0,66,22,3,6,33,4,35,34}, {103,0,22,1,22,24,6,2,68,21},
 {201,1,10,1,10,10,6,2,68,10}
};
typedef union { a15_sm3 sm3; sha2_256_t sha2; } hash_state;
/* Borrow immutable seeds for the duration of a call. Thread/address copies
 * contain pointers and public state, never duplicate the raw secret seeds. */
typedef struct { const param *p; const uint8_t *skseed,*skprf;uint8_t pkseed[N],pkroot[N],adrs[32]; hash_state seed;int backend;
#ifdef SLH_TEST_BUILD
 unsigned test_site;uint32_t test_index;
#endif
} work;
struct slh_ctx {
 const param *p; unsigned flags, cache_t; int threads,bound,backend;
 uint8_t sk[4*N], cache_pk[2*N]; uint8_t *cache; size_t cache_bytes;
};
static _Atomic uint64_t counts[7];
enum { C_PRF,C_PRFMSG,C_HMSG,C_F,C_H,C_T,C_COMP };
#ifdef SLH_COUNTERS
#define COUNT(i,n) atomic_fetch_add_explicit(&counts[i],(n),memory_order_relaxed)
#else
#define COUNT(i,n) ((void)(i),(void)(n))
#endif
static const param *lookup(int pid) { for(size_t i=0;i<sizeof parameters/sizeof *parameters;i++) if(parameters[i].pid==pid) return parameters+i; return NULL; }
/* CUDA B1 accelerates FORS; the existing WOTS SIMD worker is the CPU portion
 * of this hybrid backend. Runtime dispatch remains explicit and inspectable. */
static int wots_simd(int backend) {return backend==SLH_BACKEND_AVX2||(backend==SLH_BACKEND_CUDA&&a15_sm3_avx2_available());}
static void put32(uint8_t *p,uint32_t x) { p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x; }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3]; }
static uint64_t getint(const uint8_t *p,unsigned n) { uint64_t x=0; for(unsigned i=0;i<n;i++) x=(x<<8)|p[i]; return x; }
static void set_type(work *w,unsigned t) { put32(w->adrs+16,t); memset(w->adrs+20,0,12); }
static void set_type_kp(work *w,unsigned t) { put32(w->adrs+16,t); memset(w->adrs+24,0,8); }
static void set_tree(work *w,uint64_t t) { put32(w->adrs+8,t>>32);put32(w->adrs+12,t); }
static void hi(const param *p,hash_state *s) { if(p->sm3) a15_sm3_init(&s->sm3);else sha2_256_init(&s->sha2); }
static void hu(const param *p,hash_state *s,const void *b,size_t n) {
 size_t before=p->sm3?s->sm3.bytes:s->sha2.len;
 if(p->sm3)a15_sm3_update(&s->sm3,b,n);else sha2_256_update(&s->sha2,b,n);
 COUNT(C_COMP,((before+n)/64)-(before/64));
}
static void hf(const param *p,hash_state *s,uint8_t out[32]) {
 if(p->sm3) { COUNT(C_COMP,s->sm3.used<56?1:2); a15_sm3_final(&s->sm3,out); }
 else { COUNT(C_COMP,s->sha2.i<56?1:2); sha2_256_final_len(&s->sha2,out,32); }
}
static void init_work(work *w,const param *p,const uint8_t *sk,const uint8_t *pk) {
 static const uint8_t zero[48]={0}; memset(w,0,sizeof *w);w->p=p;w->backend=SLH_BACKEND_REF;
 if(sk) {w->skseed=sk;w->skprf=sk+N;pk=sk+2*N;}
 memcpy(w->pkseed,pk,N);memcpy(w->pkroot,pk+N,N);
 hi(p,&w->seed);hu(p,&w->seed,w->pkseed,N);hu(p,&w->seed,zero,48);
}
static void thash(work *w,uint8_t out[N],const uint8_t *in,size_t n,int kind) {
 uint8_t ac[22], digest[32];hash_state s=w->seed;
 ac[0]=w->adrs[3];memcpy(ac+1,w->adrs+8,8);memcpy(ac+9,w->adrs+19,13);
 hu(w->p,&s,ac,22);hu(w->p,&s,in,n);hf(w->p,&s,digest);memcpy(out,digest,N);COUNT(kind,1);
 if(kind==C_PRF||kind==C_F){a15_secure_zero(&s,sizeof s);a15_secure_zero(digest,sizeof digest);}
}
static void hpair(work *w,uint8_t out[N],const uint8_t left[N],const uint8_t right[N]) {
 uint8_t b[2*N];memcpy(b,left,N);memcpy(b+N,right,N);thash(w,out,b,2*N,C_H);
}
static void prf(work *w,uint8_t out[N]) { thash(w,out,w->skseed,N,C_PRF); }
static void chain(work *w,uint8_t out[N],const uint8_t in[N],unsigned start,unsigned steps) {
 memcpy(out,in,N);for(unsigned j=0;j<steps;j++){put32(w->adrs+28,start+j);thash(w,out,out,N,C_F);if(!j)TEST_FAULT(w,3,get32(w->adrs+24),out);}
}
static void wots_secret(work *w,uint8_t out[N]) { put32(w->adrs+16,5);put32(w->adrs+28,0);prf(w,out);put32(w->adrs+16,0); }
static void fors_secret(work *w,uint8_t out[N]) { put32(w->adrs+16,6);put32(w->adrs+24,0);prf(w,out);TEST_FAULT(w,2,get32(w->adrs+28),out);put32(w->adrs+16,3); }
static void digits(uint32_t *out,const uint8_t *x,unsigned b,unsigned len) {
 unsigned bits=0,j=0;uint32_t acc=0,mask=(1u<<b)-1;for(unsigned i=0;i<len;i++) {while(bits<b){acc=(acc<<8)|x[j++];bits+=8;}bits-=b;out[i]=(acc>>bits)&mask;}
}
static void wots_digits(work *w,uint32_t *v,const uint8_t m[N]) {
 unsigned l1=8*N/w->p->lgw,l2=w->p->len-l1;uint32_t sum=0,max=(1u<<w->p->lgw)-1;uint8_t b[4]={0};
 digits(v,m,w->p->lgw,l1);for(unsigned j=0;j<l1;j++)sum+=max-v[j];sum<<=(8-(l2*w->p->lgw)%8)%8;
 unsigned bytes=(l2*w->p->lgw+7)/8;for(unsigned j=0;j<bytes;j++)b[bytes-1-j]=(uint8_t)(sum>>(8*j));digits(v+l1,b,w->p->lgw,l2);
}
static void wots_leaf(work *w,uint32_t idx,uint8_t node[N]) {
 uint8_t pk[MAX_LEN*N];set_type(w,0);put32(w->adrs+20,idx);unsigned max=(1u<<w->p->lgw)-1;
 for(unsigned j=0;j<w->p->len;j++){put32(w->adrs+24,j);wots_secret(w,pk+j*N);chain(w,pk+j*N,pk+j*N,0,max);}
 set_type_kp(w,1);thash(w,node,pk,w->p->len*N,C_T);TEST_FAULT(w,4,idx,node);
}
static void fors_leaf(work *w,uint32_t idx,uint8_t node[N]) {put32(w->adrs+28,idx);fors_secret(w,node);thash(w,node,node,N,C_F);TEST_FAULT(w,5,idx,node);}
/* PRF/F/H each have one final block after the cached PK.seed block. Counts are
 * logical scalar primitives and scalar compression blocks, never SIMD calls. */
static void thash8_mask(work lanes[8],uint8_t out[8][N],const uint8_t *in[8],size_t n,int kind,unsigned mask) {
 uint8_t blocks[8][64]={{0}};for(unsigned lane=0;lane<8;lane++){
  blocks[lane][0]=lanes[lane].adrs[3];memcpy(blocks[lane]+1,lanes[lane].adrs+8,8);memcpy(blocks[lane]+9,lanes[lane].adrs+19,13);memcpy(blocks[lane]+22,in[lane],n);blocks[lane][22+n]=0x80;
  uint64_t bits=(64+22+n)*8;for(unsigned j=0;j<8;j++)blocks[lane][63-j]=(uint8_t)(bits>>(8*j));
 }
 a15_sm3x8_final_blocks(lanes[0].seed.sm3.h,blocks,out);unsigned active=0;for(unsigned lane=0;lane<8;lane++)active+=(mask>>lane)&1u;COUNT(kind,active);COUNT(C_COMP,active);
 if(kind==C_PRF||kind==C_F)a15_secure_zero(blocks,sizeof blocks);
}
static void thash8(work lanes[8],uint8_t out[8][N],const uint8_t *in[8],size_t n,int kind) {thash8_mask(lanes,out,in,n,kind,0xffu);}
/* T_len is one scalar hash over the ordered chain endpoints. Absorbing each
 * x8 group removes the MAX_LEN*N temporary while preserving exact padding,
 * address bytes and scalar compression counts. */
static hash_state thash_stream_begin(work *w) {
 hash_state state=w->seed;uint8_t ac[22];ac[0]=w->adrs[3];memcpy(ac+1,w->adrs+8,8);memcpy(ac+9,w->adrs+19,13);hu(w->p,&state,ac,sizeof ac);return state;
}
static void thash_stream_end(work *w,hash_state *state,uint8_t out[N]) {uint8_t digest[32];hf(w->p,state,digest);memcpy(out,digest,N);COUNT(C_T,1);}
/* Variable chain lengths leave finished lanes unchanged. Inactive lanes are
 * physically evaluated by SIMD but never copied, faulted or logically counted.
 * All buffers remain defined for the hardware's full eight-lane load. */
static void wots_group8(work w,unsigned first,unsigned count,uint8_t out[8][N],const uint32_t *starts,const uint32_t *steps,const uint8_t *signature) {
 work lanes[8];const uint8_t *inputs[8];uint8_t next[8][N];const unsigned valid=(1u<<count)-1;
 for(unsigned lane=0;lane<8;lane++){
  lanes[lane]=w;put32(lanes[lane].adrs+24,first+(lane<count?lane:0));put32(lanes[lane].adrs+28,0);inputs[lane]=lanes[lane].skseed;
  if(signature)memcpy(out[lane],signature+(first+(lane<count?lane:0))*N,N);
  else put32(lanes[lane].adrs+16,5);
 }
 if(!signature)thash8_mask(lanes,out,inputs,N,C_PRF,valid);
 for(unsigned lane=0;lane<8;lane++){put32(lanes[lane].adrs+16,0);inputs[lane]=out[lane];}
 unsigned maximum=0;for(unsigned lane=0;lane<count;lane++)if(steps[lane]>maximum)maximum=steps[lane];
 for(unsigned step=0;step<maximum;step++){
  unsigned mask=0;for(unsigned lane=0;lane<count;lane++)if(step<steps[lane]){mask|=1u<<lane;put32(lanes[lane].adrs+28,starts[lane]+step);}
  thash8_mask(lanes,next,inputs,N,C_F,mask);
   for(unsigned lane=0;lane<count;lane++)if((mask>>lane)&1u){memcpy(out[lane],next[lane],N);if(!step)TEST_FAULT(&lanes[lane],3,first+lane,out[lane]);}
  }
 a15_secure_zero(next,sizeof next);
}
static void wots_leaf8(work *w,uint32_t idx,uint8_t node[N]) {
 set_type(w,0);put32(w->adrs+20,idx);work address=*w;set_type_kp(&address,1);hash_state stream=thash_stream_begin(&address);
 uint32_t starts[8]={0},steps[8];for(unsigned lane=0;lane<8;lane++)steps[lane]=(1u<<w->p->lgw)-1;
 for(unsigned first=0;first<w->p->len;first+=8){unsigned count=w->p->len-first;if(count>8)count=8;uint8_t endpoints[8][N];wots_group8(*w,first,count,endpoints,starts,steps,NULL);hu(w->p,&stream,endpoints,count*N);a15_secure_zero(endpoints,sizeof endpoints);}
 thash_stream_end(&address,&stream,node);TEST_FAULT(w,4,idx,node);
}
static void wots_sign8(work w,uint8_t *sig,const uint32_t *digits) {
 const uint32_t starts[8]={0};for(unsigned first=0;first<w.p->len;first+=8){unsigned count=w.p->len-first;if(count>8)count=8;uint8_t endpoints[8][N];wots_group8(w,first,count,endpoints,starts,digits+first,NULL);memcpy(sig+first*N,endpoints,count*N);a15_secure_zero(endpoints,sizeof endpoints);}
}
static void wots_from_sig8(work w,uint8_t node[N],const uint8_t *sig,const uint32_t *digits) {
 work address=w;set_type_kp(&address,1);hash_state stream=thash_stream_begin(&address);
 for(unsigned first=0;first<w.p->len;first+=8){unsigned count=w.p->len-first;if(count>8)count=8;uint32_t steps[8]={0};uint8_t endpoints[8][N];for(unsigned lane=0;lane<count;lane++)steps[lane]=((1u<<w.p->lgw)-1)-digits[first+lane];wots_group8(w,first,count,endpoints,digits+first,steps,sig);hu(w.p,&stream,endpoints,count*N);}
 thash_stream_end(&address,&stream,node);
}
/* Eight independent aligned lane subtrees retain O(8*height) stack memory.
 * Their absolute addresses match scalar treehash; only the final three levels
 * use scalar H. Target authentication nodes are captured before reduction. */
static void fors_tree8(work w,uint32_t start,unsigned z,uint32_t target,uint8_t root[N],uint8_t *auth) {
 const unsigned sub=z-3;const uint32_t leaves=1u<<sub;work lanes[8];uint8_t stack[MAX_HEIGHT+1][8][N],nodes[8][N];unsigned sp=0,levels[MAX_HEIGHT+1];const uint8_t *inputs[8];
 for(unsigned lane=0;lane<8;lane++)lanes[lane]=w;
 for(uint32_t step=0;step<leaves;step++){
  uint32_t indices[8];unsigned height=0;
  for(unsigned lane=0;lane<8;lane++){indices[lane]=start+lane*leaves+step;put32(lanes[lane].adrs+16,6);put32(lanes[lane].adrs+24,0);put32(lanes[lane].adrs+28,indices[lane]);inputs[lane]=lanes[lane].skseed;}
  thash8(lanes,nodes,inputs,N,C_PRF);
  for(unsigned lane=0;lane<8;lane++){TEST_FAULT(&lanes[lane],2,indices[lane],nodes[lane]);put32(lanes[lane].adrs+16,3);inputs[lane]=nodes[lane];}
  thash8(lanes,nodes,inputs,N,C_F);
  for(unsigned lane=0;lane<8;lane++){TEST_FAULT(&lanes[lane],5,indices[lane],nodes[lane]);if(auth&&target!=NO_TARGET&&sub&&indices[lane]==(target^1u))memcpy(auth,nodes[lane],N);}
  while(sp&&levels[sp-1]==height){
   uint8_t pairs[8][2*N];--sp;for(unsigned lane=0;lane<8;lane++){memcpy(pairs[lane],stack[sp][lane],N);memcpy(pairs[lane]+N,nodes[lane],N);inputs[lane]=pairs[lane];put32(lanes[lane].adrs+24,height+1);put32(lanes[lane].adrs+28,indices[lane]>>1);}
   thash8(lanes,nodes,inputs,2*N,C_H);height++;
   for(unsigned lane=0;lane<8;lane++){indices[lane]>>=1;if(auth&&target!=NO_TARGET&&height<sub&&indices[lane]==((target>>height)^1u))memcpy(auth+height*N,nodes[lane],N);}
  }
  memcpy(stack[sp],nodes,sizeof nodes);levels[sp++]=height;
 }
 memcpy(nodes,stack[0],sizeof nodes);put32(w.adrs+16,3);
 for(unsigned height=sub;height<z;height++){
  const unsigned count=1u<<(z-height);const uint32_t first=start>>height;
  if(auth&&target!=NO_TARGET)memcpy(auth+height*N,nodes[((target>>height)^1u)-first],N);
  for(unsigned j=0;j<count;j+=2){put32(w.adrs+24,height+1);put32(w.adrs+28,(first+j)>>1);hpair(&w,nodes[j/2],nodes[j],nodes[j+1]);}
 }
 memcpy(root,nodes[0],N);
}
static size_t node_offset(unsigned hp,unsigned t,unsigned height,uint32_t index) {
 size_t offset=0;for(unsigned j=t;j<height;j++)offset+=((size_t)1<<(hp-j));return (offset+index)*N;
}
static void record_node(const slh_ctx *ctx,uint8_t *cache,unsigned height,uint32_t idx,const uint8_t *node) {
 if(cache&&height>=ctx->cache_t)memcpy(cache+node_offset(ctx->p->hp,ctx->cache_t,height,idx),node,N);
}
/* An aligned treehash uses only O(height) stack space. Independent chunks are
 * combined at their absolute address heights, preserving the scalar result. */
static void serial_tree(work w,slh_leaf_type type,uint32_t start,unsigned z,uint32_t target,uint8_t root[N],uint8_t *auth,const slh_ctx *ctx,uint8_t *cache) {
 if(type==SLH_LEAF_FORS&&ctx->backend==SLH_BACKEND_AVX2&&z>=3){fors_tree8(w,start,z,target,root,auth);return;}
 uint8_t stack[MAX_HEIGHT+1][N];unsigned levels[MAX_HEIGHT+1],sp=0;uint32_t end=start+(1u<<z);
 for(uint32_t i=start;i<end;i++) {
  uint8_t node[N];unsigned h=0;uint32_t idx=i;
  if(type==SLH_LEAF_WOTS){if(wots_simd(ctx->backend))wots_leaf8(&w,i,node);else wots_leaf(&w,i,node);}else fors_leaf(&w,i,node);
  if(type==SLH_LEAF_WOTS)record_node(ctx,cache,0,i,node);
  if(auth&&target!=NO_TARGET&&z>0&&idx==(target^1u))memcpy(auth,node,N);
  while(sp&&levels[sp-1]==h){
   if(type==SLH_LEAF_WOTS)set_type(&w,2);else put32(w.adrs+16,3);
   put32(w.adrs+24,h+1);put32(w.adrs+28,idx>>1);hpair(&w,node,stack[--sp],node);idx>>=1;h++;
   if(type==SLH_LEAF_WOTS)record_node(ctx,cache,h,idx,node);
   if(auth&&target!=NO_TARGET&&h<z&&idx==((target>>h)^1u))memcpy(auth+h*N,node,N);
  }
  memcpy(stack[sp],node,N);levels[sp++]=h;
 }
 memcpy(root,stack[0],N);
}
static int treehash(const slh_ctx *ctx,work w,slh_leaf_type type,uint32_t start,unsigned z,uint32_t target,uint8_t root[N],uint8_t *auth,uint8_t *cache) {
 if(ctx->backend==SLH_BACKEND_CUDA&&type==SLH_LEAF_FORS){
  unsigned site=0;uint32_t index=0;
  #ifdef SLH_TEST_BUILD
  site=w.test_site;index=w.test_index;
  #endif
  int rc=a15_cuda_fors_tree(w.seed.sm3.h,w.skseed,w.adrs,start,z,target,root,auth,site,index);if(rc)return rc;
  uint64_t leaves=UINT64_C(1)<<z;COUNT(C_PRF,leaves);COUNT(C_F,leaves);COUNT(C_H,leaves-1);COUNT(C_COMP,3*leaves-1);return 0;
 }
 unsigned split=0;while(split<z&&split<10&&(1u<<split)<(unsigned)ctx->threads*4u)split++;
 if(ctx->threads<=1||z<5)split=0;
 if(type==SLH_LEAF_FORS&&ctx->backend==SLH_BACKEND_AVX2&&z>=3&&split>z-3)split=z-3;
 if(!split){serial_tree(w,type,start,z,target,root,auth,ctx,cache);return 0;}
 unsigned chunks=1u<<split,sub=z-split;uint8_t *nodes=malloc(chunks*N);if(!nodes)return SLH_ERR_ALLOC;
 #pragma omp parallel for num_threads(ctx->threads) schedule(static)
 for(unsigned i=0;i<chunks;i++) {
  unsigned task=i;
  #ifdef SLH_TEST_REVERSE_TASKS
  task=chunks-1-i;
  #endif
  uint32_t base=start+(task<<sub),chosen=(target!=NO_TARGET&&target>=base&&target<base+(1u<<sub))?target:NO_TARGET;
  serial_tree(w,type,base,sub,chosen,nodes+task*N,chosen==NO_TARGET?NULL:auth,ctx,cache);
 }
 for(unsigned h=sub;h<z;h++) {
  unsigned count=1u<<(z-h);uint32_t first=start>>h;
  if(auth&&target!=NO_TARGET)memcpy(auth+h*N,nodes+(((target>>h)^1u)-first)*N,N);
  for(unsigned j=0;j<count;j+=2){
   if(type==SLH_LEAF_WOTS)set_type(&w,2);else put32(w.adrs+16,3);
   put32(w.adrs+24,h+1);put32(w.adrs+28,(first+j)>>1);hpair(&w,nodes+(j/2)*N,nodes+j*N,nodes+(j+1)*N);
   if(type==SLH_LEAF_WOTS)record_node(ctx,cache,h+1,(first+j)>>1,nodes+(j/2)*N);
  }
 }
 memcpy(root,nodes,N);free(nodes);return 0;
}
static int xmss_sign(const slh_ctx *ctx,work w,uint8_t *sig,const uint8_t m[N],uint32_t idx) {
 uint8_t root[N];unsigned hp=w.p->hp;uint8_t *auth=sig+w.p->len*N;int cache_ok=ctx->cache&&memcmp(ctx->cache_pk,w.pkseed,N)==0&&memcmp(ctx->cache_pk+N,w.pkroot,N)==0&&get32(w.adrs)==w.p->d-1&&getint(w.adrs+4,12)==0;
 for(unsigned j=0;j<hp;j++) {
  uint32_t sibling=(idx>>j)^1u;
  if(cache_ok&&j>=ctx->cache_t)memcpy(auth+j*N,ctx->cache+node_offset(hp,ctx->cache_t,j,sibling),N);
  else {work auth_work=w;if(!j&&get32(w.adrs)==w.p->d-1)TEST_SITE(auth_work,4,sibling);int r=treehash(ctx,auth_work,SLH_LEAF_WOTS,sibling<<j,j,NO_TARGET,root,NULL,NULL);if(r)return r;memcpy(auth+j*N,root,N);}
 }
 uint32_t v[MAX_LEN];wots_digits(&w,v,m);set_type_kp(&w,0);put32(w.adrs+20,idx);
 #ifdef SLH_TEST_BUILD
 /* A zero-step chain performs no F computation. Select the first nonempty
  * chain, at the top layer where a fault cannot be absorbed by later signing. */
 if(get32(w.adrs)==w.p->d-1){unsigned first=0;while(first<w.p->len&&!v[first])first++;TEST_SITE(w,3,first);}
 #endif
 if(wots_simd(ctx->backend))wots_sign8(w,sig,v);
 else for(unsigned j=0;j<w.p->len;j++){put32(w.adrs+24,j);wots_secret(&w,sig+j*N);chain(&w,sig+j*N,sig+j*N,0,v[j]);}
 return 0;
}
static void xmss_from_sig(work w,uint8_t root[N],const uint8_t *sig,const uint8_t m[N],uint32_t idx) {
 uint32_t v[MAX_LEN];wots_digits(&w,v,m);set_type_kp(&w,0);put32(w.adrs+20,idx);unsigned max=(1u<<w.p->lgw)-1;
 if(wots_simd(w.backend))wots_from_sig8(w,root,sig,v);
 else {uint8_t pk[MAX_LEN*N];for(unsigned j=0;j<w.p->len;j++){put32(w.adrs+24,j);chain(&w,pk+j*N,sig+j*N,v[j],max-v[j]);}set_type_kp(&w,1);thash(&w,root,pk,w.p->len*N,C_T);}
 set_type(&w,2);const uint8_t *auth=sig+w.p->len*N;
 for(unsigned j=0;j<w.p->hp;j++){put32(w.adrs+24,j+1);put32(w.adrs+28,idx>>(j+1));if((idx>>j)&1)hpair(&w,root,auth+j*N,root);else hpair(&w,root,root,auth+j*N);}
}
static void prf_msg(work *w,uint8_t out[N],const uint8_t rnd[N],const uint8_t *m,size_t mlen) {
 uint8_t pad[64],digest[32];hash_state s;memset(pad,0x36,64);for(unsigned i=0;i<N;i++)pad[i]^=w->skprf[i];
 hi(w->p,&s);hu(w->p,&s,pad,64);hu(w->p,&s,rnd,N);hu(w->p,&s,m,mlen);hf(w->p,&s,digest);
 memset(pad,0x5c,64);for(unsigned i=0;i<N;i++)pad[i]^=w->skprf[i];hi(w->p,&s);hu(w->p,&s,pad,64);hu(w->p,&s,digest,32);hf(w->p,&s,digest);memcpy(out,digest,N);COUNT(C_PRFMSG,1);
 a15_secure_zero(pad,sizeof pad);a15_secure_zero(digest,sizeof digest);a15_secure_zero(&s,sizeof s);
}
static void h_msg(work *w,uint8_t *out,const uint8_t r[N],const uint8_t *m,size_t mlen) {
 uint8_t digest[32],seed[2*N+32+4];hash_state s;hi(w->p,&s);hu(w->p,&s,r,N);hu(w->p,&s,w->pkseed,N);hu(w->p,&s,w->pkroot,N);hu(w->p,&s,m,mlen);hf(w->p,&s,digest);
 memcpy(seed,r,N);memcpy(seed+N,w->pkseed,N);memcpy(seed+2*N,digest,32);
 for(unsigned i=0,off=0;off<w->p->m;i++,off+=32){put32(seed+2*N+32,i);hi(w->p,&s);hu(w->p,&s,seed,sizeof seed);hf(w->p,&s,digest);TEST_FAULT(w,1,i,digest);unsigned len=w->p->m-off;if(len>32)len=32;memcpy(out+off,digest,len);}
 COUNT(C_HMSG,1);
}
static void split_digest(const param *p,const uint8_t *digest,uint32_t *v,uint64_t *tree,uint32_t *leaf) {
 digits(v,digest,p->a,p->k);unsigned md=(p->k*p->a+7)/8,treebits=p->h-p->hp,tb=(treebits+7)/8;
 *tree=getint(digest+md,tb);if(treebits<64)*tree&=treebits?((UINT64_C(1)<<treebits)-1):0;
 *leaf=(uint32_t)getint(digest+md+tb,(p->hp+7)/8)&((1u<<p->hp)-1);
}
static int sign_fors_tree(const slh_ctx *ctx,work w,unsigned i,uint32_t choice,uint8_t *sig,uint8_t root[N]) {
 uint32_t idx=(i<<w.p->a)+choice;work secret=w;put32(secret.adrs+28,idx);if(!i)TEST_SITE(secret,2,idx);fors_secret(&secret,sig);
 if(!i)TEST_SITE(w,5,idx);
 return treehash(ctx,w,SLH_LEAF_FORS,i<<w.p->a,w.p->a,idx,root,sig+N,NULL);
}
static int sign_core(slh_ctx *ctx,uint8_t *sig,const uint8_t *m,size_t mlen,const uint8_t *sk,const uint8_t *rnd) {
 work w;init_work(&w,ctx->p,sk,NULL);w.backend=ctx->backend;uint8_t digest[49],roots[35*N],node[N];uint32_t v[35],leaf;uint64_t tree;
 prf_msg(&w,sig,rnd?rnd:w.pkseed,m,mlen);TEST_SITE(w,1,0);h_msg(&w,digest,sig,m,mlen);TEST_SITE(w,0,0);split_digest(w.p,digest,v,&tree,&leaf);
 set_tree(&w,tree);set_type_kp(&w,3);put32(w.adrs+20,leaf);uint8_t *fs=sig+N;int failure=0;
 if(w.p->a>=16||ctx->backend==SLH_BACKEND_CUDA) {
  /* Limited-use FORS trees are large enough to occupy the whole allocation. */
  for(unsigned i=0;i<w.p->k;i++){int rc=sign_fors_tree(ctx,w,i,v[i],fs+i*(w.p->a+1)*N,roots+i*N);if(rc)return rc;}
 } else {
  #pragma omp parallel for num_threads(ctx->threads) schedule(dynamic,1) reduction(min:failure)
  for(unsigned i=0;i<w.p->k;i++) {
    slh_ctx one={0};one.p=ctx->p;one.backend=ctx->backend;one.threads=1;one.cache_t=ctx->cache_t;int rc=sign_fors_tree(&one,w,i,v[i],fs+i*(w.p->a+1)*N,roots+i*N);if(rc<failure)failure=rc;
  }
 }
 if(failure)return failure;set_type_kp(&w,4);thash(&w,node,roots,w.p->k*N,C_T);
 uint8_t *ht=fs+w.p->k*(w.p->a+1)*N;memset(w.adrs,0,32);set_tree(&w,tree);
 for(unsigned layer=0;layer<w.p->d;layer++) {
  put32(w.adrs,layer);int rc=xmss_sign(ctx,w,ht,node,leaf);if(rc)return rc;
  if(layer+1<w.p->d){xmss_from_sig(w,node,ht,node,leaf);leaf=(uint32_t)tree&((1u<<w.p->hp)-1);tree>>=w.p->hp;set_tree(&w,tree);ht+=(w.p->len+w.p->hp)*N;}
 }
 return 0;
}
static int verify_core(slh_ctx *ctx,const uint8_t *sig,size_t siglen,const uint8_t *m,size_t mlen,const uint8_t *pk) {
 if(siglen!=slh_sig_bytes(ctx->p->pid))return SLH_ERR_VERIFY;work w;init_work(&w,ctx->p,NULL,pk);w.backend=ctx->backend;uint8_t digest[49],roots[35*N],node[N];uint32_t v[35],leaf;uint64_t tree;
 h_msg(&w,digest,sig,m,mlen);split_digest(w.p,digest,v,&tree,&leaf);set_tree(&w,tree);set_type_kp(&w,3);put32(w.adrs+20,leaf);
 const uint8_t *s=sig+N;for(unsigned i=0;i<w.p->k;i++){
  uint32_t idx=(i<<w.p->a)+v[i];put32(w.adrs+24,0);put32(w.adrs+28,idx);thash(&w,roots+i*N,s,N,C_F);s+=N;
  for(unsigned j=0;j<w.p->a;j++){put32(w.adrs+24,j+1);put32(w.adrs+28,idx>>(j+1));if((v[i]>>j)&1)hpair(&w,roots+i*N,s,roots+i*N);else hpair(&w,roots+i*N,roots+i*N,s);s+=N;}
 }
 set_type_kp(&w,4);thash(&w,node,roots,w.p->k*N,C_T);memset(w.adrs,0,32);set_tree(&w,tree);
 for(unsigned layer=0;layer<w.p->d;layer++){
  put32(w.adrs,layer);xmss_from_sig(w,node,s,node,leaf);s+=(w.p->len+w.p->hp)*N;leaf=(uint32_t)tree&((1u<<w.p->hp)-1);tree>>=w.p->hp;set_tree(&w,tree);
 }
 unsigned mismatch=0;for(unsigned i=0;i<N;i++)mismatch|=node[i]^w.pkroot[i];return mismatch?SLH_ERR_VERIFY:SLH_OK;
}
static void wipe(void *p,size_t n) { a15_secure_zero(p,n); }
static void clear_cache(slh_ctx *ctx) { if(ctx->cache){wipe(ctx->cache,ctx->cache_bytes);free(ctx->cache);}ctx->cache=NULL;ctx->cache_bytes=0;memset(ctx->cache_pk,0,2*N); }
uint32_t slh_abi_version(void){return SLH_ABI_VERSION;}
int slh_ctx_new(slh_ctx **out,int pid,unsigned flags) {
 if(!out)return SLH_ERR_PARAM;*out=NULL;const param *p=lookup(pid);if(!p||flags&~(0xffu|SLH_FLAG_VERIFY_AFTER_SIGN))return SLH_ERR_PARAM;
 unsigned requested=flags&0xffu;
 if((requested>SLH_BACKEND_AVX2&&requested!=SLH_BACKEND_CUDA)||(requested==SLH_BACKEND_AVX2&&(!p->sm3||!a15_sm3_avx2_available()))||(requested==SLH_BACKEND_CUDA&&(!p->sm3||!a15_cuda_available())))return SLH_ERR_BACKEND;
 slh_ctx *c=calloc(1,sizeof *c);if(!c)return SLH_ERR_ALLOC;c->p=p;c->flags=flags;c->threads=1;c->backend=requested==SLH_BACKEND_CUDA?SLH_BACKEND_CUDA:(requested!=SLH_BACKEND_REF&&p->sm3&&a15_sm3_avx2_available())?SLH_BACKEND_AVX2:SLH_BACKEND_REF;c->cache_t=p->hp<12?p->hp:12;*out=c;return 0;
}
int slh_backend_available(int backend) {return backend==SLH_BACKEND_AUTO||backend==SLH_BACKEND_REF?1:backend==SLH_BACKEND_AVX2?a15_sm3_avx2_available():backend==SLH_BACKEND_CUDA?a15_cuda_available():0;}
int slh_cuda_get_info(slh_cuda_info *out){return a15_cuda_info(out);}
int slh_cuda_stats_reset(int enabled){return a15_cuda_stats_reset(enabled);}
int slh_cuda_stats_get(slh_cuda_stats *out){return a15_cuda_stats_get(out);}
int slh_ctx_backend(const slh_ctx *ctx) {return ctx?ctx->backend:SLH_ERR_PARAM;}
int slh_ctx_set_threads(slh_ctx *ctx,int n) {if(!ctx||n<0||n>1024)return SLH_ERR_PARAM;if(!n){n=omp_get_num_procs();if(n>48)n=48;}ctx->threads=n;return 0;}
int slh_ctx_set_cache_level(slh_ctx *ctx,unsigned t) {if(!ctx||t>ctx->p->hp)return SLH_ERR_PARAM;clear_cache(ctx);ctx->cache_t=t;return 0;}
void slh_ctx_free(slh_ctx *ctx) {if(ctx){clear_cache(ctx);wipe(ctx,sizeof *ctx);free(ctx);}}
size_t slh_pk_bytes(int pid) {return lookup(pid)?2*N:0;}
size_t slh_sk_bytes(int pid) {return lookup(pid)?4*N:0;}
size_t slh_sig_bytes(int pid) {const param *p=lookup(pid);return p?(1+p->k*(1+p->a)+p->h+p->d*p->len)*N:0;}
int slh_ctx_bind_key(slh_ctx *ctx,const uint8_t *sk) {if(!ctx||!sk)return SLH_ERR_PARAM;memcpy(ctx->sk,sk,4*N);ctx->bound=1;return 0;}
static int subtree_inputs(const slh_ctx *ctx,slh_leaf_type type,const uint8_t base[32],uint32_t start,unsigned z,uint32_t target,uint8_t *root,uint8_t *auth) {
 if(!ctx||!ctx->bound||!base||!root||(type!=SLH_LEAF_WOTS&&type!=SLH_LEAF_FORS))return SLH_ERR_PARAM;
 unsigned max=type==SLH_LEAF_WOTS?ctx->p->hp:ctx->p->a;if(z>max||z>MAX_HEIGHT)return SLH_ERR_PARAM;uint64_t end=(uint64_t)start+(UINT64_C(1)<<z);
 if(start&((1u<<z)-1)||end>UINT64_C(0x100000000)||(target!=NO_TARGET&&((!auth&&z)||target<start||target>=end)))return SLH_ERR_PARAM;
 if(type==SLH_LEAF_WOTS&&end>(UINT64_C(1)<<ctx->p->hp))return SLH_ERR_PARAM;
 if(type==SLH_LEAF_FORS&&(end>(uint64_t)ctx->p->k*(1u<<ctx->p->a)||start/(1u<<ctx->p->a)!=(end-1)/(1u<<ctx->p->a)))return SLH_ERR_PARAM;
 return 0;
}
int slh_subtree(const slh_ctx *ctx,slh_leaf_type type,const uint8_t base[32],uint32_t start,unsigned z,uint32_t target,uint8_t *root,uint8_t *auth) {
 return slh_subtree_checked(ctx,type,base,start,z,target,root,N,auth,z<=MAX_HEIGHT?z*N:0);
}
int slh_subtree_checked(const slh_ctx *ctx,slh_leaf_type type,const uint8_t base[32],uint32_t start,unsigned z,uint32_t target,uint8_t *root,size_t root_capacity,uint8_t *auth,size_t auth_capacity) {
 int rc=subtree_inputs(ctx,type,base,start,z,target,root,auth);if(rc)return rc;size_t path=target==NO_TARGET?0:z*N;
 if(root_capacity<N||auth_capacity<path)return SLH_ERR_CAPACITY;
 uint8_t candidate_root[N],candidate_auth[MAX_HEIGHT*N];work w;init_work(&w,ctx->p,ctx->sk,NULL);memcpy(w.adrs,base,32);
 rc=treehash(ctx,w,type,start,z,target,candidate_root,path?candidate_auth:NULL,NULL);
 if(!rc){memcpy(root,candidate_root,N);if(path)memcpy(auth,candidate_auth,path);}else{wipe(root,N);if(path)wipe(auth,path);}return rc;
}
static int allocate_cache(slh_ctx *ctx,unsigned t) {
 clear_cache(ctx);ctx->cache_t=t;size_t bytes=(((size_t)1<<(ctx->p->hp-t+1))-1)*N;
 if(bytes>((size_t)1<<30))return SLH_ERR_ALLOC;ctx->cache=calloc(1,bytes);if(!ctx->cache)return SLH_ERR_ALLOC;ctx->cache_bytes=bytes;return 0;
}
int slh_keygen_internal(slh_ctx *ctx,uint8_t *pk,uint8_t *sk,const uint8_t *seed,const uint8_t *prfseed,const uint8_t *pkseed) {
 if(!ctx||!pk||!sk||!seed||!prfseed||!pkseed)return SLH_ERR_PARAM;uint8_t tmp[4*N];memcpy(tmp,seed,N);memcpy(tmp+N,prfseed,N);memcpy(tmp+2*N,pkseed,N);memset(tmp+3*N,0,N);
 int rc=allocate_cache(ctx,ctx->cache_t);if(rc){wipe(tmp,sizeof tmp);return rc;}work w;init_work(&w,ctx->p,tmp,NULL);put32(w.adrs,ctx->p->d-1);
 rc=treehash(ctx,w,SLH_LEAF_WOTS,0,ctx->p->hp,NO_TARGET,tmp+3*N,NULL,ctx->cache);if(rc){clear_cache(ctx);wipe(tmp,sizeof tmp);return rc;}
 memcpy(sk,tmp,sizeof tmp);memcpy(pk,tmp+2*N,2*N);memcpy(ctx->cache_pk,pk,2*N);slh_ctx_bind_key(ctx,sk);wipe(tmp,sizeof tmp);return 0;
}
int slh_keygen(slh_ctx *ctx,uint8_t *pk,uint8_t *sk) {
 if(!ctx||!pk||!sk)return SLH_ERR_PARAM;uint8_t seed[3*N];size_t used=0;while(used<sizeof seed){ssize_t r=getrandom(seed+used,sizeof seed-used,0);if(r<0&&errno==EINTR)continue;if(r<=0){wipe(seed,sizeof seed);return SLH_ERR_FAULT;}used+=(size_t)r;}
 int rc=slh_keygen_internal(ctx,pk,sk,seed,seed+N,seed+2*N);wipe(seed,sizeof seed);return rc;
}
int slh_cache_build(slh_ctx *ctx,const uint8_t *sk,unsigned t) {
 if(!ctx||!sk||t>ctx->p->hp)return SLH_ERR_PARAM;int rc=allocate_cache(ctx,t);if(rc)return rc;work w;init_work(&w,ctx->p,sk,NULL);put32(w.adrs,ctx->p->d-1);uint8_t root[N];
 rc=treehash(ctx,w,SLH_LEAF_WOTS,0,ctx->p->hp,NO_TARGET,root,NULL,ctx->cache);if(rc||memcmp(root,sk+3*N,N)){clear_cache(ctx);return rc?rc:SLH_ERR_CACHE;}memcpy(ctx->cache_pk,sk+2*N,2*N);return slh_ctx_bind_key(ctx,sk);
}
int slh_sign_internal(slh_ctx *ctx,uint8_t *sig,const uint8_t *m,size_t mlen,const uint8_t *sk,const uint8_t *rnd) {
 return slh_sign_internal_checked(ctx,sig,ctx?slh_sig_bytes(ctx->p->pid):0,m,mlen,sk,rnd);
}
int slh_sign_internal_checked(slh_ctx *ctx,uint8_t *sig,size_t capacity,const uint8_t *m,size_t mlen,const uint8_t *sk,const uint8_t *rnd) {
 if(!ctx||!sig||(!m&&mlen)||!sk)return SLH_ERR_PARAM;size_t bytes=slh_sig_bytes(ctx->p->pid);if(capacity<bytes)return SLH_ERR_CAPACITY;
 uint8_t *candidate=malloc(bytes);if(!candidate){wipe(sig,bytes);return SLH_ERR_ALLOC;}int rc=sign_core(ctx,candidate,m,mlen,sk,rnd);
 #ifdef A15_TEST_CANDIDATE_OBSERVER
 A15_TEST_CANDIDATE_OBSERVER(sig,candidate,bytes);
 #endif
 if(!rc&&(ctx->flags&SLH_FLAG_VERIFY_AFTER_SIGN)){
  slh_ctx verifier={0};verifier.p=ctx->p;verifier.backend=SLH_BACKEND_REF;
  if(verify_core(&verifier,candidate,bytes,m,mlen,sk+2*N))rc=SLH_ERR_FAULT;
 }
 if(!rc)memcpy(sig,candidate,bytes);else wipe(sig,bytes);wipe(candidate,bytes);free(candidate);return rc;
}
int slh_verify_internal(slh_ctx *ctx,const uint8_t *sig,size_t len,const uint8_t *m,size_t mlen,const uint8_t *pk) {if(!ctx||!sig||(!m&&mlen)||!pk)return SLH_ERR_PARAM;return verify_core(ctx,sig,len,m,mlen,pk);}
static int encode_message(uint8_t **out,const uint8_t *m,size_t len,const uint8_t *c,size_t clen) {
 if(clen>255)return SLH_ERR_CTXLEN;if((!m&&len)||(!c&&clen)||len>SIZE_MAX-clen-2)return SLH_ERR_PARAM;
 *out=malloc(len+clen+2);if(!*out)return SLH_ERR_ALLOC;(*out)[0]=0;(*out)[1]=(uint8_t)clen;if(clen)memcpy(*out+2,c,clen);if(len)memcpy(*out+2+clen,m,len);return 0;
}
int slh_sign(slh_ctx *ctx,uint8_t *sig,size_t *siglen,const uint8_t *m,size_t mlen,const uint8_t *c,size_t clen,const uint8_t *sk,const uint8_t *rnd) {
 return slh_sign_checked(ctx,sig,ctx?slh_sig_bytes(ctx->p->pid):0,siglen,m,mlen,c,clen,sk,rnd);
}
int slh_sign_checked(slh_ctx *ctx,uint8_t *sig,size_t capacity,size_t *siglen,const uint8_t *m,size_t mlen,const uint8_t *c,size_t clen,const uint8_t *sk,const uint8_t *rnd) {
 if(siglen)*siglen=0;if(!ctx||!sig||!siglen||!sk)return SLH_ERR_PARAM;if(capacity<slh_sig_bytes(ctx->p->pid))return SLH_ERR_CAPACITY;uint8_t *encoded=NULL;int rc=encode_message(&encoded,m,mlen,c,clen);if(rc)return rc;
 rc=slh_sign_internal_checked(ctx,sig,capacity,encoded,mlen+clen+2,sk,rnd);free(encoded);if(!rc)*siglen=slh_sig_bytes(ctx->p->pid);return rc;
}
int slh_verify(slh_ctx *ctx,const uint8_t *sig,size_t siglen,const uint8_t *m,size_t mlen,const uint8_t *c,size_t clen,const uint8_t *pk) {
 if(!ctx||!sig||!pk)return SLH_ERR_PARAM;if(siglen!=slh_sig_bytes(ctx->p->pid))return SLH_ERR_VERIFY;uint8_t *encoded=NULL;int rc=encode_message(&encoded,m,mlen,c,clen);if(rc)return rc;
 rc=slh_verify_internal(ctx,sig,siglen,encoded,mlen+clen+2,pk);free(encoded);return rc;
}
typedef struct {int id;unsigned bytes,oidlen;uint8_t oid[11];} prehash_parameter;
static const prehash_parameter prehash_parameters[]={
 {SLH_PREHASH_SHA256,32,11,{0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01}},
 {SLH_PREHASH_SHA512,64,11,{0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03}},
 {SLH_PREHASH_SHAKE128,32,11,{0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0b}},
 {SLH_PREHASH_SHAKE256,64,11,{0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0c}},
 {SLH_PREHASH_SM3,32,10,{0x06,0x08,0x2a,0x81,0x1c,0xcf,0x55,0x01,0x83,0x11}}
};
static const prehash_parameter *prehash_lookup(int id){for(size_t i=0;i<sizeof prehash_parameters/sizeof *prehash_parameters;i++)if(prehash_parameters[i].id==id)return prehash_parameters+i;return NULL;}
size_t slh_prehash_bytes(int id){const prehash_parameter *p=prehash_lookup(id);return p?p->bytes:0;}
static int message_prehash(int id,uint8_t digest[64],const uint8_t *msg,size_t mlen){
 if(!prehash_lookup(id)||(!msg&&mlen))return SLH_ERR_PARAM;static const uint8_t empty[1]={0};if(!msg)msg=empty;
 switch(id){
  case SLH_PREHASH_SHA256:sha2_256(digest,msg,mlen);break;
  case SLH_PREHASH_SHA512:sha2_512(digest,msg,mlen);break;
  case SLH_PREHASH_SHAKE128:shake128(digest,32,msg,mlen);break;
  case SLH_PREHASH_SHAKE256:shake256(digest,64,msg,mlen);break;
  case SLH_PREHASH_SM3:{a15_sm3 hash;a15_sm3_init(&hash);a15_sm3_update(&hash,msg,mlen);a15_sm3_final(&hash,digest);break;}
  default:return SLH_ERR_PARAM;
 }return 0;
}
static int encode_prehash_message(uint8_t **out,size_t *len,int id,const uint8_t *digest,size_t dlen,const uint8_t *c,size_t clen){
 if(clen>255)return SLH_ERR_CTXLEN;const prehash_parameter *p=prehash_lookup(id);if(!p||!digest||dlen!=p->bytes||(!c&&clen))return SLH_ERR_PARAM;
 *len=2+clen+p->oidlen+dlen;*out=malloc(*len);if(!*out)return SLH_ERR_ALLOC;(*out)[0]=1;(*out)[1]=(uint8_t)clen;if(clen)memcpy(*out+2,c,clen);memcpy(*out+2+clen,p->oid,p->oidlen);memcpy(*out+2+clen+p->oidlen,digest,dlen);return 0;
}
int slh_sign_digest(slh_ctx *ctx,uint8_t *sig,size_t *siglen,int id,const uint8_t *digest,size_t dlen,const uint8_t *c,size_t clen,const uint8_t *sk,const uint8_t *rnd){
 return slh_sign_digest_checked(ctx,sig,ctx?slh_sig_bytes(ctx->p->pid):0,siglen,id,digest,dlen,c,clen,sk,rnd);
}
int slh_sign_digest_checked(slh_ctx *ctx,uint8_t *sig,size_t capacity,size_t *siglen,int id,const uint8_t *digest,size_t dlen,const uint8_t *c,size_t clen,const uint8_t *sk,const uint8_t *rnd){
 if(siglen)*siglen=0;if(!ctx||!sig||!siglen||!sk)return SLH_ERR_PARAM;if(capacity<slh_sig_bytes(ctx->p->pid))return SLH_ERR_CAPACITY;uint8_t *encoded=NULL;size_t len=0;int rc=encode_prehash_message(&encoded,&len,id,digest,dlen,c,clen);if(rc)return rc;
 rc=slh_sign_internal_checked(ctx,sig,capacity,encoded,len,sk,rnd);free(encoded);if(!rc)*siglen=slh_sig_bytes(ctx->p->pid);return rc;
}
int slh_verify_digest(slh_ctx *ctx,const uint8_t *sig,size_t siglen,int id,const uint8_t *digest,size_t dlen,const uint8_t *c,size_t clen,const uint8_t *pk){
 if(!ctx||!sig||!pk)return SLH_ERR_PARAM;if(siglen!=slh_sig_bytes(ctx->p->pid))return SLH_ERR_VERIFY;uint8_t *encoded=NULL;size_t len=0;int rc=encode_prehash_message(&encoded,&len,id,digest,dlen,c,clen);if(rc)return rc;
 rc=slh_verify_internal(ctx,sig,siglen,encoded,len,pk);free(encoded);return rc;
}
int slh_sign_prehash(slh_ctx *ctx,uint8_t *sig,size_t *siglen,int id,const uint8_t *msg,size_t mlen,const uint8_t *c,size_t clen,const uint8_t *sk,const uint8_t *rnd){
 return slh_sign_prehash_checked(ctx,sig,ctx?slh_sig_bytes(ctx->p->pid):0,siglen,id,msg,mlen,c,clen,sk,rnd);
}
int slh_sign_prehash_checked(slh_ctx *ctx,uint8_t *sig,size_t capacity,size_t *siglen,int id,const uint8_t *msg,size_t mlen,const uint8_t *c,size_t clen,const uint8_t *sk,const uint8_t *rnd){
 if(siglen)*siglen=0;if(!ctx||!sig||!siglen||!sk)return SLH_ERR_PARAM;if(capacity<slh_sig_bytes(ctx->p->pid))return SLH_ERR_CAPACITY;if(clen>255)return SLH_ERR_CTXLEN;if(!c&&clen)return SLH_ERR_PARAM;uint8_t digest[64];int rc=message_prehash(id,digest,msg,mlen);if(rc){wipe(digest,sizeof digest);return rc;}
 rc=slh_sign_digest_checked(ctx,sig,capacity,siglen,id,digest,slh_prehash_bytes(id),c,clen,sk,rnd);wipe(digest,sizeof digest);return rc;
}
int slh_verify_prehash(slh_ctx *ctx,const uint8_t *sig,size_t siglen,int id,const uint8_t *msg,size_t mlen,const uint8_t *c,size_t clen,const uint8_t *pk){
 if(!ctx||!sig||!pk)return SLH_ERR_PARAM;if(siglen!=slh_sig_bytes(ctx->p->pid))return SLH_ERR_VERIFY;if(clen>255)return SLH_ERR_CTXLEN;if(!c&&clen)return SLH_ERR_PARAM;uint8_t digest[64];int rc=message_prehash(id,digest,msg,mlen);if(rc)return rc;
 rc=slh_verify_digest(ctx,sig,siglen,id,digest,slh_prehash_bytes(id),c,clen,pk);wipe(digest,sizeof digest);return rc;
}
/* Cache format v1: 96-byte fixed header, then only public nodes at height t.
 * SM3 digest detects corruption; upper layers are recomputed and root-bound.
 * Files contain no secret key seeds. */
static void cache_digest(const uint8_t *header,const uint8_t *data,size_t bytes,uint8_t out[32]) {a15_sm3 s;a15_sm3_init(&s);a15_sm3_update(&s,header,64);a15_sm3_update(&s,data,bytes);a15_sm3_final(&s,out);}
int slh_cache_save(const slh_ctx *ctx,const char *path) {
 if(!ctx||!path||!ctx->cache)return SLH_ERR_CACHE;size_t bytes=((size_t)1<<(ctx->p->hp-ctx->cache_t))*N;
 uint8_t h[96]={0};memcpy(h,"A15CACHE",8);put32(h+8,1);put32(h+12,ctx->p->pid);put32(h+16,ctx->cache_t);put32(h+20,ctx->p->hp);put32(h+24,N);put32(h+28,(uint32_t)bytes);memcpy(h+32,ctx->cache_pk,2*N);cache_digest(h,ctx->cache,bytes,h+64);
 FILE *f=fopen(path,"wb");if(!f)return SLH_ERR_CACHE;int ok=fwrite(h,1,sizeof h,f)==sizeof h&&fwrite(ctx->cache,1,bytes,f)==bytes;if(fclose(f))ok=0;return ok?0:SLH_ERR_CACHE;
}
int slh_cache_load(slh_ctx *ctx,const char *path,const uint8_t *pk) {
 if(!ctx||!path||!pk)return SLH_ERR_PARAM;FILE *f=fopen(path,"rb");if(!f)return SLH_ERR_CACHE;uint8_t h[96],digest[32];uint8_t *data=NULL;int rc=SLH_ERR_CACHE;
 if(fread(h,1,sizeof h,f)!=sizeof h)goto done;unsigned t=get32(h+16);size_t bytes=get32(h+28);
 if(memcmp(h,"A15CACHE",8)||get32(h+8)!=1||get32(h+12)!=(unsigned)ctx->p->pid||get32(h+20)!=ctx->p->hp||get32(h+24)!=N||t>ctx->p->hp||bytes!=((size_t)1<<(ctx->p->hp-t))*N||bytes>((size_t)1<<29)||memcmp(h+32,pk,2*N))goto done;
 /* Inspect this open descriptor before allocation; pathname checks race a
  * replacement. Exact read/EOF/digest/root checks remain after allocation. */
 struct stat st;if(fstat(fileno(f),&st)||!S_ISREG(st.st_mode)||st.st_size<0||(uint64_t)st.st_size!=(uint64_t)sizeof h+bytes)goto done;
 #ifdef A15_TEST_CACHE_PREALLOC
 A15_TEST_CACHE_PREALLOC(f);
 #endif
 size_t memory_bytes=(((size_t)1<<(ctx->p->hp-t+1))-1)*N;
 data=malloc(memory_bytes);if(!data){rc=SLH_ERR_ALLOC;goto done;}if(fread(data,1,bytes,f)!=bytes||fgetc(f)!=EOF)goto done;cache_digest(h,data,bytes,digest);if(memcmp(h+64,digest,32))goto done;
 work w;init_work(&w,ctx->p,NULL,pk);put32(w.adrs,ctx->p->d-1);set_type(&w,2);
 for(unsigned height=t+1;height<=ctx->p->hp;height++)for(uint32_t i=0;i<(1u<<(ctx->p->hp-height));i++){
  put32(w.adrs+24,height);put32(w.adrs+28,i);size_t off=node_offset(ctx->p->hp,t,height-1,2*i);hpair(&w,data+node_offset(ctx->p->hp,t,height,i),data+off,data+off+N);
 }
 if(memcmp(data+node_offset(ctx->p->hp,t,ctx->p->hp,0),pk+N,N))goto done;
 /* stdio may have prefetched bytes before a concurrent truncation. Recheck
  * descriptor metadata before committing even when fread/EOF saw old bytes. */
 struct stat final;if(fstat(fileno(f),&final)||final.st_size!=st.st_size||final.st_dev!=st.st_dev||final.st_ino!=st.st_ino||final.st_mtime!=st.st_mtime||final.st_ctime!=st.st_ctime)goto done;
 clear_cache(ctx);ctx->cache=data;data=NULL;ctx->cache_bytes=memory_bytes;ctx->cache_t=t;memcpy(ctx->cache_pk,pk,2*N);rc=0;
done: free(data);fclose(f);return rc;
}
void slh_counters_reset(void) {for(unsigned i=0;i<7;i++)atomic_store_explicit(&counts[i],0,memory_order_relaxed);}
void slh_counters_get(slh_counters *out) {if(!out)return;uint64_t v[7];for(unsigned i=0;i<7;i++)v[i]=atomic_load_explicit(&counts[i],memory_order_relaxed);memcpy(out,v,sizeof v);}
