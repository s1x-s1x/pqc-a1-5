#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wcast-qual"
#define __NV_CUBIN_HANDLE_STORAGE__ static
#if !defined(__CUDA_INCLUDE_COMPILER_INTERNAL_HEADERS__)
#define __CUDA_INCLUDE_COMPILER_INTERNAL_HEADERS__
#endif
#include "crt/host_runtime.h"
#include "sm3_cuda.fatbin.c"
extern void __device_stub__Z10sm3_kernelPKhmmmPh(const uint8_t *, size_t, size_t, size_t, uint8_t *);
extern void __device_stub__Z16fors_leaf_kernel12a15_cuda_jobjPh(struct a15_cuda_job&, uint32_t, uint8_t *);
extern void __device_stub__Z18fors_reduce_kernel12a15_cuda_jobjjPKhPh(struct a15_cuda_job&, unsigned, uint32_t, const uint8_t *, uint8_t *);
static void __nv_cudaEntityRegisterCallback(void **);
static void __sti____cudaRegisterAll(void) __attribute__((__constructor__));
void __device_stub__Z10sm3_kernelPKhmmmPh(const uint8_t *__par0, size_t __par1, size_t __par2, size_t __par3, uint8_t *__par4){__cudaLaunchPrologue(5);__cudaSetupArgSimple(__par0, 0UL);__cudaSetupArgSimple(__par1, 8UL);__cudaSetupArgSimple(__par2, 16UL);__cudaSetupArgSimple(__par3, 24UL);__cudaSetupArgSimple(__par4, 32UL);__cudaLaunch(((char *)((void ( *)(const uint8_t *, size_t, size_t, size_t, uint8_t *))sm3_kernel)));}
# 48 "src/sm3_cuda.cu"
void sm3_kernel( const uint8_t *__cuda_0,size_t __cuda_1,size_t __cuda_2,size_t __cuda_3,uint8_t *__cuda_4)
# 48 "src/sm3_cuda.cu"
{__device_stub__Z10sm3_kernelPKhmmmPh( __cuda_0,__cuda_1,__cuda_2,__cuda_3,__cuda_4); }
# 1 "../build/friend-cuda-native-20261004-r5/release/cuda-resources/sm3_cuda.cudafe1.stub.c"
void __device_stub__Z16fors_leaf_kernel12a15_cuda_jobjPh( struct a15_cuda_job&__par0,  uint32_t __par1,  uint8_t *__par2) {  __cudaLaunchPrologue(3); __cudaSetupArg(__par0, 0UL); __cudaSetupArgSimple(__par1, 80UL); __cudaSetupArgSimple(__par2, 88UL); __cudaLaunch(((char *)((void ( *)(struct a15_cuda_job, uint32_t, uint8_t *))fors_leaf_kernel))); }
# 49 "src/sm3_cuda.cu"
void fors_leaf_kernel( struct a15_cuda_job __cuda_0,uint32_t __cuda_1,uint8_t *__cuda_2)
# 49 "src/sm3_cuda.cu"
{__device_stub__Z16fors_leaf_kernel12a15_cuda_jobjPh( __cuda_0,__cuda_1,__cuda_2); }
# 1 "../build/friend-cuda-native-20261004-r5/release/cuda-resources/sm3_cuda.cudafe1.stub.c"
void __device_stub__Z18fors_reduce_kernel12a15_cuda_jobjjPKhPh( struct a15_cuda_job&__par0,  unsigned __par1,  uint32_t __par2,  const uint8_t *__par3,  uint8_t *__par4) {  __cudaLaunchPrologue(5); __cudaSetupArg(__par0, 0UL); __cudaSetupArgSimple(__par1, 80UL); __cudaSetupArgSimple(__par2, 84UL); __cudaSetupArgSimple(__par3, 88UL); __cudaSetupArgSimple(__par4, 96UL); __cudaLaunch(((char *)((void ( *)(struct a15_cuda_job, unsigned, uint32_t, const uint8_t *, uint8_t *))fors_reduce_kernel))); }
# 50 "src/sm3_cuda.cu"
void fors_reduce_kernel( struct a15_cuda_job __cuda_0,unsigned __cuda_1,uint32_t __cuda_2,const uint8_t *__cuda_3,uint8_t *__cuda_4)
# 50 "src/sm3_cuda.cu"
{__device_stub__Z18fors_reduce_kernel12a15_cuda_jobjjPKhPh( __cuda_0,__cuda_1,__cuda_2,__cuda_3,__cuda_4); }
# 1 "../build/friend-cuda-native-20261004-r5/release/cuda-resources/sm3_cuda.cudafe1.stub.c"
static void __nv_cudaEntityRegisterCallback( void **__T3) {  __nv_dummy_param_ref(__T3); __nv_save_fatbinhandle_for_managed_rt(__T3); __cudaRegisterEntry(__T3, ((void ( *)(struct a15_cuda_job, unsigned, uint32_t, const uint8_t *, uint8_t *))fors_reduce_kernel), _Z18fors_reduce_kernel12a15_cuda_jobjjPKhPh, (-1)); __cudaRegisterEntry(__T3, ((void ( *)(struct a15_cuda_job, uint32_t, uint8_t *))fors_leaf_kernel), _Z16fors_leaf_kernel12a15_cuda_jobjPh, (-1)); __cudaRegisterEntry(__T3, ((void ( *)(const uint8_t *, size_t, size_t, size_t, uint8_t *))sm3_kernel), _Z10sm3_kernelPKhmmmPh, (-1)); }
static void __sti____cudaRegisterAll(void) {  __cudaRegisterBinary(__nv_cudaEntityRegisterCallback);  }

#pragma GCC diagnostic pop
