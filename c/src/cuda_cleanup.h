/* CUDA allocation ownership policy, also exercised by a host fake driver.
 * Driver methods return zero on success and an ABI error otherwise. All
 * production users hold cuda_mutex; poisoning lasts for this process/library.
 */
#ifndef A15_CUDA_CLEANUP_H
#define A15_CUDA_CLEANUP_H
#include <cstddef>
#include <cstdint>

template <typename Driver> struct a15_cuda_buffer_owner {
 uint8_t *p;
 size_t bytes;
 bool &poisoned;
 explicit a15_cuda_buffer_owner(size_t n, bool &failed):p(nullptr),bytes(n),poisoned(failed){}
 a15_cuda_buffer_owner(const a15_cuda_buffer_owner &)=delete;
 a15_cuda_buffer_owner &operator=(const a15_cuda_buffer_owner &)=delete;
 int allocate(){
  if(poisoned)return Driver::backend_error();
  return bytes?Driver::allocate(&p,bytes):0;
 }
 int clear_release(){
  if(!p)return 0;
  int rc=Driver::wipe(p,bytes);
  if(!rc)rc=Driver::synchronize();
  /* Never return a buffer to the allocator without confirmed wipe completion.
   * Retain an allocation on any error and make future GPU work fail closed.
   * Other existing owners still attempt their cleanup after poisoning.
   */
  if(!rc)rc=Driver::release(p);
  if(rc)poisoned=true;
  else p=nullptr;
  return rc;
 }
 ~a15_cuda_buffer_owner(){
  /* One checked retry after an explicit cleanup failure. A persistent error
   * retains the allocation until CUDA context/process teardown; no reset and
   * no unchecked cudaFree. This does not certify driver/hardware erasure.
   */
  if(p)(void)clear_release();
 }
};
#endif
