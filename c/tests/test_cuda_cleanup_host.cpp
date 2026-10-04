/* Deterministic host driver faults, not evidence of real CUDA fault behavior. */
#include "cuda_cleanup.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#define CHECK(x) do{if(!(x)){std::fprintf(stderr,"CUDA cleanup policy FAIL line %d: %s\n",__LINE__,#x);std::exit(1);}}while(0)

struct fake_driver {
 static std::map<uint8_t *,size_t> memory;
 static std::string failure;
 static int remaining, allocates, wipes, syncs, frees, released;
 static std::vector<std::string> calls;
 static int backend_error(){return 97;}
 static int fault(const char *name,int rc){
  calls.push_back(name);
  if(failure==name&&remaining){if(remaining>0)--remaining;return rc;}
  return 0;
 }
 static int allocate(uint8_t **p,size_t n){
  ++allocates;int rc=fault("allocate",31);if(rc)return rc;
  *p=new uint8_t[n];std::memset(*p,0xa5,n);memory[*p]=n;return 0;
 }
 static int wipe(uint8_t *p,size_t n){++wipes;int rc=fault("wipe",41);if(!rc)std::memset(p,0,n);return rc;}
 static int synchronize(){++syncs;return fault("sync",42);}
 static int release(uint8_t *p){
  ++frees;int rc=fault("free",43);if(rc)return rc;
  CHECK(calls.size()>=3&&calls[calls.size()-2]=="sync"&&calls[calls.size()-3]=="wipe");
  for(size_t i=0;i<memory.at(p);++i)CHECK(p[i]==0);
  delete[] p;memory.erase(p);++released;return 0;
 }
 static void reset(const char *stage="",int failures=0){
  /* Test fixture teardown only, after assertions about retained allocations. */
  for(auto entry:memory)delete[] entry.first;
  memory.clear();failure=stage;remaining=failures;
  allocates=wipes=syncs=frees=released=0;calls.clear();
 }
};
std::map<uint8_t *,size_t> fake_driver::memory;
std::string fake_driver::failure;
int fake_driver::remaining=0,fake_driver::allocates=0,fake_driver::wipes=0,fake_driver::syncs=0,fake_driver::frees=0,fake_driver::released=0;
std::vector<std::string> fake_driver::calls;
using owner=a15_cuda_buffer_owner<fake_driver>;

static void blocked(bool &poisoned){
 int before=fake_driver::allocates;
 owner next(16,poisoned);CHECK(next.allocate()==fake_driver::backend_error());CHECK(!next.p);
 CHECK(fake_driver::allocates==before);
}
int main(){
 unsigned checks=0;
 fake_driver::reset();bool poison=false;
 {owner buffer(16,poison);CHECK(!buffer.allocate());CHECK(!buffer.clear_release());CHECK(!buffer.p);}
 CHECK(!poison&&fake_driver::released==1&&fake_driver::wipes==1);++checks;
 fake_driver::reset();poison=false;
 {owner buffer(16,poison);CHECK(!buffer.allocate());}
 CHECK(!poison&&fake_driver::released==1&&fake_driver::wipes==1);++checks;
 for(const char *stage:{"wipe","sync","free"})for(int failures:{1,-1}){
  fake_driver::reset(stage,failures);poison=false;
  {owner buffer(16,poison);CHECK(!buffer.allocate());CHECK(buffer.clear_release()!=0);CHECK(buffer.p);CHECK(poison);CHECK(!fake_driver::released);}
  CHECK(poison);
  if(failures==1)CHECK(fake_driver::released==1&&fake_driver::memory.empty());
  else{
   CHECK(!fake_driver::released&&fake_driver::memory.size()==1);
   if(std::string(stage)=="wipe"||std::string(stage)=="sync")CHECK(fake_driver::frees==0);
  }
  blocked(poison);++checks;
 }
 for(const char *stage:{"wipe","sync","free"})for(int failures:{1,-1}){
  fake_driver::reset(stage,failures);poison=false;
  {owner buffer(16,poison);CHECK(!buffer.allocate());}
  CHECK(poison&&!fake_driver::released&&fake_driver::memory.size()==1);
  if(std::string(stage)!="free")CHECK(!fake_driver::frees);
  blocked(poison);++checks;
 }
 fake_driver::reset("allocate",1);poison=false;
 {owner buffer(16,poison);CHECK(buffer.allocate()==31);CHECK(!buffer.p);}
 CHECK(!poison&&!fake_driver::wipes&&!fake_driver::frees);++checks;
 fake_driver::reset("wipe",1);poison=false;
 {owner first(16,poison),second(16,poison);CHECK(!first.allocate()&&!second.allocate());
  CHECK(first.clear_release()==41&&poison);CHECK(!second.clear_release());CHECK(!second.p);}
 CHECK(poison&&fake_driver::released==2&&fake_driver::memory.empty());blocked(poison);++checks;
 fake_driver::reset("sync",-1);poison=false;
 {owner buffer(16,poison);CHECK(!buffer.allocate());int primary=19;int cleanup=buffer.clear_release();if(!primary)primary=cleanup;CHECK(primary==19&&cleanup==42&&poison);}
 CHECK(!fake_driver::released&&fake_driver::memory.size()==1);++checks;
 fake_driver::reset();
 std::printf("CUDA cleanup host fake-driver: %u policy cases PASS; cryptographic_abi_calls=0; real_timing_samples=0; real GPU fault behavior untested\n",checks);
 return 0;
}
