CC ?= gcc
.DEFAULT_GOAL := all
BASE = -std=c11 -Wall -Wextra -Wno-misleading-indentation -fPIC -fopenmp -Iinclude -Isrc -I../third_party/slhdsa-c
CFLAGS ?= -O3
OUT ?= ../build
SOURCES = src/engine.c src/sm3.c src/sm3x8.c ../third_party/slhdsa-c/sha2_256.c ../third_party/slhdsa-c/sha2_512.c ../third_party/slhdsa-c/sha3_api.c ../third_party/slhdsa-c/sha3_f1600.c
HEADERS = include/slhdsa_sm3.h src/sm3.h src/sm3x8.h ../third_party/slhdsa-c/sha2_api.h ../third_party/slhdsa-c/sha3_api.h ../third_party/slhdsa-c/plat_local.h
CUDA ?= 0
NVCC ?= nvcc
CUDA_ARCH ?= compute_86
CUDA_LIBDIR ?= /usr/lib/x86_64-linux-gnu
HEADERS += src/sm3_cuda.h src/sm3_cuda_device.cuh
ifeq ($(CUDA),1)
CUDA_OBJECT = $(OUT)/sm3_cuda.o
CUDA_LIBS = -L$(CUDA_LIBDIR) -lcudart -lstdc++ -pthread
CUDA_BASE = -std=c++14 -O3 -gencode=arch=$(CUDA_ARCH),code=$(CUDA_ARCH) -Xcompiler=-fPIC,-fvisibility=hidden,-pthread -Iinclude -Isrc
else
SOURCES += src/sm3_cuda_stub.c
endif
FAULT_POINTS = 0 1 2 3 4 5
SAN_OUT ?= $(OUT)/sanitizer
ifeq ($(COUNTERS),1)
BASE += -DSLH_COUNTERS
endif
ifeq ($(AVX2),0)
BASE += -DSLH_DISABLE_AVX2
endif
.PHONY: all test review-test avx2-test wots-test prehash-test sanitizer fault-test guard-test clean cuda-test cuda-fault-test
$(OUT)/sm3_cuda.o: src/sm3_cuda.cu src/sm3_cuda.h src/sm3_cuda_device.cuh include/slhdsa_sm3.h
	mkdir -p $(OUT)
	$(NVCC) $(CUDA_BASE) -DSLH_RELEASE_BUILD -c $< -o $@
$(OUT)/sm3_cuda_fault_%.o: src/sm3_cuda.cu src/sm3_cuda.h src/sm3_cuda_device.cuh include/slhdsa_sm3.h
	mkdir -p $(OUT)
	$(NVCC) $(CUDA_BASE) -DSLH_TEST_BUILD -DSLH_TEST_FAULT_POINT=$* -c $< -o $@
all: $(OUT)/libslhdsa_sm3.so
$(OUT)/libslhdsa_sm3.so: $(SOURCES) $(HEADERS) $(CUDA_OBJECT)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) -DSLH_RELEASE_BUILD -shared $(SOURCES) $(CUDA_OBJECT) $(CUDA_LIBS) -o $@
$(OUT)/test_native: $(SOURCES) $(HEADERS) tests/test_native.c $(CUDA_OBJECT)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_native.c $(CUDA_OBJECT) $(CUDA_LIBS) -o $@
test: $(OUT)/test_native
	A15_TEST_CACHE=$(OUT)/test.cache $(OUT)/test_native
$(OUT)/test_review: $(SOURCES) $(HEADERS) tests/test_review.c $(CUDA_OBJECT)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_review.c $(CUDA_OBJECT) $(CUDA_LIBS) -o $@
review-test: $(OUT)/test_review
	$(OUT)/test_review $(OUT)
$(OUT)/test_avx2: $(SOURCES) $(HEADERS) tests/test_avx2.c $(CUDA_OBJECT)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_avx2.c $(CUDA_OBJECT) $(CUDA_LIBS) -o $@
avx2-test: $(OUT)/test_avx2
	A15_TEST_CACHE_DIR=$(OUT) $(OUT)/test_avx2
$(OUT)/test_wots: $(SOURCES) $(HEADERS) tests/test_wots.c $(CUDA_OBJECT)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(filter-out src/engine.c,$(SOURCES)) tests/test_wots.c $(CUDA_OBJECT) $(CUDA_LIBS) -o $@
wots-test: $(OUT)/test_wots
	$(OUT)/test_wots
$(OUT)/test_prehash: $(SOURCES) $(HEADERS) tests/test_prehash.c $(CUDA_OBJECT)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_prehash.c $(CUDA_OBJECT) $(CUDA_LIBS) -o $@
prehash-test: $(OUT)/test_prehash
	$(OUT)/test_prehash
$(OUT)/test_fault_%: $(SOURCES) $(HEADERS) tests/test_fault.c $(CUDA_OBJECT)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) -DSLH_TEST_BUILD -DSLH_TEST_FAULT_POINT=$* $(SOURCES) tests/test_fault.c $(CUDA_OBJECT) $(CUDA_LIBS) -o $@
$(OUT)/test_cuda: $(SOURCES) $(HEADERS) tests/test_cuda.c $(CUDA_OBJECT)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_cuda.c $(CUDA_OBJECT) $(CUDA_LIBS) -o $@
cuda-test: $(OUT)/test_cuda
	A15_TEST_CACHE_DIR=$(OUT) $(OUT)/test_cuda
ifeq ($(CUDA),1)
$(OUT)/test_cuda_fault_%: $(SOURCES) $(HEADERS) tests/test_fault.c $(OUT)/sm3_cuda_fault_%.o
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) -DSLH_TEST_BUILD -DSLH_TEST_FAULT_POINT=$* -DSLH_TEST_BACKEND=5 $(SOURCES) tests/test_fault.c $(OUT)/sm3_cuda_fault_$*.o $(CUDA_LIBS) -o $@
cuda-fault-test: $(addprefix $(OUT)/test_cuda_fault_,$(FAULT_POINTS))
	@set -e; for point in $(FAULT_POINTS); do $(OUT)/test_cuda_fault_$$point; done
else
cuda-fault-test:
	@echo 'CUDA=1 is required for GPU fault acceptance'; exit 1
endif
fault-test: $(addprefix $(OUT)/test_fault_,$(FAULT_POINTS))
	@set -e; for point in $(FAULT_POINTS); do $(OUT)/test_fault_$$point; done
guard-test: $(OUT)/libslhdsa_sm3.so
	python3 ../tools/check_native_guards.py --cc '$(CC)' --library $(OUT)/libslhdsa_sm3.so
sanitizer:
	$(MAKE) OUT=$(SAN_OUT) CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' test review-test avx2-test wots-test prehash-test fault-test
clean:
	rm -f $(OUT)/libslhdsa_sm3.so $(OUT)/test_native $(OUT)/test_review $(OUT)/test_avx2 $(OUT)/test_wots $(OUT)/test_prehash $(addprefix $(OUT)/test_fault_,$(FAULT_POINTS))
