CC ?= gcc
BASE = -std=c11 -Wall -Wextra -Wno-misleading-indentation -fPIC -fopenmp -Iinclude -Isrc -I../third_party/slhdsa-c
CFLAGS ?= -O3
OUT ?= ../build
SOURCES = src/engine.c src/sm3.c src/sm3x8.c ../third_party/slhdsa-c/sha2_256.c ../third_party/slhdsa-c/sha2_512.c ../third_party/slhdsa-c/sha3_api.c ../third_party/slhdsa-c/sha3_f1600.c
HEADERS = include/slhdsa_sm3.h src/sm3.h src/sm3x8.h ../third_party/slhdsa-c/sha2_api.h ../third_party/slhdsa-c/sha3_api.h ../third_party/slhdsa-c/plat_local.h
FAULT_POINTS = 0 1 2 3 4 5
SAN_OUT ?= $(OUT)/sanitizer
ifeq ($(COUNTERS),1)
BASE += -DSLH_COUNTERS
endif
ifeq ($(AVX2),0)
BASE += -DSLH_DISABLE_AVX2
endif
.PHONY: all test review-test avx2-test prehash-test sanitizer fault-test guard-test clean
all: $(OUT)/libslhdsa_sm3.so
$(OUT)/libslhdsa_sm3.so: $(SOURCES) $(HEADERS)
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) -DSLH_RELEASE_BUILD -shared $(SOURCES) -o $@
$(OUT)/test_native: $(SOURCES) $(HEADERS) tests/test_native.c
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_native.c -o $@
test: $(OUT)/test_native
	A15_TEST_CACHE=$(OUT)/test.cache $(OUT)/test_native
$(OUT)/test_review: $(SOURCES) $(HEADERS) tests/test_review.c
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_review.c -o $@
review-test: $(OUT)/test_review
	$(OUT)/test_review $(OUT)
$(OUT)/test_avx2: $(SOURCES) $(HEADERS) tests/test_avx2.c
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_avx2.c -o $@
avx2-test: $(OUT)/test_avx2
	$(OUT)/test_avx2
$(OUT)/test_prehash: $(SOURCES) $(HEADERS) tests/test_prehash.c
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) $(SOURCES) tests/test_prehash.c -o $@
prehash-test: $(OUT)/test_prehash
	$(OUT)/test_prehash
$(OUT)/test_fault_%: $(SOURCES) $(HEADERS) tests/test_fault.c
	mkdir -p $(OUT)
	$(CC) $(BASE) $(CFLAGS) -DSLH_TEST_BUILD -DSLH_TEST_FAULT_POINT=$* $(SOURCES) tests/test_fault.c -o $@
fault-test: $(addprefix $(OUT)/test_fault_,$(FAULT_POINTS))
	@set -e; for point in $(FAULT_POINTS); do $(OUT)/test_fault_$$point; done
guard-test: $(OUT)/libslhdsa_sm3.so
	python3 ../tools/check_native_guards.py --cc '$(CC)' --library $(OUT)/libslhdsa_sm3.so
sanitizer:
	$(MAKE) OUT=$(SAN_OUT) CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' test review-test avx2-test prehash-test fault-test
clean:
	rm -f $(OUT)/libslhdsa_sm3.so $(OUT)/test_native $(OUT)/test_review $(OUT)/test_avx2 $(OUT)/test_prehash $(addprefix $(OUT)/test_fault_,$(FAULT_POINTS))
