# New-environment CPU correctness recipe; not a replica of historical CUDA bytes.
ARG BASE_IMAGE=python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed
FROM ${BASE_IMAGE}
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261003T000000Z/ bookworm main' > /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends gcc g++ make git libc6-dev binutils ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /work/pqc-a1-5
COPY base_tls/requirements.lock.txt /tmp/tls.lock
COPY reference/requirements.lock.txt /tmp/reference.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/tls.lock && \
    python -m pip install --no-cache-dir --require-hashes -r /tmp/reference.lock
COPY . .
RUN python tools/install_falcon_provider.py && \
    OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE make -C c OUT=../build/container-native CFLAGS=-O3 all test repair-test prehash-test guard-test cuda-cleanup-host-test
ENV PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE
CMD ["python", "-B", "ops/run_review_checks.py", "--fresh-native-build", "build/container-acceptance-native", "--output", "build/container-review"]
