# SPDX-License-Identifier: MIT
# Proposed host environment; not built during artifact preparation.
FROM python:3.11.11-slim-bookworm
ARG LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183
RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git init /tmp/liboqs \
    && git -C /tmp/liboqs remote add origin https://github.com/open-quantum-safe/liboqs.git \
    && git -C /tmp/liboqs fetch --depth 1 origin "${LIBOQS_COMMIT}" \
    && git -C /tmp/liboqs checkout --detach FETCH_HEAD \
    && test "$(git -C /tmp/liboqs rev-parse HEAD)" = "${LIBOQS_COMMIT}" \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -G Ninja \
       -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    && cmake --build /tmp/liboqs/build --parallel 2 \
    && cmake --install /tmp/liboqs/build \
    && rm -rf /tmp/liboqs
ENV OQS_INSTALL_PATH=/opt/liboqs
ENV LD_LIBRARY_PATH=/opt/liboqs/lib
WORKDIR /artifact
COPY . .
RUN python -m pip install --no-cache-dir '.[dev,pq]'
CMD ["python", "-m", "daahe", "--help"]

