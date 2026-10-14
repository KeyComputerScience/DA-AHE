# SPDX-License-Identifier: MIT
# Proposed host environment; not built during artifact preparation.
FROM python:3.11.11-slim-bookworm
ARG LIBOQS_TAG=0.16.0
RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${LIBOQS_TAG}" https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -G Ninja \
       -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    && cmake --build /tmp/liboqs/build --parallel 2 \
    && cmake --install /tmp/liboqs/build \
    && rm -rf /tmp/liboqs
ENV OQS_INSTALL_PATH=/opt/liboqs
ENV LD_LIBRARY_PATH=/opt/liboqs/lib
WORKDIR /artifact
COPY . .
RUN python -m pip install --no-cache-dir '.[dev,pq]'
CMD ["python", "-m", "daahe", "--help"]

