ARG LLVM_VERSION=22.04-llvm17.0.6

FROM ghcr.io/llvmparty/packages/ubuntu:${LLVM_VERSION} AS build
WORKDIR /tmp
COPY \
    CMakeLists.txt  \
    superbuild.cmake \
    xed.cmake \
    XEDConfig.cmake.in \
    ./

# Build dependencies
RUN \
mkdir /dependencies && \
cmake -B build "-DCMAKE_INSTALL_PREFIX=/dependencies" -DUSE_EXTERNAL_LLVM=ON && \
cmake --build build && \
rm -rf build

# Actual final image
FROM ghcr.io/llvmparty/packages/ubuntu:${LLVM_VERSION} AS cxx-common

COPY --from=build /dependencies /dependencies

# Install remill cross-compilation dependencies
COPY ubuntu-dependencies.sh ./
RUN \
./ubuntu-dependencies.sh && \
rm -rf /var/lib/apt/lists/* && \
rm ubuntu-dependencies.sh

ENV CMAKE_PREFIX_PATH="/dependencies" \
    LD_LIBRARY_PATH="/dependencies/lib" \
    PATH="/dependencies/bin:$PATH"
