#!/bin/bash

# Exit when any command fails (https://petereisentraut.blogspot.com/2010/11/pipefail.html)
set -e 
set -o pipefail

build_docker_images() {
  local LLVM_VERSION="22.04-llvm$1"
  local DOCKER_TAG=ghcr.io/llvmparty/remill/cxx-common:$LLVM_VERSION
  
  docker buildx build --build-arg "LLVM_VERSION=$LLVM_VERSION" --platform linux/amd64 --tag $DOCKER_TAG .
  docker buildx build --build-arg "LLVM_VERSION=$LLVM_VERSION" --platform linux/arm64 --tag $DOCKER_TAG .
  docker buildx build --build-arg "LLVM_VERSION=$LLVM_VERSION" --platform linux/arm64,linux/amd64 --tag $DOCKER_TAG .
}

build_docker_images "14.0.6"
build_docker_images "15.0.7"
build_docker_images "16.0.6"
build_docker_images "17.0.6"
build_docker_images "18.1.8"
build_docker_images "19.1.7"
build_docker_images "20.1.8"
build_docker_images "21.1.1"