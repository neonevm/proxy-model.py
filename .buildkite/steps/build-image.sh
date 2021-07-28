#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

set ${SOLANA_REVISION:=v1.7.6-resources}
set ${EVM_LOADER_REVISION:=9443f841b3635650b0eff682a704b1ce88daffc5}

# Refreshing cybercoredev/solana:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/solana:${SOLANA_REVISION}

# Refreshing cybercoredev/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/evm_loader:${EVM_LOADER_REVISION}

docker build -t cybercoredev/proxy:${REVISION} \
    --build-arg SOLANA_REVISION=${SOLANA_REVISION} \
    --build-arg EVM_LOADER_REVISION=${EVM_LOADER_REVISION} \
    .
