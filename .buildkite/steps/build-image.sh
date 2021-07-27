#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

set ${SOLANA_REVISION:=v1.6.9-resources}
set ${EVM_LOADER_REVISION:=6da1b8d1ceee39d399e3e0048ff67d037c6a1caa}

# Refreshing cybercoredev/solana:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/solana:${SOLANA_REVISION}

# Refreshing cybercoredev/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/evm_loader:${EVM_LOADER_REVISION}

docker build -t cybercoredev/proxy:${REVISION} \
    --build-arg SOLANA_REVISION=${SOLANA_REVISION} \
    --build-arg EVM_LOADER_REVISION=${EVM_LOADER_REVISION} \
    .
