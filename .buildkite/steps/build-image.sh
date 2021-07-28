#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

set ${SOLANA_REVISION:=v1.7.6-resources}
set ${EVM_LOADER_REVISION:=b2cdd7ed80e2d7dc39a60f778b722856bc2c32cc}

# Refreshing cybercoredev/solana:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/solana:${SOLANA_REVISION}

# Refreshing cybercoredev/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/evm_loader:${EVM_LOADER_REVISION}

docker build -t cybercoredev/proxy:${REVISION} \
    --build-arg SOLANA_REVISION=${SOLANA_REVISION} \
    --build-arg EVM_LOADER_REVISION=${EVM_LOADER_REVISION} \
    .
