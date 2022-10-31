#!/bin/bash
set -euo pipefail

source .buildkite/steps/revision.sh

if [ "${SKIP_DOCKER_PULL}" != "YES" ]; then
    # Refreshing neonlabsorg/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
    docker pull neonlabsorg/evm_loader:${NEON_EVM_COMMIT}
    docker pull neonlabsorg/neon_test_invoke_program:develop
fi

docker build --network=host -t neonlabsorg/proxy:${REVISION} \
    --build-arg NEON_EVM_COMMIT=${NEON_EVM_COMMIT} \
    --build-arg PROXY_REVISION=${REVISION} \
    --build-arg PROXY_LOG_CFG=${PROXY_LOG_CFG} \
    .
