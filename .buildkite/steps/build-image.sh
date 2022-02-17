#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

set ${SOLANA_REVISION:=v1.8.12-testnet}
set ${EVM_LOADER_REVISION:=latest}

# Refreshing neonlabsorg/solana:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull neonlabsorg/solana:${SOLANA_REVISION}

# Refreshing neonlabsorg/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull neonlabsorg/evm_loader:${EVM_LOADER_REVISION}

ls -al

INFRA_REFLECT_FILE="proxy-model.py.changes"
INFRA_REFLECT_REPO_PATH="https://raw.githubusercontent.com/neonlabsorg/proxy-model.py/369-calculate-hashes/develop_changes/"
MAINTENANCE_FILES="
./proxy/environment.py
./proxy/proxy.py"

echo "MAINTENANCE_FILES=$MAINTENANCE_FILES"
wget -O "${INFRA_REFLECT_FILE}" "${INFRA_REFLECT_REPO_PATH}${INFRA_REFLECT_FILE}"
git ls-files -s $MAINTENANCE_FILES > "${INFRA_REFLECT_FILE}"".""${REVISION}"
echo "------ ${INFRA_REFLECT_FILE}:" && cat ./"${INFRA_REFLECT_FILE}"
echo "------ ${INFRA_REFLECT_FILE}.${REVISION}:" && cat ./"${INFRA_REFLECT_FILE}"".""${REVISION}"
echo "==========================================================================="
if diff -B ./"${INFRA_REFLECT_FILE}" ./"${INFRA_REFLECT_FILE}"".""${REVISION}"; then
  echo "==========================================================================="
  echo "The changes in maintenance files: "$MAINTENANCE_FILES "are reflected in the infra file ${INFRA_REFLECT_REPO_PATH}${INFRA_REFLECT_FILE}";
else
  echo "==========================================================================="
  echo "The changes in maintenance files: "$MAINTENANCE_FILES "are NOT reflected in the infra file ${INFRA_REFLECT_REPO_PATH}${INFRA_REFLECT_FILE}" | grep --color=always "are NOT reflected";
  exit 1
fi
echo "==========================================================================="

docker build -t neonlabsorg/proxy:${REVISION} \
    --build-arg SOLANA_REVISION=${SOLANA_REVISION} \
    --build-arg EVM_LOADER_REVISION=${EVM_LOADER_REVISION} \
    --build-arg PROXY_REVISION=${REVISION} \
    .
