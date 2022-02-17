#!/bin/bash
set -euox pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

#INFRA_REFLECT_FILE="https://github.com/neonlabsorg/neon-infra-inventories/blob/369-calculate-hashes/develop_changes/neon-evm.changes"
INFRA_REFLECT_FILE="https://github.com/neonlabsorg/proxy-model.py/blob/369-calculate-hashes/develop_changes/neon-evm.changes"
MAINTENANCE_FILES="
./proxy/environment.py
./proxy/proxy.py"

cat ./proxy-model.py.changes

echo "INFRA_REFLECT_FILE=$INFRA_REFLECT_FILE"
echo "MAINTENANCE_FILES=$MAINTENANCE_FILES"

git ls-files -s $MAINTENANCE_FILES > proxy-model.py.changes.${PROXY_REVISION}
wget "$INFRA_REFLECT_FILE"

if diff proxy-model.py.changes proxy-model.py.changes.${PROXY_REVISION}; then
  echo "the changes in maintenance files: "$MAINTENANCE_FILES "are reflected in the infra file $INFRA_REFLECT_FILE";
else
  echo "the changes in maintenance files: "$MAINTENANCE_FILES "are NOT reflected in the infra file $INFRA_REFLECT_FILE";
fi

echo "CI checks success"
exit 0
