#!/bin/bash
COMPONENT="dbcreation"
echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

if [ -z "$EVM_LOADER" ]; then
    echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Extracting EVM_LOADER address from keypair file..."
    export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
    echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} EVM_LOADER=$EVM_LOADER"
fi

echo "$(date "+%F %X.%3N") I $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} dbcreation"

export DBCREATION_MODE='true'

python3 -m proxy

docker exec postgres psql neon-db neon-proxy --command "\\dt+ public.*"
docker exec postgres psql neon-db neon-proxy --command "\\d+ public.*"
