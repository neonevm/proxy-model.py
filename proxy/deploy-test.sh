#!/bin/bash
set -xeuo pipefail

echo "Deploy test..."

solana config set -u $SOLANA_URL
solana address || solana-keygen new --no-passphrase
export $(/spl/bin/neon-cli --commitment confirmed --url $SOLANA_URL --evm_loader "$EVM_LOADER" neon-elf-params)

curl -v --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","id":1,"jsonrpc":"2.0","params":[]}' $PROXY_URL

solana config set -u $SOLANA_URL
solana config get
solana address
solana airdrop 1000
solana balance

set ${TESTNAME:=*}

python3 -m unittest discover -v -p "test_${TESTNAME}.py"

echo "Deploy test success"
exit 0
