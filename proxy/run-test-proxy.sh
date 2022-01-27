#!/bin/bash

if [ -z "$SOLANA_URL" ]; then
  echo "SOLANA_URL is not set"
  exit 1
fi

solana config set -u $SOLANA_URL

echo "Dumping evm_loader and extracting ELF parameters"
export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
export $(/spl/bin/neon-cli --commitment confirmed --url $SOLANA_URL --evm_loader="$EVM_LOADER" neon-elf-params)

/spl/bin/create-test-accounts.sh 1

proxy/run-proxy.sh
