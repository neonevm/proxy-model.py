#!/bin/bash

if [ -z "$SOLANA_URL" ]; then
  echo "SOLANA_URL is not set"
  exit 1
fi

if [ -z "$TEST_FAUCET_INIT_NEON_BALANCE"]; then
    echo "TEST_FAUCET_INIT_NEON_BALANCE is not set"
    exit 1
fi

solana config set -u "$SOLANA_URL"

echo "Extracting NEON-EVM's ELF parameters"
export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
export $(/spl/bin/neon-cli --commitment confirmed --url $SOLANA_URL --evm_loader="$EVM_LOADER" neon-elf-params)

echo "Generating new account for operate with faucet service"
rm /$HOME/.config/solana/id.json
solana-keygen new --no-passphrase -o "$HOME/.config/solana/id.json"

ACCOUNT=$(solana address -k "/$HOME/.config/solana/id.json")
echo "New account $ACCOUNT"
if ! solana account "$ACCOUNT"; then
    echo "airdropping..."
    solana airdrop 5000 "$ACCOUNT"
    # check that balance >= 10 otherwise airdroping by 1 SOL up to 10
    BALANCE=$(solana balance "$ACCOUNT" | tr '.' '\t'| tr '[:space:]' '\t' | cut -f1)
    while [ "$BALANCE" -lt 10 ]; do
      solana airdrop 1 "$ACCOUNT"
      sleep 1
      BALANCE=$(solana balance "$ACCOUNT" | tr '.' '\t'| tr '[:space:]' '\t' | cut -f1)
    done
fi

if [ "$(spl-token balance "$NEON_TOKEN_MINT" || echo 0)" -eq 0 ]; then
    echo 'Create balance and mint token'
	TOKEN_ACCOUNT=$( (spl-token create-account "$NEON_TOKEN_MINT" || true) | grep -Po 'Creating account \K[^\n]*')
	echo "TOKEN_ACCOUNT=$TOKEN_ACCOUNT"
	spl-token mint "$NEON_TOKEN_MINT" $TEST_FAUCET_INIT_NEON_BALANCE --owner /spl/bin/evm_loader-keypair.json -- "$TOKEN_ACCOUNT"
fi

./run-faucet.sh
