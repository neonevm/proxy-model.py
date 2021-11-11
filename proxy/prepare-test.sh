#!/bin/bash

if [ -z "$SOLANA_URL" ]; then
  echo "SOLANA_URL is not set"
  exit 1
fi

solana config set -u $SOLANA_URL

echo "Dumping evm_loader and extracting ELF parameters"
export EVM_LOADER=$(cat /var/deployment_data/evm_loader_id | sed '/Program Id: \([0-9A-Za-z]\+\)/,${s//\1/;b};s/^.*$//;$q1')
solana program dump "$EVM_LOADER" ./evm_loader.dump
export $(/spl/bin/neon-cli --evm_loader="$EVM_LOADER" neon-elf-params ./evm_loader.dump)

create-test-accounts.sh 1

if [ "$(spl-token balance "$NEON_TOKEN_MINT" || echo 0)" -eq 0 ]; then
  [[ -z "$NEW_USER_AIRDROP_AMOUNT" ]] && export NEW_USER_AIRDROP_AMOUNT=100
  echo "NEW_USER_AIRDROP_AMOUNT=$NEW_USER_AIRDROP_AMOUNT"
	echo 'Create balance and mint token'
	TOKEN_ACCOUNT=$( (spl-token create-account "$NEON_TOKEN_MINT" || true) | grep -Po 'Creating account \K[^\n]*')
	echo "TOKEN_ACCOUNT=$TOKEN_ACCOUNT"
	spl-token mint "$NEON_TOKEN_MINT" $(("$NEW_USER_AIRDROP_AMOUNT"*1000)) --owner /var/deployment_data/test_token_owner -- "$TOKEN_ACCOUNT"
fi
