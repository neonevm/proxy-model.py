#!/bin/bash
set -xeuo pipefail

echo "Prepare deploying of tests..."
curl -v --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","id":1,"jsonrpc":"2.0","params":[]}' "${PROXY_URL}"

solana config get

echo "Get ELF params"
python3 proxy/deploy-get-elf.py
ls -la
cp .test-env ../
ls -la ../
echo "TEST_PROGRAM=$(solana address -k /spl/bin/neon_test_invoke_program-keypair.json)" >> .test-env

export $(cat .test-env | xargs)

echo "Done preparing of deploying of tests"
