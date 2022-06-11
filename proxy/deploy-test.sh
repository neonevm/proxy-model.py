#!/bin/bash
set -xeuo pipefail

echo "Deploy test..."

solana config set -u $SOLANA_URL
ln -s /opt/proxy/operator-keypairs/id?*.json /root/.config/solana/

solana address || solana-keygen new --no-passphrase
export $(/spl/bin/neon-cli --commitment confirmed --url $SOLANA_URL --evm_loader "$EVM_LOADER" neon-elf-params)

curl -v --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","id":1,"jsonrpc":"2.0","params":[]}' $PROXY_URL

solana config set -u $SOLANA_URL
solana config get
solana address
solana airdrop 1000
solana balance

set ${TESTNAME:=*}

export ETH_TOKEN_MINT=$NEON_TOKEN_MINT
export TEST_PROGRAM=$(solana address -k /spl/bin/proxy_program-keypair.json)

if [[ -z "${UNITTEST_TESTPATH}" ]]; then
  find . -name "test_*.py" -printf "%f\n" | sort | parallel --halt now,fail=1 --jobs 4 python3 -m unittest discover -v -p {}
else
  python3 -m unittest ${UNITTEST_TESTPATH}
fi

echo "Deploy test success"
exit 0
