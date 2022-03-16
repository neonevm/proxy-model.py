#!/bin/bash
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update
sudo apt-get -y install ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
cd /opt
curl -O https://raw.githubusercontent.com/neonlabsorg/proxy-model.py/${branch}/proxy/docker-compose-test.yml

export REVISION=${revision}
export SOLANA_URL=http:\/\/${solana_ip}:8899

cat > docker-compose-test.override.yml <<EOF
version: "3"

services:
  evm_loader:
    container_name: evm_loader
    #image: neonlabsorg/evm_loader:\$\{EVM_LOADER_REVISION:-latest\}
    environment:
      - SOLANA_URL=$SOLANA_URL
    depends_on: []
    networks:
      - net
    command: bash -c "create-test-accounts.sh 1 && deploy-evm.sh && /opt/spl-token create-account HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU && /opt/spl-token mint HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU 1000000000000 --owner /opt/evm_loader-keypair.json -- HX14J4Pp9CgSbWP13Dtpm8VLJpNxMYffLtRCRGsx7Edv"
  proxy:
    environment:
      - SOLANA_URL=$SOLANA_URL
    ports:
      - 9091:9090
  faucet:
    image: neonlabsorg/faucet:latest
    environment:
      - FAUCET_RPC_BIND=0.0.0.0
      - FAUCET_RPC_PORT=3333
      - SOLANA_URL=$SOLANA_URL
      - NEON_ETH_MAX_AMOUNT=50000
      - EVM_LOADER=53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io
      - NEON_TOKEN_MINT=HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU   
      - FAUCET_RPC_ALLOWED_ORIGINS=["https://neonswap.live"]
      - FAUCET_WEB3_ENABLE=false
      - FAUCET_SOLANA_ENABLE=true
      - NEON_TOKEN_MINT_DECIMALS=9
      - NEON_OPERATOR_KEYFILE=/opt/faucet/id.json
      - SOLANA_COMMITMENT=finalized
    ports:
      - 3334:3333
    entrypoint: /opt/faucet/faucet --config /opt/proxy/faucet.conf run
  airdropper:
    environment:
      - SOLANA_URL=$SOLANA_URL
  indexer:
    environment:
      - SOLANA_URL=$SOLANA_URL
EOF



SERVICES=$(docker-compose -f docker-compose-test.yml config --services | grep -v "solana")

CHECK_COMMAND=`curl $SOLANA_URL -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1, "method":"getHealth"}'`
MAX_COUNT=100
CURRENT_ATTEMPT=1
while [[ "$CHECK_COMMAND" != "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":1}" && $CURRENT_ATTEMPT -gt $MAX_COUNT ]]
do
  CHECK_COMMAND=`curl $SOLANA_URL -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1, "method":"getHealth"}'`
  echo $CHECK_COMMAND >> /tmp/output.txt
  echo "attempt: $CURRENT_ATTEMPT"
  ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
  sleep 2
done;

docker-compose -f docker-compose-test.yml -f docker-compose-test.override.yml up -d $SERVICES

docker rm -f solana
