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
    command: bash -c "create-test-accounts.sh 1 && deploy-evm.sh"
  proxy:
    environment:
      - SOLANA_URL=$SOLANA_URL
  faucet:
    environment:
      - SOLANA_URL=$SOLANA_URL
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
