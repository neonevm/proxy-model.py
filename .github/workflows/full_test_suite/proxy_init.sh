#!/bin/bash


# Install docker
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update
sudo apt-get -y install ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io

sudo apt-get -y install pbzip2

# Install docker-compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose


# Get docker-compose file
cd /opt
curl -O https://raw.githubusercontent.com/neonlabsorg/proxy-model.py/${proxy_model_commit}/docker-compose/docker-compose-ci.yml


# Set required environment variables
export REVISION=${proxy_image_tag}
export SOLANA_URL=http:\/\/${solana_ip}:8899
export NEON_EVM_COMMIT=${neon_evm_commit}
export FAUCET_COMMIT=${faucet_model_commit}
export CI_PP_SOLANA_URL=${ci_pp_solana_url}
export DOCKERHUB_ORG_NAME=${dockerhub_org_name}



# Generate docker-compose override file
cat > docker-compose-ci.override.yml <<EOF
version: "3"

services:
  solana:
    container_name: solana
    healthcheck:
      test: [ CMD-SHELL, "/echo done" ]
    entrypoint: "/usr/bin/sleep 10000"

  gas_tank:
    container_name: gas_tank
    entrypoint: "/usr/bin/sleep 10000"

  neon_test_invoke_program_loader:
    container_name: neon_test_invoke_program_loader
    command: bash -c "echo done"

services:
  proxy:
    container_name: proxy
    environment:
      SOLANA_URL: $SOLANA_URL
      EXTRA_ARGS: "--num-workers 16"
    ports:
      - "9090:9090"

  faucet:
    container_name: faucet
    environment:
      SOLANA_URL: $SOLANA_URL
    ports:
      - "3333:3333"

  indexer:
    container_name: indexer
    environment:
      SOLANA_URL: $SOLANA_URL

  postgres:
    container_name: postgres

  dbcreation:
    container_name: dbcreation
EOF


# Get list of services
SERVICES=$(docker-compose -f docker-compose-ci.yml -f docker-compose-ci.override.yml config --services | grep -vP "solana|gas_tank|neon_test_invoke_program_loader")

# Pull latest versions
docker-compose -f docker-compose-ci.yml -f docker-compose-ci.override.yml pull $SERVICES


function wait_service() {
  local SERVICE=$1
  local URL=$2
  local DATA=$3
  local RESULT=$4

  # Max attepts is 100 (each for 2 seconds)
  local MAX_COUNT=100
  local CURRENT_ATTEMPT=1

  local CHECK_COMMAND="curl $URL -s -X POST -H 'Content-Type: application/json' -d '$DATA' | grep -cF '$RESULT'"

  while [[ $CURRENT_ATTEMPT -lt $MAX_COUNT ]]
  do
    echo "$SERVICE attempt: $CURRENT_ATTEMPT" 1>&2
    local CHECK_COMMAND_RESULT=$(eval $CHECK_COMMAND)
    echo $CHECK_COMMAND_RESULT >> /tmp/output.txt
    if [[ "$CHECK_COMMAND_RESULT" == "1" ]]; then
      echo "$SERVICE is up" 1>&2
      break
    fi

    ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
    sleep 2
  done;
}

# Check if Solana is available
SOLANA_DATA='{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
SOLANA_RESULT='"ok"'
wait_service "solana" $SOLANA_URL $SOLANA_DATA $SOLANA_RESULT

# Up all services
docker-compose -f docker-compose-ci.yml -f docker-compose-ci.override.yml up -d $SERVICES


# Check if Proxy is available
PROXY_URL="http://localhost:9090/solana"
PROXY_DATA='{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
PROXY_RESULT='"result"'
wait_service "proxy" $PROXY_URL $PROXY_DATA $PROXY_RESULT


docker rm -f opt_solana_1
