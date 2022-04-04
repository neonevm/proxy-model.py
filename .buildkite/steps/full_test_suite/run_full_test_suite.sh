#!/bin/bash

handle_error() {
  if [[ $? -ne 0 ]]
  then
    echo "Interrupt at step. $1"
    exit 1
  fi
}

# External addresses from previous step
PROXY_ADDR=`buildkite-agent meta-data get 'PROXY_IP'`
SOLANA_ADDR=`buildkite-agent meta-data get 'SOLANA_IP'`

# Create envirinment variables for tests
export PROXY_URL="http://${PROXY_ADDR}:9091/solana"
export FAUCET_URL="http://${PROXY_ADDR}:3333/request_neon"
export SOLANA_URL="http://${SOLANA_ADDR}:8899"

# Check variables
echo "External URL for proxy service: ${PROXY_URL}"
echo "External URL for faucet: ${FAUCET_URL}"
echo "External URL for solana: ${SOLANA_URL}"

# Start tests
echo Full test suite container name - ${FTS_CONTAINER_NAME}
docker-compose -f docker-compose/docker-compose-full-test-suite.yml pull
handle_error "Error while docker image pulling"
docker-compose -f docker-compose/docker-compose-full-test-suite.yml up
handle_error "Error while tests running"
FTS_RESULT=$(docker logs ${FTS_CONTAINER_NAME} | (grep -oP "(?<=Passing - )\d+" || echo 0))

# Retreive logs from local containers
docker cp ${FTS_CONTAINER_NAME}:/opt/allure-reports.tar.gz ./
docker logs ${FTS_CONTAINER_NAME} > ./${FTS_CONTAINER_NAME}.log

# Retreive logs from remote instances
export SSH_KEY="~/.ssh/ci-stands"
export ARTIFACTS_LOGS="./logs"
mkdir -p $ARTIFACTS_LOGS
handle_error "Failed to create artifacts dir at: '$ARTIFACTS_LOGS'"

# solana
export SOLANA_ADDR=`buildkite-agent meta-data get "SOLANA_IP"`
ssh-keyscan -H $SOLANA_ADDR >> ~/.ssh/known_hosts
echo "Upload logs for service: solana"
ssh -i ${SSH_KEY} ubuntu@${SOLANA_ADDR} 'sudo docker logs solana 2>&1 | pbzip2 > /tmp/solana.log.bz2'
handle_error "Can't scan host for fingerprint"
scp -i ${SSH_KEY} ubuntu@${SOLANA_ADDR}:/tmp/solana.log.bz2 ${ARTIFACTS_LOGS}
handle_error "Retrieve log file for atrifact"

# proxy
export PROXY_ADDR=`buildkite-agent meta-data get "PROXY_IP"`
ssh-keyscan -H $PROXY_ADDR >> ~/.ssh/known_hosts
declare -a services=("evm_loader" "postgres" "dbcreation" "indexer" "proxy" "faucet" "airdropper")

for service in "${services[@]}"
do
   echo "Upload logs for service: $service"
   ssh -i ${SSH_KEY} ubuntu@${PROXY_ADDR} "sudo docker logs $service 2>&1 | pbzip2 > /tmp/$service.log.bz2"
   handle_error "Dump $service log to the file"
   scp -i ${SSH_KEY} ubuntu@${PROXY_ADDR}:/tmp/$service.log.bz2 ${ARTIFACTS_LOGS}
   handle_error "Retrieve log file from service $service"
done

# Clean resources
docker-compose -f docker-compose/docker-compose-full-test-suite.yml rm -f
handle_error "Error while tests cleanup"

# Results
echo Full test passing - ${FTS_RESULT}
echo Full test threshold - ${FTS_THRESHOLD}
echo Check if ${FTS_RESULT} is greater or equeal ${FTS_THRESHOLD}
test ${FTS_RESULT} -ge ${FTS_THRESHOLD}
