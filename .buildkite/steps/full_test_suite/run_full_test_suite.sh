#!/bin/bash
set -euo pipefail

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
#
## Start tests
#echo Full test suite container name - ${FTS_CONTAINER_NAME}
#docker-compose -f docker-compose/docker-compose-full-test-suite.yml pull
#docker-compose -f docker-compose/docker-compose-full-test-suite.yml up
#FTS_RESULT=$(docker logs ${FTS_CONTAINER_NAME} | (grep -oP "(?<=Passing - )\d+" || echo 0))
## Retreive logs
#docker cp ${FTS_CONTAINER_NAME}:/opt/allure-reports.tar.gz ./
#docker logs ${FTS_CONTAINER_NAME} > ./${FTS_CONTAINER_NAME}.log
## Clean resources
#docker-compose -f docker-compose/docker-compose-full-test-suite.yml rm -f
#
## Results
#echo Full test passing - ${FTS_RESULT}
#echo Full test threshold - ${FTS_THRESHOLD}
#echo Check if ${FTS_RESULT} is greater or equeal ${FTS_THRESHOLD}
#test ${FTS_RESULT} -ge ${FTS_THRESHOLD}

# solana
export SOLANA_HOST=`buildkite-agent meta-data get "SOLANA_IP"`
ssh-keyscan -H $SOLANA_HOST >> ~/.ssh/known_hosts
echo "Upload logs for service: solana"
ssh -i ${SSH_KEY} ubuntu@${SOLANA_HOST} 'sudo docker logs solana 2>&1 | pbzip2 > /tmp/solana.log.bz2'
scp -i ${SSH_KEY} ubuntu@${SOLANA_HOST}:/tmp/solana.log.bz2 ./solana.log.bz2


# proxy
export PROXY_HOST=`buildkite-agent meta-data get "PROXY_IP"`
ssh-keyscan -H $PROXY_HOST >> ~/.ssh/known_hosts
declare -a services=("evm_loader" "postgres" "dbcreation" "indexer" "proxy" "faucet" "airdropper")

for service in "${services[@]}"
do
   echo "Upload logs for service: $service"
   ssh -i ${SSH_KEY} ubuntu@${PROXY_HOST} "sudo docker logs $service 2>&1 | pbzip2 > /tmp/$service.log.bz2"
   scp -i ${SSH_KEY} ubuntu@${PROXY_HOST}:/tmp/$service.log.bz2 ./$service.log.bz2
done
