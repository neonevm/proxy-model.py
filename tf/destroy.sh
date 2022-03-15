#!/bin/bash

cd tf

### Receive artefacts
export SSH_KEY="~/.ssh/ci-stands"
export ARTIFACTS_LOGS="./logs"
mkdir -p $ARTIFACTS_LOGS

# solana
export REMOTE_HOST=`buildkite-agent meta-data get "SOLANA_IP"`
ssh-keyscan -H $REMOTE_HOST >> ~/.ssh/known_hosts
ssh -i $SSH_KEY ubuntu@$REMOTE_HOST 'sudo docker logs solana > /tmp/solana.log'
scp -i $SSH_KEY ubuntu@$REMOTE_HOST:/tmp/solana.log $ARTIFACTS_LOGS

# proxy
export REMOTE_HOST=`buildkite-agent meta-data get "PROXY_IP"`
ssh-keyscan -H $REMOTE_HOST >> ~/.ssh/known_hosts
declare -a services=("evm_loader" "postgres" "dbcreation" "indexer" "proxy" "faucet" "airdropper")

for service in "${services[@]}"
do
   echo "$servce"
   ssh -i $SSH_KEY ubuntu@$REMOTE_HOST "sudo docker logs $service > /tmp/$service.log"
   scp -i $SSH_KEY ubuntu@$REMOTE_HOST:/tmp/$service.log $ARTIFACTS_LOGS
done



### Clean infrastructure by terraform
export TF_VAR_branch=$BUILDKITE_BRANCH
export TFSTATE_BUCKET="nl-ci-stands"
export TFSTATE_KEY="tests/test-$BUILDKITE_COMMIT"
export TFSTATE_REGION="us-east-2"
export TF_VAR_neon_evm_revision=latest
export TF_VAR_proxy_model_revision=latest
export TF_BACKEND_CONFIG="-backend-config="bucket=${TFSTATE_BUCKET}" -backend-config="key=${TFSTATE_KEY}" -backend-config="region=${TFSTATE_REGION}""
terraform init $TF_BACKEND_CONFIG
terraform destroy --auto-approve=true

# info
buildkite-agent meta-data get "PROXY_IP"
buildkite-agent meta-data get "SOLANA_IP"
