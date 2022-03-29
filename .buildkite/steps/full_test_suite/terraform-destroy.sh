#!/bin/bash

# error handler
handle_error() {
  if [[ $? -ne 0 ]]
  then
    echo "Interrupt at step. $1"
    exit 1
  fi
}


cd .buildkite/steps/full_test_suite


### Receive artefacts
export SSH_KEY="~/.ssh/ci-stands"
export ARTIFACTS_LOGS="./logs"
mkdir -p $ARTIFACTS_LOGS
handle_error "Failed to create artifacts dir at: '$ARTIFACTS_LOGS'"


# solana
export REMOTE_HOST=`buildkite-agent meta-data get "SOLANA_IP"`
ssh-keyscan -H $REMOTE_HOST >> ~/.ssh/known_hosts
handle_error "Can't scan host for fingerprint"
ssh -i ${SSH_KEY} ubuntu@${REMOTE_HOST} 'sudo docker logs solana > /tmp/solana.log 2>&1'
handle_error "Failed to dump logs remotely at: ' ubuntu@${REMOTE_HOST}' with key file: '${SSH_KEY}'"
scp -i ${SSH_KEY} ubuntu@${REMOTE_HOST}:/tmp/solana.log ${ARTIFACTS_LOGS}
handle_error "Retrieve log file for atrifact"


# proxy
export REMOTE_HOST=`buildkite-agent meta-data get "PROXY_IP"`
ssh-keyscan -H $REMOTE_HOST >> ~/.ssh/known_hosts
declare -a services=("evm_loader" "postgres" "dbcreation" "indexer" "proxy" "faucet" "airdropper")

for service in "${services[@]}"
do
   echo "$service"
   ssh -i ${SSH_KEY} ubuntu@${REMOTE_HOST} "sudo docker logs $service > /tmp/$service.log 2>&1"
   handle_error "Dump $service log to the file"
   scp -i ${SSH_KEY} ubuntu@${REMOTE_HOST}:/tmp/$service.log ${ARTIFACTS_LOGS}
   handle_error "Retrieve log file from service $service"
done

export NEON_EVM_COMMIT=${NEON_EVM_COMMIT:-latest}
export PROXY_MODEL_COMMIT=${BUILDKITE_COMMIT}

### Clean infrastructure by terraform
export TF_VAR_branch=${BUILDKITE_BRANCH}
export TF_VAR_neon_evm_commit=${NEON_EVM_COMMIT}
export TF_VAR_proxy_model_commit=${PROXY_MODEL_COMMIT}
export TFSTATE_BUCKET="nl-ci-stands"
export TFSTATE_KEY="tests/test-$BUILDKITE_COMMIT"
export TFSTATE_REGION="us-east-2"
export TF_BACKEND_CONFIG="-backend-config="bucket=${TFSTATE_BUCKET}" -backend-config="key=${TFSTATE_KEY}" -backend-config="region=${TFSTATE_REGION}""
terraform init $TF_BACKEND_CONFIG
handle_error "Failed to proceed the terraform init step. TF_BACKEND_CONFIG: ${TF_BACKEND_CONFIG}"
terraform destroy --auto-approve=true
handle_error "Failed to proceed terraform destroy step"


# info
buildkite-agent meta-data get "PROXY_IP"
buildkite-agent meta-data get "SOLANA_IP"
