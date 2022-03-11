#!/bin/bash

cd tf

export TF_VAR_branch=$BUILDKITE_BRANCH
export TFSTATE_BUCKET="nl-ci-stands"
export TFSTATE_KEY="tests/test-$BUILDKITE_COMMIT"
export TFSTATE_REGION="us-east-2"
export TF_VAR_neon_evm_revision=latest
export TF_VAR_proxy_model_revision=latest
export TF_BACKEND_CONFIG="-backend-config="bucket=${TFSTATE_BUCKET}" -backend-config="key=${TFSTATE_KEY}" -backend-config="region=${TFSTATE_REGION}""
terraform init $TF_BACKEND_CONFIG
terraform apply --auto-approve=true

terraform output --json | jq -r '.proxy_ip.value' | buildkite-agent meta-data set "neon-tests-proxy-$BUILDKITE_COMMIT"
terraform output --json | jq -r '.solana_ip.value' | buildkite-agent meta-data set "neon-tests-solana-$BUILDKITE_COMMIT"

buildkite-agent meta-data get "neon-tests-proxy-$BUILDKITE_COMMIT"
buildkite-agent meta-data get "neon-tests-solana-$BUILDKITE_COMMIT"
