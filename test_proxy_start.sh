#!/bin/bash

python3 ./.github/workflows/deploy.py deploy_check \
	--proxy_tag=local-test \
	--neon_evm_tag=latest \
	--skip_uniswap \
	--test_files='test_get_block_hash.py'
