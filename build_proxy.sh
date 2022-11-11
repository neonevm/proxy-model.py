#!/bin/bash

python3 ./.github/workflows/deploy.py build_docker_image \
	--proxy_tag=local-test \
	--neon_evm_tag=latest
