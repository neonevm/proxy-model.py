#!/bin/bash
set -euo pipefail

if [[ ${GITHUB_REF_NAME} == "master" ]]; then
    TAG=stable
elif [[ ${GITHUB_REF_NAME} == "develop" ]]; then
    TAG=latest
else
    TAG=${GITHUB_REF_NAME}
fi

docker pull neonlabsorg/proxy:${GITHUB_SHA}
docker tag neonlabsorg/proxy:${GITHUB_SHA} neonlabsorg/proxy:${TAG}
docker push neonlabsorg/proxy:${TAG}
