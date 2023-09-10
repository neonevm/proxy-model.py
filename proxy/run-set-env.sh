#!/bin/bash
COMPONENT="${1:-Undefined}"
set -xeo pipefail

echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Init environment set"

[[ -z "$SOLANA_URL" ]] && echo "$(date "+%F %X.%3N") E $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} SOLANA_URL is not set" && exit 1
[[ -z "$EVM_LOADER" ]] && echo "$(date "+%F %X.%3N") E $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} EVM_LOADER is not set" && exit 1

solana config set -u $SOLANA_URL

isArg() { case "$1" in "$2"|"$2="*) true;; *) false;; esac }
EXTRA_ARGS_TIMEOUT=' --timeout 300'
for val in $EXTRA_ARGS; do
    isArg $val '--timeout' && EXTRA_ARGS_TIMEOUT=''
done
EXTRA_ARGS+=$EXTRA_ARGS_TIMEOUT
