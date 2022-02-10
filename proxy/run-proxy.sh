#!/bin/bash
echo $(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ Proxy:Undefined {}

source proxy/run-set-env.sh

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin $EXTRA_ARGS
