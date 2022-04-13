#!/bin/bash

curl --location --request POST 'http://faucet:3333/request_ping' \
--header 'X-Ping-Header' \
--data-raw 'Healthcheck-ping'