#!/bin/bash
COMPONENT="dbcreation"
echo "$(date "+%F %X.%3N") I $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

source proxy/run-set-env.sh ${COMPONENT}

echo "$(date "+%F %X.%3N") I $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} dbcreation"

cd ./proxy
pwd
ls -al
python3 ./db_creation.py
