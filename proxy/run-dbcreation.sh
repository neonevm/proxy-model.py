#!/bin/bash
COMPONENT="DB-Creation"
echo "$(date "+%F %X.%3N") I $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

source proxy/run-set-env.sh ${COMPONENT}

echo "$(date "+%F %X.%3N") I $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} dbcreation"
python3 db_creation.py
