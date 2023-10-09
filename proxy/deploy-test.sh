#!/bin/bash
set -xeuo pipefail

echo "Deploy test ..."
python3 -m unittest discover -v -p "${TESTNAME:-test_*.py}"
echo "Deploy test success"

exit 0
