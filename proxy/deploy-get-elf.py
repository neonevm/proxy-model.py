import os
import json
import subprocess


solana_url = os.environ.get("SOLANA_URL")
evm_loader = os.environ.get("EVM_LOADER")

result = subprocess.run(f'neon-cli --commitment confirmed --url "{solana_url}" --evm_loader "{evm_loader}" neon-elf-params', shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')

envs = json.loads(result)["value"]

with open(".test-env", "w") as f:
    for env in envs:
        f.write(f"{env}={envs[env]}\n")
