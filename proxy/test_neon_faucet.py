# File: test_neon_faucet.py
# Test for the faucet service.

import unittest
import os
import io
import time
import subprocess
import requests

class Test_Neon_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['FAUCET_RPC_PORT'] = '3333'
        os.environ['FAUCET_RPC_ALLOWED_ORIGINS'] = 'http://localhost'
        os.environ['FAUCET_WEB3_ENABLE'] = 'false'
        os.environ['WEB3_RPC_URL'] = 'http://localhost:9090/solana'
        os.environ['WEB3_PRIVATE_KEY'] = '0x0000000000000000000000000000000000000000000000000000000000000Ace'
        os.environ['NEON_ERC20_TOKENS'] = '0x00000000000000000000000000000000CafeBabe, 0x00000000000000000000000000000000DeadBeef'
        os.environ['NEON_ERC20_MAX_AMOUNT'] = '1000'
        os.environ['FAUCET_SOLANA_ENABLE'] = 'true'
        os.environ['SOLANA_URL'] = 'http://solana:8899'
        os.environ['EVM_LOADER'] = '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io'
        os.environ['NEON_TOKEN_MINT'] = 'HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU'
        os.environ['NEON_TOKEN_MINT_DECIMALS'] = '9'
        os.environ['NEON_OPERATOR_KEYFILE'] = '/root/.config/solana/id.json'
        os.environ['NEON_ETH_MAX_AMOUNT'] = '10'
        cls.faucet = subprocess.Popen(['faucet', 'run', '--workers', '1'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print('Sleeping 1 sec...')
        time.sleep(1) # 1 second

    def test_eth_token(self):
        url = 'http://localhost:{}/request_eth_token'.format(os.environ['FAUCET_RPC_PORT'])
        data = '{"wallet": "0x4570e07200b6332989Dc04fA2a671b839D26eF0E", "amount": 1}'
        r = requests.post(url, data=data)
        print('r:',r)

    def test_erc20_tokens(self):
        print("\n# test_erc20_tokens")

    @classmethod
    def tearDownClass(cls):
        url = 'http://localhost:{}/request_stop'.format(os.environ['FAUCET_RPC_PORT'])
        data = '{"delay": 1000}' # 1 second
        requests.post(url, data=data)
        with io.TextIOWrapper(cls.faucet.stdout, encoding="utf-8") as out:
            for line in out:
                print(line.strip())

if __name__ == '__main__':
    unittest.main()
