# File: test_neon_faucet.py
# Test for the faucet service.

import unittest
import os
import io
import time
import subprocess
import requests
from web3 import Web3

proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))

class Test_Neon_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['FAUCET_RPC_PORT'] = '3333'
        os.environ['FAUCET_RPC_ALLOWED_ORIGINS'] = 'http://localhost'
        os.environ['FAUCET_WEB3_ENABLE'] = 'true'
        os.environ['WEB3_RPC_URL'] = proxy_url
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

    @unittest.skip("a.i.")
    def test_eth_token(self):
        print()
        address = '0x1111111111111111111111111111111111111111'
        balance_before = proxy.eth.get_balance(address)
        print('balance_before:', balance_before)
        url = 'http://localhost:{}/request_eth_token'.format(os.environ['FAUCET_RPC_PORT'])
        data = '{"wallet": "' + address + '", "amount": 1}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        balance_after = proxy.eth.get_balance(address)
        print('balance_after:', balance_after)
        self.assertEqual(balance_after - balance_before, 1000000000000000000)

    # @unittest.skip("a.i.")
    def test_erc20_tokens(self):
        print()
        address = '0x1111111111111111111111111111111111111111'
        url = 'http://localhost:{}/request_erc20_tokens'.format(os.environ['FAUCET_RPC_PORT'])
        data = '{"wallet": "' + address + '", "amount": 1}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)

    @classmethod
    def tearDownClass(cls):
        url = 'http://localhost:{}/request_stop'.format(os.environ['FAUCET_RPC_PORT'])
        data = '{"delay": 1000}' # 1 second
        r = requests.post(url, data=data)
        if not r.ok:
            cls.faucet.terminate
        with io.TextIOWrapper(cls.faucet.stdout, encoding="utf-8") as out:
            for line in out:
                print(line.strip())

if __name__ == '__main__':
    unittest.main()
