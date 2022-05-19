# File: test_neon_faucet.py
# Test for the faucet service.

import unittest
import os
import requests
from web3 import Web3

issue = 'https://github.com/neonlabsorg/neon-evm/issues/166'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create(issue + '/admin')
user = proxy.eth.account.create(issue + '/user')
proxy.eth.default_account = admin.address

erc20_abi = '[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"tokenOwner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"tokens","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"tokens","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[],"name":"_totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"tokenOwner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"remaining","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"tokens","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"success","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"tokenOwner","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"balance","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"a","type":"uint256"},{"internalType":"uint256","name":"b","type":"uint256"}],"name":"safeAdd","outputs":[{"internalType":"uint256","name":"c","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"a","type":"uint256"},{"internalType":"uint256","name":"b","type":"uint256"}],"name":"safeSub","outputs":[{"internalType":"uint256","name":"c","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"receiver","type":"address"},{"internalType":"uint256","name":"tokens","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"success","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"receiver","type":"address"},{"internalType":"uint256","name":"tokens","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"success","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'

class Test_Neon_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\n' + issue)

    # @unittest.skip("a.i.")
    def test_neon_faucet_00_ping(self):
        print()
        url = '{}/request_ping'.format(os.environ['FAUCET_URL'])
        print(url)
        data = '{"ping": "Hello"}'
        r = requests.get(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)

    # @unittest.skip("a.i.")
    def test_neon_faucet_01_version(self):
        print()
        url = '{}/request_version'.format(os.environ['FAUCET_URL'])
        r = requests.get(url)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)

    # @unittest.skip("a.i.")
    def test_neon_faucet_02_neon_in_galans(self):
        print()
        url = '{}/request_neon_in_galans'.format(os.environ['FAUCET_URL'])
        balance_before = proxy.eth.get_balance(user.address)
        print('NEO balance before:', balance_before)
        data = '{"wallet": "' + user.address + '", "amount": 99999}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        # Check
        balance_after = proxy.eth.get_balance(user.address)
        print('NEO balance after:', balance_after)
        print('NEO balance difference:', balance_before - balance_after)
        self.assertEqual(balance_after, 99999000000000)

    # @unittest.skip("a.i.")
    def test_neon_faucet_03_neon(self):
        print()
        url = '{}/request_neon'.format(os.environ['FAUCET_URL'])
        balance_before = proxy.eth.get_balance(user.address)
        print('NEO balance before:', balance_before)
        data = '{"wallet": "' + user.address + '", "amount": 1}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        # Check
        balance_after = proxy.eth.get_balance(user.address)
        print('NEO balance after:', balance_after)
        print('NEO balance difference:', balance_after - balance_before)
        self.assertEqual(balance_after - balance_before, 1000000000000000000)

    # @unittest.skip("a.i.")
    def test_neon_faucet_04_erc20_list(self):
        print()
        url = '{}/request_erc20_list'.format(os.environ['FAUCET_URL'])
        r = requests.get(url)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        self.assertEqual(r.text, '["0xB521b9F3484deF53545F276F1DAA50ef0Ca82E2d","0x51F74c4f148044699113C74A74A64212b0812bE9"]')

    # @unittest.skip("a.i.")
    def test_neon_faucet_06_erc20_single(self):
        print()
        token = '0xB521b9F3484deF53545F276F1DAA50ef0Ca82E2d' # USDT

        bank = '0xb4cC4Ae703Ae5FBF5a678C7CC51868E0A367597F'
        bank_balance = self.get_token_balance(token, bank)
        print('Bank USDT balance before:', bank_balance)
        
        before = self.get_token_balance(token, user.address)
        print('User USDT balance before:', before)
        
        url = '{}/request_erc20'.format(os.environ['FAUCET_URL'])
        data = '{"wallet": "' + user.address + '", "token_addr": "' + token + '", "amount": 1}'
        print('data:', data)
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code, r.reason)
        assert(r.ok)
        
        after = self.get_token_balance(token, user.address)
        print('User USDT balance after:', after)
        self.assertEqual(after - before, 1000000000000000000)

    @unittest.skip("a.i.")
    def test_neon_faucet_05_erc20_all(self):
        print()
        url = '{}/request_erc20'.format(os.environ['FAUCET_URL'])
        token_a = '0xB521b9F3484deF53545F276F1DAA50ef0Ca82E2d' # USDT
        token_b = '0x51F74c4f148044699113C74A74A64212b0812bE9' # AAVE
        a_before = self.get_token_balance(token_a, user.address)
        b_before = self.get_token_balance(token_b, user.address)
        print('token A balance before:', a_before)
        print('token B balance before:', b_before)
        data = '{"wallet": "' + user.address + '", "amount": 1}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        a_after = self.get_token_balance(token_a, user.address)
        b_after = self.get_token_balance(token_b, user.address)
        print('token A balance after:', a_after)
        print('token B balance after:', b_after)
        self.assertEqual(a_after - a_before, 1000000000000000000)
        self.assertEqual(b_after - b_before, 1000000000000000000)

    # Returns balance of a token account.
    # Note: the result is in 10E-18 fractions.
    def get_token_balance(self, token_address, address):
        erc20 = proxy.eth.contract(address=token_address, abi=erc20_abi)
        return erc20.functions.balanceOf(address).call()

if __name__ == '__main__':
    unittest.main()
