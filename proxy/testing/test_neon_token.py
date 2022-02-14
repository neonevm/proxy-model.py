import unittest
from solcx import compile_source
from web3 import Web3
import os
from .testing_helpers import request_airdrop

NEON_TOKEN_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

interface INeon {
    function withdraw(bytes32 spender) external payable returns (bool);
}

contract NeonToken is INeon {
    address constant NeonPrecompiled = 0xFF00000000000000000000000000000000000003;

    function withdraw(bytes32 spender) public override payable returns (bool) {
        return INeon(NeonPrecompiled).withdraw{value: msg.value}(spender);
    }
}
'''

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
SEED = 'TestNeonToken'
eth_account = proxy.eth.account.create(SEED)
proxy.eth.default_account = eth_account.address

class TestNeonToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        artifacts = compile_source(NEON_TOKEN_CONTRACT)
        _, cls.neon_token = artifacts.popitem()
        cls.deploy_contract(cls)

    def deploy_contract(self):
        erc20 = proxy.eth.contract(abi=self.neon_token['abi'], bytecode=self.neon_token['bin'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = erc20.constructor().buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, eth_account.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        self.debug(f'tx_deploy_hash: {tx_deploy_hash.hex()}')
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        self.debug(f'tx_deploy_receipt: {tx_deploy_receipt}')
        self.debug(f'deploy status: {tx_deploy_receipt.status}')
        self.neon_token_address = tx_deploy_receipt.contractAddress
        self.debug(f'NeonToken contract address is: {self.neon_token_address}')

    def test_success_call_withdraw(self):
        print('IMPLEMENT ME!')