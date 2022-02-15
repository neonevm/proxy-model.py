import unittest
from solcx import compile_source
from web3 import Web3
import os
from .testing_helpers import request_airdrop
from solana.account import Account as SolanaAccount

NEON_TOKEN_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract NeonToken {
    address constant NeonPrecompiled = 0xFF00000000000000000000000000000000000003;

    function withdraw(bytes32 spender) override public payable returns (bool) {
        (bool success, bytes memory returnData) = NeonPrecompiled.delegatecall(abi.encodeWithSignature("withdraw(bytes32)", spender));
        return success;
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
        print(f"default eth account: {eth_account.address}")
        request_airdrop(eth_account.address)

    def deploy_contract(self):
        erc20 = proxy.eth.contract(abi=self.neon_token['abi'], bytecode=self.neon_token['bin'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = erc20.constructor().buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, eth_account.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        print(f'tx_deploy_hash: {tx_deploy_hash.hex()}')
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print(f'tx_deploy_receipt: {tx_deploy_receipt}')
        print(f'deploy status: {tx_deploy_receipt.status}')
        self.neon_token_address = tx_deploy_receipt.contractAddress
        print(f'NeonToken contract address is: {self.neon_token_address}')
        self.neon_contract = proxy.eth.contract(address=self.neon_token_address, abi=self.neon_token['abi'])

    def test_success_call_withdraw(self):
        dest_acc = SolanaAccount()
        print(f"Try to withdraw NEON tokens to solana account {dest_acc.public_key()}")
        amount = pow(10, 18) # 1 NEON
        withdraw_func = self.neon_contract.functions.withdraw(bytes(dest_acc.public_key()))
        result = withdraw_func.transact({ "value": amount })
        print(result)