import unittest
from solcx import compile_source
from web3 import Web3
import os
from .testing_helpers import request_airdrop
from solana.account import Account as SolanaAccount
from solana.rpc.api import Client as SolanaClient
from solana.transaction import Transaction
from solana.rpc.types import TxOpts
from solana.rpc.commitment import Confirmed
from spl.token.client import Token as SplToken
from spl.token.instructions import get_associated_token_address, create_associated_token_account
from proxy.environment import ETH_TOKEN_MINT_ID
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.rpc.commitment import Confirmed

NEON_TOKEN_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract NeonToken {
    address constant NeonPrecompiled = 0xFF00000000000000000000000000000000000003;

    function withdraw(bytes32 spender) public payable returns (bool) {
        (bool success, bytes memory returnData) = NeonPrecompiled.delegatecall(abi.encodeWithSignature("withdraw(bytes32)", spender));
        require(success);
        return success;
    }
}
'''


proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
solana_url = os.environ.get('SOLANA_URL', 'http://solana:8899/')
proxy = Web3(Web3.HTTPProvider(proxy_url))
solana = SolanaClient(solana_url)
SEED = 'TestNeonToken'
eth_account = proxy.eth.account.create(SEED)
proxy.eth.default_account = eth_account.address

class TestNeonToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sol_payer = SolanaAccount()
        cls.deploy_contract(cls)
        cls.spl_neon_token = SplToken(solana, ETH_TOKEN_MINT_ID, TOKEN_PROGRAM_ID, cls.sol_payer)
        print(f"default eth account: {eth_account.address}")
        request_airdrop(eth_account.address)

    def deploy_contract(self):
        artifacts = compile_source(NEON_TOKEN_CONTRACT)
        _, self.neon_token_iface = artifacts.popitem()

        self.neon_contract = proxy.eth.contract(abi=self.neon_token_iface['abi'], 
                                                bytecode=self.neon_token_iface['bin'])
        nonce = proxy.eth.get_transaction_count(eth_account.address)
        tx = {'nonce': nonce}
        tx_constructor = self.neon_contract.constructor().buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, eth_account.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        print(f'tx_deploy_hash: {tx_deploy_hash.hex()}')
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print(f'tx_deploy_receipt: {tx_deploy_receipt}')
        print(f'deploy status: {tx_deploy_receipt.status}')
        self.neon_token_address = tx_deploy_receipt.contractAddress
        print(f'NeonToken contract address is: {self.neon_token_address}')
        self.neon_contract = proxy.eth.contract(address=self.neon_token_address, 
                                                abi=self.neon_token_iface['abi'])

    def withdraw(self, dest_acc: SolanaAccount, withdraw_amount_alan: int):
        nonce = proxy.eth.get_transaction_count(eth_account.address)
        tx = {'value': withdraw_amount_alan, 'nonce': nonce}
        withdraw_tx_dict = self.neon_contract.functions.withdraw(bytes(dest_acc.public_key())).buildTransaction(tx)
        withdraw_tx = proxy.eth.account.sign_transaction(withdraw_tx_dict, eth_account.key)
        withdraw_tx_hash = proxy.eth.send_raw_transaction(withdraw_tx.rawTransaction)
        print(f'withdraw_tx_hash: {withdraw_tx_hash.hex()}')
        withdraw_tx_receipt = proxy.eth.wait_for_transaction_receipt(withdraw_tx_hash)
        print(f'withdraw_tx_receipt: {withdraw_tx_receipt}')
        print(f'deploy status: {withdraw_tx_receipt.status}')
    
    def test_success_withdraw_to_non_existing_account(self):
        """
        Should succesfully withdraw NEON tokens to previously non-existing Associated Token Account
        """
        dest_acc = SolanaAccount()
        print(f"Try to withdraw NEON tokens to solana account {dest_acc.public_key()}")
        # creating destination accout by airdropping SOL
        solana.request_airdrop(dest_acc.public_key(), 1000_000_000_000)
        dest_token_acc = get_associated_token_address(dest_acc.public_key(), ETH_TOKEN_MINT_ID)
        print(f"Destination token account: {dest_token_acc}")
        
        withdraw_amount_alan = pow(10, 18) # 1 NEON
        withdraw_amount_galan = int(withdraw_amount_alan / 1_000_000_000)

        # Check source balance
        source_balance_before_alan = proxy.eth.get_balance(eth_account.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(destination_balance_before_galan['error'] is not None)

        self.withdraw(dest_acc, withdraw_amount_alan)

        # Check source balance
        source_balance_after_alan = proxy.eth.get_balance(eth_account.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan - withdraw_amount_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertEqual(int(destination_balance_after_galan['result']['value']['amount']), withdraw_amount_galan)

    def test_success_withdraw_to_existing_account(self):
        """
        Should succesfully withdraw NEON tokens to existing Associated Token Account
        """
        dest_acc = SolanaAccount()
        print(f"Try to withdraw NEON tokens to solana account {dest_acc.public_key()}")
        # creating destination accout by airdropping SOL
        solana.request_airdrop(dest_acc.public_key(), 1000_000_000_000)

        # Creating destination Associated Token Account
        trx = Transaction()
        trx.add(
            create_associated_token_account(
                dest_acc.public_key(), 
                dest_acc.public_key(), 
                ETH_TOKEN_MINT_ID
            )
        )
        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        solana.send_transaction(trx, dest_acc, opts=opts)
        
        dest_token_acc = get_associated_token_address(dest_acc.public_key(), ETH_TOKEN_MINT_ID)
        print(f"Destination token account: {dest_token_acc}")
        
        withdraw_amount_alan = pow(10, 18) # 1 NEON
        withdraw_amount_galan = int(withdraw_amount_alan / 1_000_000_000)

        # Check source balance
        source_balance_before_alan = proxy.eth.get_balance(eth_account.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must exist with zero balance)
        destination_balance_before_galan = int(self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)['result']['value']['amount'])
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertEqual(destination_balance_before_galan, 0)

        self.withdraw(dest_acc, withdraw_amount_alan)

        # Check source balance
        source_balance_after_alan = proxy.eth.get_balance(eth_account.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan - withdraw_amount_alan)

        # Check destination balance
        destination_balance_after_galan = int(self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)['result']['value']['amount'])
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertEqual(destination_balance_after_galan, withdraw_amount_galan)

    def test_failed_withdraw_non_divisible_amount(self):
        """
        Should fail withdrawal because amount not divised by 1 billion
        """
        dest_acc = SolanaAccount()
        print(f"Try to withdraw NEON tokens to solana account {dest_acc.public_key()}")
        # creating destination accout by airdropping SOL
        solana.request_airdrop(dest_acc.public_key(), 1000_000_000_000)
        dest_token_acc = get_associated_token_address(dest_acc.public_key(), ETH_TOKEN_MINT_ID)
        print(f"Destination token account: {dest_token_acc}")
        
        withdraw_amount_alan = pow(10, 18) + 123 # NEONs

        # Check source balance
        source_balance_before_alan = proxy.eth.get_balance(eth_account.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(destination_balance_before_galan['error'] is not None)

        self.withdraw(dest_acc, withdraw_amount_alan)

        # Check source balance
        source_balance_after_alan = proxy.eth.get_balance(eth_account.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertTrue(destination_balance_after_galan['error'] is not None)
