import os
import unittest
import json
from environment import NEON_CLIENT_ALLOWANCE_TOKEN, NEON_CLIENT_DENIAL_TOKEN, \
    NEON_CONTRACT_ALLOWANCE_TOKEN, NEON_CONTRACT_DENIAL_TOKEN
from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.publickey import PublicKey
from solana.account import Account as SolanaAccount
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from web3 import Web3


class TestWhiteLists(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.solana = SolanaClient(os.environ['SOLANA_URL'])
        cls.signer = SolanaAccount()
        cls.solana.request_airdrop(cls.signer.public_key(), 1000_000_000_000, Confirmed)
        with open("proxy/evm_loader-keypair.json") as f:
            d = json.load(f)
        cls.mint_authority = SolanaAccount(d[0:32])

        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        cls.proxy = Web3(Web3.HTTPProvider(proxy_url))
        cls.eth_account = cls.proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/468')
        cls.proxy.eth.default_account = cls.eth_account.address

        cls.client_allowance_token = None
        if NEON_CLIENT_ALLOWANCE_TOKEN is not None:
            print(f'Client allowance token: {NEON_CLIENT_ALLOWANCE_TOKEN}')
            cls.client_allowance_token = SplToken(cls.solana, 
                                                  PublicKey(NEON_CLIENT_ALLOWANCE_TOKEN), 
                                                  TOKEN_PROGRAM_ID,
                                                  cls.signer)

        cls.client_denial_token = None
        if NEON_CLIENT_DENIAL_TOKEN is not None:
            print(f'Client denial token: {NEON_CLIENT_DENIAL_TOKEN}')
            cls.client_denial_token = SplToken(cls.solana, 
                                               PublicKey(NEON_CLIENT_DENIAL_TOKEN), 
                                               TOKEN_PROGRAM_ID,
                                               cls.signer)

        cls.contract_allowance_token = None
        if NEON_CONTRACT_ALLOWANCE_TOKEN is not None:
            print(f'Contract allowance token: {NEON_CLIENT_ALLOWANCE_TOKEN}')
            cls.contract_allowance_token = SplToken(cls.solana, 
                                                    PublicKey(NEON_CONTRACT_ALLOWANCE_TOKEN), 
                                                    TOKEN_PROGRAM_ID,
                                                    cls.signer)

        cls.contract_denial_token = None
        if NEON_CONTRACT_DENIAL_TOKEN is not None:
            print(f'Contract denial token: {NEON_CLIENT_DENIAL_TOKEN}')
            cls.contract_denial_token = SplToken(cls.solana, 
                                                 PublicKey(NEON_CONTRACT_DENIAL_TOKEN), 
                                                 TOKEN_PROGRAM_ID,
                                                 cls.signer)

    def mint_client_allowance_token(self, target: PublicKey, amount: int):
        self.client_allowance_token.mint_to(target, self.mint_authority, amount,
                                            opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def mint_client_denial_token(self, target: PublicKey, amount: int):
        self.client_denial_token.mint_to(target, self.mint_authority, amount,
                                         opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def mint_contract_allowance_token(self, target: PublicKey, amount: int):
        self.contract_allowance_token.mint_to(target, self.mint_authority, amount,
                                              opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def mint_contract_denial_token(self, target: PublicKey, amount: int):
        self.contract_denial_token.mint_to(target, self.mint_authority, amount,
                                           opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def test_reject_transaction_from_banned_sender(self):
        """
        Should reject transaction from sender that was banned
        https://github.com/neonlabsorg/proxy-model.py/issues/468
        """
        right_nonce = self.proxy.eth.get_transaction_count(self.proxy.eth.default_account)
        value_to_store = 452356
        trx_store = self.storage_contract.functions.store(value_to_store).buildTransaction({'nonce': right_nonce})
        print('trx_store:', trx_store)
        trx_store_signed = self.proxy.eth.account.sign_transaction(trx_store, self.eth_account.key)
        print('trx_store_signed:', trx_store_signed)
        trx_store_hash = self.proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        print('trx_store_hash:', trx_store_hash.hex())
        trx_store_receipt = self.proxy.eth.wait_for_transaction_receipt(trx_store_hash)
        print('trx_store_receipt:', trx_store_receipt)