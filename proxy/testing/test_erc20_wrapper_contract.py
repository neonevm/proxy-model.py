## File: test_erc20_wrapper_contract.py
## Integration test for the Neon ERC20 Wrapper contract.

import unittest
import os
import json

from time import sleep

from solana.rpc.commitment import Commitment, Recent
from solana.rpc.types import TxOpts, TokenAccountOpts
from solana.rpc.api import Client as SolanaClient

from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
import spl.token.instructions as SplTokenInstrutions

from ..testing.testing_helpers import request_airdrop
from ..common_neon.solana_transaction import SolAccount, SolPubKey, SolLegacyTx
from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.erc20_wrapper import ERC20Wrapper
from ..common_neon.web3 import NeonWeb3 as Web3
from ..common_neon.config import Config

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create('issues/neonlabsorg/proxy-model.py/197/admin')
user = proxy.eth.account.create('issues/neonlabsorg/proxy-model.py/197/user')
proxy.eth.default_account = admin.address
request_airdrop(admin.address)
request_airdrop(user.address)

NAME = 'NEON'
SYMBOL = 'NEO'

Confirmed = Commitment('confirmed')


class Test_erc20_wrapper_contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/197")
        print('admin.key:', admin.key.hex())
        print('admin.address:', admin.address)
        print('user.key:', user.key.hex())
        print('user.address:', user.address)

        cls.create_token_mint()
        cls.deploy_erc20_wrapper_contract()
        cls.create_token_accounts()

    @classmethod
    def create_token_mint(cls):
        cls.solana_client = SolanaClient(Config().solana_url)

        with open("proxy/operator-keypairs/id.json") as f:
            d = json.load(f)
        cls.solana_account = SolAccount(d[0:32])
        cls.solana_client.request_airdrop(cls.solana_account.public_key(), 1000_000_000_000, Confirmed)

        while True:
            balance = cls.solana_client.get_balance(cls.solana_account.public_key(), Confirmed)["result"]["value"]
            if balance > 0:
                break
            sleep(1)
        print('create_token_mint mint, SolanaAccount: ', cls.solana_account.public_key())

        cls.token = SplToken.create_mint(
            cls.solana_client,
            cls.solana_account,
            cls.solana_account.public_key(),
            9,
            TOKEN_PROGRAM_ID,
        )

    @classmethod
    def deploy_erc20_wrapper_contract(cls):
        cls.wrapper = ERC20Wrapper(proxy, NAME, SYMBOL,
                                   cls.token, admin,
                                   cls.solana_account,
                                   SolPubKey(EVM_LOADER_ID))
        cls.wrapper.deploy_wrapper()

    @classmethod
    def create_token_accounts(cls):
        amount = 10_000_000_000_000
        token_account = SplTokenInstrutions.get_associated_token_address(cls.solana_account.public_key(), cls.token.pubkey)
        admin_address = cls.wrapper.get_neon_account_address(admin.address)

        tx = SolLegacyTx()

        tx.add(SplTokenInstrutions.create_associated_token_account(
            cls.solana_account.public_key(), cls.solana_account.public_key(), cls.token.pubkey
        ))
        tx.add(SplTokenInstrutions.mint_to(SplTokenInstrutions.MintToParams(
            program_id=cls.token.program_id,
            mint=cls.token.pubkey,
            dest=token_account,
            mint_authority=cls.solana_account.public_key(),
            amount=amount,
            signers=[],
        )))
        tx.add(SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
            program_id=cls.token.program_id,
            source=token_account,
            delegate=admin_address,
            owner=cls.solana_account.public_key(),
            amount=amount,
            signers=[],
        )))

        claim_instr = cls.wrapper.create_claim_instruction(
            owner=cls.solana_account.public_key(),
            from_acc=token_account,
            to_acc=admin,
            amount=amount,
        )
        tx.add(claim_instr.make_tx_exec_from_data_ix())

        cls.solana_client.send_transaction(tx, cls.solana_account, opts=TxOpts(preflight_commitment=Confirmed, skip_confirmation=False))

    def test_erc20_name(self):
        erc20 = proxy.eth.contract(address=self.wrapper.neon_contract_address, abi=self.wrapper.wrapper['abi'])
        name = erc20.functions.name().call()
        self.assertEqual(name, NAME)

    def test_erc20_symbol(self):
        erc20 = proxy.eth.contract(address=self.wrapper.neon_contract_address, abi=self.wrapper.wrapper['abi'])
        sym = erc20.functions.symbol().call()
        self.assertEqual(sym, SYMBOL)

    def test_erc20_decimals(self):
        erc20 = self.wrapper.erc20_interface()
        decs = erc20.functions.decimals().call()
        self.assertEqual(decs, 9)

    def test_erc20_totalSupply(self):
        erc20 = self.wrapper.erc20_interface()
        ts = erc20.functions.totalSupply().call()
        self.assertGreater(ts, 0)

    def test_erc20_balanceOf(self):
        erc20 = self.wrapper.erc20_interface()
        b = erc20.functions.balanceOf(admin.address).call()
        self.assertGreater(b, 0)
        b = erc20.functions.balanceOf(user.address).call()
        self.assertEqual(b, 0)

    def test_erc20_transfer(self):
        transfer_value = 1000
        erc20 = self.wrapper.erc20_interface()

        admin_balance_before = erc20.functions.balanceOf(admin.address).call()
        user_balance_before = erc20.functions.balanceOf(user.address).call()

        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx = erc20.functions.transfer(user.address, transfer_value).buildTransaction(tx)
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        admin_balance_after = erc20.functions.balanceOf(admin.address).call()
        user_balance_after = erc20.functions.balanceOf(user.address).call()

        self.assertEqual(admin_balance_after, admin_balance_before - transfer_value)
        self.assertEqual(user_balance_after, user_balance_before + transfer_value)

    def test_erc20_transfer_not_enough_funds(self):
        transfer_value = 100_000_000_000_000
        erc20 = self.wrapper.erc20_interface()

        admin_balance_before = erc20.functions.balanceOf(admin.address).call()
        user_balance_before = erc20.functions.balanceOf(user.address).call()

        with self.assertRaisesRegex(Exception, "ERC20: transfer amount exceeds balance"):
            erc20.functions.transfer(user.address, transfer_value).buildTransaction()

        admin_balance_after = erc20.functions.balanceOf(admin.address).call()
        user_balance_after = erc20.functions.balanceOf(user.address).call()

        self.assertEqual(admin_balance_after, admin_balance_before)
        self.assertEqual(user_balance_after, user_balance_before)

    def test_erc20_transfer_out_of_bounds(self):
        transfer_value = 0xFFFF_FFFF_FFFF_FFFF + 1
        erc20 = self.wrapper.erc20_interface()

        with self.assertRaisesRegex(Exception, "ERC20: transfer amount exceeds uint64 max"):
            erc20.functions.transfer(user.address, transfer_value).buildTransaction()

    def test_erc20_approve(self):
        approve_value = 1000
        erc20 = self.wrapper.erc20_interface()

        allowance_before = erc20.functions.allowance(admin.address, user.address).call()

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = erc20.functions.approve(user.address, approve_value).buildTransaction({'nonce': nonce})
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertEqual(tx_receipt.status, 1)

        self.assertIsNotNone(tx_receipt)

        allowance_after = erc20.functions.allowance(admin.address, user.address).call()
        self.assertEqual(allowance_after, allowance_before + approve_value)

    def test_erc20_transferFrom(self):
        approve_value = 1000
        transfer_value = 100
        erc20 = self.wrapper.erc20_interface()

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = erc20.functions.approve(user.address, approve_value).buildTransaction({'nonce': nonce})
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        allowance_before = erc20.functions.allowance(admin.address, user.address).call()
        admin_balance_before = erc20.functions.balanceOf(admin.address).call()
        user_balance_before = erc20.functions.balanceOf(user.address).call()

        nonce = proxy.eth.get_transaction_count(user.address)
        tx = erc20.functions.transferFrom(admin.address, user.address, transfer_value).buildTransaction(
            {'nonce': nonce, 'from': user.address}
        )
        tx = proxy.eth.account.sign_transaction(tx, user.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        allowance_after = erc20.functions.allowance(admin.address, user.address).call()
        admin_balance_after = erc20.functions.balanceOf(admin.address).call()
        user_balance_after = erc20.functions.balanceOf(user.address).call()

        self.assertEqual(allowance_after, allowance_before - transfer_value)
        self.assertEqual(admin_balance_after, admin_balance_before - transfer_value)
        self.assertEqual(user_balance_after, user_balance_before + transfer_value)

    def test_erc20_transferFrom_beyond_approve(self):
        transfer_value = 10_000_000
        erc20 = self.wrapper.erc20_interface()

        with self.assertRaisesRegex(Exception, "ERC20: insufficient allowance"):
            erc20.functions.transferFrom(admin.address, user.address, transfer_value).buildTransaction(
                {'from': user.address}
            )

    def test_erc20_transferFrom_out_of_bounds(self):
        transfer_value = 0xFFFF_FFFF_FFFF_FFFF + 1
        approve_value = transfer_value + 1
        erc20 = self.wrapper.erc20_interface()

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = erc20.functions.approve(user.address, approve_value).buildTransaction({'nonce': nonce})
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        with self.assertRaisesRegex(Exception, "ERC20: transfer amount exceeds uint64 max"):
            erc20.functions.transferFrom(admin.address, user.address, transfer_value).buildTransaction(
                {'from': user.address}
            )

    def test_erc20_approveSolana(self):
        delegate = SolAccount()
        approve_value = 1000
        erc20 = self.wrapper.erc20_interface()

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = erc20.functions.approveSolana(bytes(delegate.public_key()), approve_value).buildTransaction({'nonce': nonce})
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertEqual(tx_receipt.status, 1)

        self.assertIsNotNone(tx_receipt)
        accounts = self.solana_client.get_token_accounts_by_delegate(delegate.public_key(), TokenAccountOpts(mint=self.token.pubkey), commitment=Recent)
        accounts = list(map(lambda a: SolPubKey(a['pubkey']), accounts['result']['value']))

        self.assertGreaterEqual(len(accounts), 1)


if __name__ == '__main__':
    unittest.main()
